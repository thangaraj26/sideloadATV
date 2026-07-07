//! Thread-safe handle over a background-task [`crate::adapter::Adapter`].
//!
//! [`AdapterHandle`] spawns the adapter's I/O loop onto whatever async
//! executor is current (tokio on native, `wasm_bindgen_futures::spawn_local`
//! on `wasm32-unknown-unknown`) and communicates with it through tokio
//! `mpsc` channels. The resulting [`StreamHandle`] is `Send + Sync + 'static`,
//! enabling use cases that [`crate::stream::AdapterStream`] cannot support:
//!
//! - **Multiple concurrent connections** on the same adapter.
//! - Passing a stream to a `spawn` call or storing it in an `Arc<Mutex<…>>`.
//! - Storing the stream in a struct without a lifetime parameter.
//! - FFI or any context that requires `'static` bounds.
//!
//! The trade-off versus [`crate::stream::AdapterStream`] is a small channel
//! round-trip on every write, and the adapter runs in a dedicated background
//! task rather than being driven directly by the caller.
//!
//! # Background task
//!
//! [`AdapterHandle::new`] immediately spawns a task. The spawned task runs a
//! `select!` loop that races three branches:
//!
//! 1. **Incoming messages**: connect/send/pcap/close requests from callers.
//! 2. **Incoming packets**: reads the next frame from the transport and updates
//!    connection state.
//! 3. **1 ms tick**: calls `write_buffer_flush`, which drains pending writes and
//!    checks for retransmission timeouts.
//!
//! The task exits when the last [`AdapterHandle`] is dropped or when
//! [`AdapterHandle::close`] is called.

use std::{collections::HashMap, net::IpAddr, sync::Mutex, task::Poll};

#[cfg(feature = "pcap")]
use std::path::PathBuf;

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};
use tracing::trace;

use crate::adapter::{ConnectionStatus, UdpDatagram};
use crate::time::timeout;

enum HandleMessage {
    /// Returns the host port
    ConnectToPort {
        target: u16,
        res: oneshot::Sender<
            Result<
                (
                    u16,
                    mpsc::UnboundedReceiver<Result<Vec<u8>, std::io::Error>>,
                ),
                std::io::Error,
            >,
        >,
    },
    Close {
        host_port: u16,
    },
    Send {
        host_port: u16,
        data: Vec<u8>,
        res: oneshot::Sender<Result<(), std::io::Error>>,
    },
    BindUdp {
        port: u16,
        res: oneshot::Sender<(u16, mpsc::UnboundedReceiver<UdpDatagram>)>,
    },
    UnbindUdp {
        port: u16,
    },
    SendUdp {
        source_port: u16,
        destination_port: u16,
        data: Vec<u8>,
        res: oneshot::Sender<Result<(), std::io::Error>>,
    },
    #[cfg(feature = "pcap")]
    Pcap {
        path: PathBuf,
        res: oneshot::Sender<Result<(), std::io::Error>>,
    },
    Die,
}

/// A cloneable, thread-safe handle to a background [`crate::adapter::Adapter`] task.
///
/// Constructed via [`crate::adapter::Adapter::to_async_handle`]. Cheap to clone.
/// Each clone shares the same channel sender to the background task.
///
/// Drop all clones (or call [`AdapterHandle::close`]) to shut down the background task.
#[derive(Debug, Clone)]
pub struct AdapterHandle {
    sender: mpsc::UnboundedSender<HandleMessage>,
    host_ip: IpAddr,
    peer_ip: IpAddr,
}

impl AdapterHandle {
    pub fn new(mut adapter: crate::adapter::Adapter) -> Self {
        let host_ip = adapter.host_ip();
        let peer_ip = adapter.peer_ip();
        let (tx, mut rx) = mpsc::unbounded_channel::<HandleMessage>();
        crate::spawn(async move {
            let mut handles: HashMap<u16, mpsc::UnboundedSender<Result<Vec<u8>, std::io::Error>>> =
                HashMap::new();
            let mut udp_handles: HashMap<u16, mpsc::UnboundedSender<UdpDatagram>> = HashMap::new();
            let mut tick = crate::time::interval(std::time::Duration::from_millis(1));

            loop {
                tokio::select! {
                    // check for messages for us
                    msg = rx.recv() => {
                        match msg {
                            Some(m) => match m {
                                HandleMessage::ConnectToPort { target, res } => {
                                    let connect_response = match adapter.connect(target).await {
                                        Ok(c) => {
                                            let (ptx, prx) = mpsc::unbounded_channel();
                                            handles.insert(c, ptx);
                                            Ok((c, prx))
                                        }
                                        Err(e) => Err(e),
                                    };
                                    res.send(connect_response).ok();
                                }
                                HandleMessage::Close { host_port } => {
                                    handles.remove(&host_port);
                                    adapter.close(host_port).await.ok();
                                }
                                HandleMessage::Send {
                                    host_port,
                                    data,
                                    res,
                                } => {
                                    if let Err(e) = adapter.queue_send(&data, host_port) {
                                        res.send(Err(e)).ok();
                                    } else {
                                        let response = adapter.write_buffer_flush().await;
                                        res.send(response).ok();
                                    }
                                }
                                HandleMessage::BindUdp { port, res } => {
                                    let bound = adapter.bind_udp(port);
                                    let (utx, urx) = mpsc::unbounded_channel();
                                    udp_handles.insert(bound, utx);
                                    res.send((bound, urx)).ok();
                                }
                                HandleMessage::UnbindUdp { port } => {
                                    udp_handles.remove(&port);
                                    adapter.unbind_udp(port);
                                }
                                HandleMessage::SendUdp {
                                    source_port,
                                    destination_port,
                                    data,
                                    res,
                                } => {
                                    let r = adapter
                                        .send_udp(source_port, destination_port, &data)
                                        .await;
                                    res.send(r).ok();
                                }
                                #[cfg(feature = "pcap")]
                                HandleMessage::Pcap {
                                    path,
                                    res
                                } => {
                                    res.send(adapter.pcap(path).await).ok();
                                },
                                HandleMessage::Die => {
                                    break;
                                }
                            },
                            None => {
                                break;
                            },
                        }
                    }

                    r = adapter.process_tcp_packet() => {
                        if let Err(e) = r {
                            // propagate error to all streams; close them
                            for (hp, tx) in handles.drain() {
                                let _ = tx.send(Err(e.kind().into())); // or clone/convert
                                let _ = adapter.close(hp).await;
                            }
                            break;
                        }

                        // Push any newly available bytes to per-conn channels
                        let mut dead = Vec::new();
                        for (&hp, tx) in &handles {
                            match adapter.uncache_all(hp) {
                                Ok(buf) if !buf.is_empty() => {
                                    if tx.send(Ok(buf)).is_err() {
                                        dead.push(hp);
                                    }
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(e));
                                    dead.push(hp);
                                }
                                _ => {}
                            }
                        }
                        for hp in dead {
                            handles.remove(&hp);
                            let _ = adapter.close(hp).await;
                        }

                        let mut to_close = Vec::new();
                        for (&hp, tx) in &handles {
                            if let Ok(ConnectionStatus::Error(kind)) = adapter.get_status(hp) {
                                if kind == std::io::ErrorKind::UnexpectedEof {
                                    to_close.push(hp);
                                } else {
                                    let _ = tx.send(Err(std::io::Error::from(kind)));
                                    to_close.push(hp);
                                }
                            }
                        }
                        for hp in to_close {
                            handles.remove(&hp);
                            // Best-effort close. For RST this just tidies state on our side
                            let _ = adapter.close(hp).await;
                        }

                        // Forward any inbound UDP datagrams to their bound port's channel.
                        if !udp_handles.is_empty() {
                            for dg in adapter.udp_drain() {
                                if let Some(tx) = udp_handles.get(&dg.destination_port) {
                                    let _ = tx.send(dg);
                                }
                            }
                        }

                        // An ACK in that packet may have cleared `unacked` for some
                        // connection; flush now instead of waiting up to 1ms for the tick.
                        let _ = adapter.write_buffer_flush().await;
                    }

                    _ = tick.tick() => {
                        let _ = adapter.write_buffer_flush().await;
                    }
                }
            }
        });

        Self {
            sender: tx,
            host_ip,
            peer_ip,
        }
    }

    /// The local (host) IP of the tunnel — use this as the RTP `receiverIP`.
    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// The remote (device) IP of the tunnel.
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Bind a local UDP port for connectionless send/receive. Pass 0 to let
    /// the stack choose a free port (returned in [`UdpSocketHandle::local_port`]).
    pub async fn bind_udp(&self, port: u16) -> Result<UdpSocketHandle, std::io::Error> {
        let (res_tx, res_rx) = oneshot::channel();
        if self
            .sender
            .send(HandleMessage::BindUdp { port, res: res_tx })
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "adapter closed",
            ));
        }
        match res_rx.await {
            Ok((local_port, recv_channel)) => Ok(UdpSocketHandle {
                local_port,
                recv_channel: tokio::sync::Mutex::new(recv_channel),
                send_channel: self.sender.clone(),
            }),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "adapter closed",
            )),
        }
    }

    pub async fn connect(&mut self, port: u16) -> Result<StreamHandle, std::io::Error> {
        let (res_tx, res_rx) = oneshot::channel();
        if self
            .sender
            .send(HandleMessage::ConnectToPort {
                target: port,
                res: res_tx,
            })
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "adapter closed",
            ));
        }

        match timeout(std::time::Duration::from_secs(8), res_rx).await {
            Ok(Ok(r)) => {
                let (host_port, recv_channel) = r?;
                Ok(StreamHandle {
                    host_port,
                    recv_channel: Mutex::new(recv_channel),
                    send_channel: self.sender.clone(),
                    read_buffer: Vec::new(),
                    pending_writes: FuturesUnordered::new(),
                })
            }
            Ok(Err(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "adapter closed",
            )),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "channel recv timeout",
            )),
        }
    }

    #[cfg(feature = "pcap")]
    pub async fn pcap(&mut self, path: impl Into<PathBuf>) -> Result<(), std::io::Error> {
        let (res_tx, res_rx) = oneshot::channel();
        let path: PathBuf = path.into();

        if self
            .sender
            .send(HandleMessage::Pcap { path, res: res_tx })
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "adapter closed",
            ));
        }

        match res_rx.await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "adapter closed",
            )),
        }
    }

    pub async fn close(&mut self) -> Result<(), std::io::Error> {
        if self.sender.send(HandleMessage::Die).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "adapter closed",
            ));
        }
        Ok(())
    }
}

/// A `Send + Sync + 'static` stream produced by [`AdapterHandle::connect`].
///
/// Implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`], so it can
/// be used anywhere a Tokio I/O stream is expected.
///
/// Dropping this handle automatically sends a `Close` message to the background
/// task, which sends a TCP FIN and cleans up connection state.
#[derive(Debug)]
pub struct StreamHandle {
    host_port: u16,
    // Mutex only exists to satisfy the `Sync` bound on `ReadWrite`; this is the
    // sole owner of the receiver, so it should never actually contend.
    recv_channel: Mutex<mpsc::UnboundedReceiver<Result<Vec<u8>, std::io::Error>>>,
    send_channel: mpsc::UnboundedSender<HandleMessage>,

    read_buffer: Vec<u8>,
    pending_writes: FuturesUnordered<oneshot::Receiver<Result<(), std::io::Error>>>,
}

impl StreamHandle {
    pub fn close(&mut self) {
        let _ = self.send_channel.send(HandleMessage::Close {
            host_port: self.host_port,
        });
    }
}

impl AsyncRead for StreamHandle {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 1) Serve from cache first.
        if !self.read_buffer.is_empty() {
            let n = buf.remaining().min(self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..n]);
            self.read_buffer.drain(..n); // fewer allocs than to_vec + reassign
            return Poll::Ready(Ok(()));
        }

        // 2) Poll the channel directly; this registers the waker on Empty.
        let mut lock = self
            .recv_channel
            .lock()
            .expect("somehow the mutex was poisoned");
        // this should always return, since we're the only owner of the mutex. The mutex is only
        // used to satisfy the `Send` bounds of ReadWrite.
        let mut extend_slice = Vec::new();
        let res = match lock.poll_recv(cx) {
            Poll::Pending => Poll::Pending,

            // Disconnected/ended: map to BrokenPipe
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),

            // Got a chunk: copy what fits; cache the tail.
            Poll::Ready(Some(res)) => match res {
                Ok(data) => {
                    let n = buf.remaining().min(data.len());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        extend_slice = data[n..].to_vec();
                    }
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(e)),
            },
        };
        std::mem::drop(lock);
        self.read_buffer.extend(extend_slice);
        res
    }
}

impl AsyncWrite for StreamHandle {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        trace!("poll psh {}", buf.len());
        let (tx, rx) = oneshot::channel();
        self.send_channel
            .send(HandleMessage::Send {
                host_port: self.host_port,
                data: buf.to_vec(),
                res: tx,
            })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))?;
        self.pending_writes.push(rx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        while let Poll::Ready(maybe) = self.pending_writes.poll_next_unpin(cx) {
            match maybe {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => return Poll::Ready(Err(e)),
                Some(Err(_canceled)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "channel closed",
                    )));
                }
                None => break, // nothing pending
            }
        }
        if self.pending_writes.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // Just a drop will close the channel, which will trigger a close
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        let _ = self.send_channel.send(HandleMessage::Close {
            host_port: self.host_port,
        });
    }
}

/// A bound UDP port on the userspace stack. Connectionless: [`recv`] yields
/// whole datagrams and [`send_to`] sends to a peer port. Dropping it unbinds
/// the port.
#[derive(Debug)]
pub struct UdpSocketHandle {
    local_port: u16,
    // Mutex only to satisfy `Sync`; this is the sole owner of the receiver.
    recv_channel: tokio::sync::Mutex<mpsc::UnboundedReceiver<UdpDatagram>>,
    send_channel: mpsc::UnboundedSender<HandleMessage>,
}

impl UdpSocketHandle {
    /// The local port datagrams are received on (and the source port of sends).
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Await the next inbound datagram. Returns `BrokenPipe` if the stack closed.
    pub async fn recv(&self) -> Result<UdpDatagram, std::io::Error> {
        let mut lock = self.recv_channel.lock().await;
        match lock.recv().await {
            Some(dg) => Ok(dg),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "adapter closed",
            )),
        }
    }

    /// Send a datagram from `local_port` to the peer's `destination_port`.
    pub async fn send_to(
        &self,
        destination_port: u16,
        data: Vec<u8>,
    ) -> Result<(), std::io::Error> {
        let (res_tx, res_rx) = oneshot::channel();
        self.send_channel
            .send(HandleMessage::SendUdp {
                source_port: self.local_port,
                destination_port,
                data,
                res: res_tx,
            })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "adapter closed"))?;
        match res_rx.await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "adapter closed",
            )),
        }
    }
}

impl Drop for UdpSocketHandle {
    fn drop(&mut self) {
        let _ = self.send_channel.send(HandleMessage::UnbindUdp {
            port: self.local_port,
        });
    }
}

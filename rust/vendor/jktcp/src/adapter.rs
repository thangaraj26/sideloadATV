//! Core TCP state machine.
//!
//! [`Adapter`] owns the underlying transport and manages all TCP connections.
//! It is the entry point for both usage patterns exposed by this crate:
//!
//! - **Single-task use**:  keep the `Adapter` directly and open streams with
//!   [`crate::stream::AdapterStream::connect`].
//! - **Multi-task use**: call [`Adapter::to_async_handle`] to move the adapter
//!   into a background task and obtain an [`crate::handle::AdapterHandle`] that
//!   can be shared across threads.
//!
//! See the [crate-level documentation](crate) for a full comparison.

use std::{
    collections::{HashMap, VecDeque},
    io::ErrorKind,
    net::IpAddr,
    sync::Arc,
};

#[cfg(feature = "pcap")]
use std::path::Path;

use crate::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

use crate::packets::{Ipv4Packet, Ipv6Packet, ProtocolNumber, TcpFlags, TcpPacket, UdpPacket};
use crate::{PcapLog, ReadWrite, packets::IpParseError};

/// A received UDP datagram, addressed from `peer_ip:source_port` to the local
/// `destination_port`. UDP is connectionless, so there is no socket state
/// beyond the set of bound local ports.
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub data: Vec<u8>,
}

/// Maximum number of retransmission attempts before a connection is killed.
///
/// sideloadATV patch: raised from upstream's 5 (~6.2s) to 12 (~45s). Our
/// transport is a reliable TLS/TCP tunnel, so an unacked head segment almost
/// never means real packet loss -- it means the Apple TV paused (storage flush
/// / GC / receive-buffer drain) mid-transfer. A large IPA (100 MB+) takes long
/// enough that hitting one such multi-second pause is near-certain, and the old
/// 6s give-up killed the install ("device socket io failed: timed out"). With
/// the RTO capped at 6400ms, 12 retries tolerates ~45s of stall before we
/// conclude the connection is genuinely dead.
const MAX_RETRIES: u32 = 12;

/// Initial retransmission timeout in milliseconds. Doubles on each retry.
const INITIAL_RTO_MS: u64 = 200;

const OUR_WSCALE: u8 = 8;

/// Default cap on bytes in flight per connection, in bytes. Overridden via
/// [`Adapter::set_send_window`].
const DEFAULT_SEND_WINDOW: usize = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Unacknowledged segment tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct UnackedSegment {
    seq: u32,
    data: Arc<[u8]>,
    sent_at: Instant,
    retries: u32,
}

impl UnackedSegment {
    fn rto(&self) -> std::time::Duration {
        // 200ms, 400ms, 800ms, 1600ms, 3200ms, 6400ms (capped)
        std::time::Duration::from_millis(INITIAL_RTO_MS << self.retries.min(6))
    }

    fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() >= self.rto()
    }
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ConnectionState {
    /// Next sequence number we will send.
    seq: u32,
    /// Next sequence number we expect from the peer (= what we put in ACK field).
    ack: u32,
    host_port: u16,
    peer_port: u16,
    read_buffer: Vec<u8>,
    write_buffer: VecDeque<u8>,
    status: ConnectionStatus,
    /// Segments we have sent but not yet received an ACK for, in send order.
    unacked: VecDeque<UnackedSegment>,
    bytes_in_flight: usize,
    peer_window: u32,
    peer_wscale: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConnectionStatus {
    WaitingForSyn,
    Connected,
    Error(ErrorKind),
}

impl ConnectionState {
    fn new(host_port: u16, peer_port: u16) -> Self {
        Self {
            seq: rand::random(),
            ack: 0,
            host_port,
            peer_port,
            read_buffer: Vec::new(),
            write_buffer: VecDeque::new(),
            status: ConnectionStatus::WaitingForSyn,
            unacked: VecDeque::new(),
            bytes_in_flight: 0,
            peer_window: 0,
            peer_wscale: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Sequence number helpers (wrapping arithmetic)
// ---------------------------------------------------------------------------

/// Returns true if `a < b` in TCP sequence-number space.
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

/// Returns true if `a <= b` in TCP sequence-number space.
#[inline]
fn seq_lte(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// A userspace TCP stack backed by an arbitrary [`crate::ReadWrite`] transport.
///
/// `Adapter` drives the TCP state machine: it sends and receives raw IPv4/IPv6
/// packets over `peer`, maintains per-connection state, and implements
/// stop-and-wait retransmission.
///
/// # Lifecycle
///
/// 1. Construct with [`Adapter::new`], supplying the framed transport and the
///    local/remote IP addresses.
/// 2. Open connections with [`crate::stream::AdapterStream::connect`] **or** call
///    [`Adapter::to_async_handle`] to get a thread-safe [`crate::handle::AdapterHandle`].
/// 3. Optionally enable PCAP logging with [`Adapter::pcap`].
///
/// See the [crate-level documentation](crate) for a full comparison of both
/// usage patterns.
/// Default MSS: IPv6 min MTU (1280) minus headers.
const DEFAULT_MSS: usize = 1280 - 40 - 20;

#[derive(Debug)]
pub struct Adapter {
    peer: Box<dyn ReadWrite>,
    host_ip: IpAddr,
    peer_ip: IpAddr,
    states: HashMap<u16, ConnectionState>,
    dropped: Vec<u16>,
    read_buf: [u8; 65536],
    bytes_in_buf: usize,
    pcap: Option<PcapLog>,
    /// Maximum Segment Size for TCP data (payload only, no headers).
    mss: usize,
    send_window: usize,
    udp_sockets: HashMap<u16, VecDeque<UdpDatagram>>,
}

impl Adapter {
    pub fn new(peer: Box<dyn ReadWrite>, host_ip: IpAddr, peer_ip: IpAddr) -> Self {
        Self {
            peer,
            host_ip,
            peer_ip,
            states: HashMap::new(),
            dropped: Vec::new(),
            read_buf: [0u8; 65536],
            bytes_in_buf: 0,
            pcap: None,
            mss: DEFAULT_MSS,
            send_window: DEFAULT_SEND_WINDOW,
            udp_sockets: HashMap::new(),
        }
    }

    /// Set the Maximum Segment Size (MSS) for outbound TCP segments.
    ///
    /// This should be `MTU - 40 (IPv6 header) - 20 (TCP header)` for the
    /// tunnel you are using. Defaults to 1220 (based on IPv6 min MTU 1280).
    pub fn set_mss(&mut self, mss: usize) -> &mut Self {
        self.mss = mss;
        self
    }

    pub fn set_send_window(&mut self, window: usize) -> &mut Self {
        self.send_window = window;
        self
    }

    /// The local (host) IP address of this tunnel endpoint.
    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// The remote (peer/device) IP address of this tunnel endpoint.
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Wraps this adapter in a thread-safe handle.
    pub fn to_async_handle(self) -> crate::handle::AdapterHandle {
        crate::handle::AdapterHandle::new(self)
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    pub(crate) async fn connect(&mut self, port: u16) -> Result<u16, std::io::Error> {
        let host_port = loop {
            let p: u16 = rand::random();
            if !self.states.contains_key(&p) {
                break p;
            }
        };
        let state = ConnectionState::new(host_port, port);
        self.states.insert(host_port, state);

        // Send initial SYN.
        self.send_syn(host_port).await?;

        // Wait for SYN-ACK, retransmitting the SYN on timeout.
        let start = Instant::now();
        let mut last_syn = Instant::now();
        loop {
            self.process_tcp_packet().await?;

            if let Some(s) = self.states.get(&host_port) {
                match s.status {
                    ConnectionStatus::Connected => break,
                    ConnectionStatus::Error(e) => {
                        self.states.remove(&host_port);
                        return Err(std::io::Error::new(e, "failed to connect"));
                    }
                    ConnectionStatus::WaitingForSyn => {
                        if start.elapsed() > std::time::Duration::from_secs(10) {
                            self.states.remove(&host_port);
                            return Err(std::io::Error::new(ErrorKind::TimedOut, "SYN timed out"));
                        }
                        // Retransmit SYN every INITIAL_RTO_MS * 2^retry ms.
                        if last_syn.elapsed() >= std::time::Duration::from_millis(INITIAL_RTO_MS) {
                            debug!("retransmitting SYN for port {host_port}");
                            self.send_syn(host_port).await?;
                            last_syn = Instant::now();
                        }
                    }
                }
            }
        }

        Ok(host_port)
    }

    #[cfg(feature = "pcap")]
    pub async fn pcap(&mut self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(&0xa1b2c3d4_u32.to_le_bytes()).await?;
        file.write_all(&2_u16.to_le_bytes()).await?;
        file.write_all(&4_u16.to_le_bytes()).await?;
        file.write_all(&0_i32.to_le_bytes()).await?;
        file.write_all(&0_u32.to_le_bytes()).await?;
        file.write_all(&(u16::MAX as u32).to_le_bytes()).await?;
        file.write_all(&101_u32.to_le_bytes()).await?;
        self.pcap = Some(std::sync::Arc::new(tokio::sync::Mutex::new(file)));
        Ok(())
    }

    pub(crate) async fn close(&mut self, host_port: u16) -> Result<(), std::io::Error> {
        if let Some(state) = self.states.remove(&host_port) {
            let tcp = TcpPacket::create(
                self.host_ip,
                self.peer_ip,
                state.host_port,
                state.peer_port,
                state.seq,
                state.ack,
                TcpFlags {
                    fin: true,
                    ack: true,
                    ..Default::default()
                },
                u16::MAX - 1,
                &[],
                &[],
            );
            let ip = self.ip_wrap(&tcp);
            self.peer.write_all(&ip).await?;
            self.log_packet(&ip)?;
            Ok(())
        } else {
            Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            ))
        }
    }

    pub(crate) fn connection_drop(&mut self, host_port: u16) {
        self.dropped.push(host_port);
    }

    pub(crate) fn queue_send(
        &mut self,
        payload: &[u8],
        host_port: u16,
    ) -> Result<(), std::io::Error> {
        match self.states.get_mut(&host_port) {
            Some(s) => {
                s.write_buffer.extend(payload.iter().copied());
                Ok(())
            }
            None => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            )),
        }
    }

    pub(crate) fn uncache(
        &mut self,
        to_copy: usize,
        host_port: u16,
    ) -> Result<Vec<u8>, std::io::Error> {
        match self.states.get_mut(&host_port) {
            Some(s) => {
                let n = to_copy.min(s.read_buffer.len());
                let out = s.read_buffer[..n].to_vec();
                s.read_buffer.drain(..n);
                Ok(out)
            }
            None => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            )),
        }
    }

    pub(crate) fn uncache_all(&mut self, host_port: u16) -> Result<Vec<u8>, std::io::Error> {
        match self.states.get_mut(&host_port) {
            Some(s) => {
                let out = std::mem::take(&mut s.read_buffer);
                Ok(out)
            }
            None => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            )),
        }
    }

    pub(crate) fn cache_read(
        &mut self,
        payload: &[u8],
        host_port: u16,
    ) -> Result<(), std::io::Error> {
        match self.states.get_mut(&host_port) {
            Some(s) => {
                s.read_buffer.extend_from_slice(payload);
                Ok(())
            }
            None => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            )),
        }
    }

    pub(crate) fn get_status(&self, host_port: u16) -> Result<ConnectionStatus, std::io::Error> {
        match self.states.get(&host_port) {
            Some(s) => Ok(s.status.clone()),
            None => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            )),
        }
    }

    pub(crate) async fn recv(&mut self, host_port: u16) -> Result<Vec<u8>, std::io::Error> {
        loop {
            if let Some(state) = self.states.get_mut(&host_port) {
                if !state.read_buffer.is_empty() {
                    return Ok(std::mem::take(&mut state.read_buffer));
                }
                if let ConnectionStatus::Error(e) = state.status {
                    return Err(std::io::Error::new(e, "socket io error"));
                }
            } else {
                return Err(std::io::Error::new(
                    ErrorKind::NotConnected,
                    "not connected",
                ));
            }
            self.process_tcp_packet().await?;
        }
    }

    // -----------------------------------------------------------------------
    // Flush / retransmit
    // -----------------------------------------------------------------------

    /// Drain pending write-buffer data into outbound segments, up to the
    /// effective send window (`min(send_window, peer_window)`), then check
    /// for timed-out retransmissions.
    pub(crate) async fn write_buffer_flush(&mut self) -> Result<(), std::io::Error> {
        // Check retransmissions first so a timed-out connection is marked before
        // we attempt to send new data on it.
        self.check_retransmissions().await?;

        let host_ports: Vec<u16> = self.states.keys().cloned().collect();
        for hp in host_ports {
            // Inner loop: keep peeling off MSS-sized chunks until either the
            // write buffer is empty or the window is full.
            loop {
                let chunk: Arc<[u8]> = {
                    let Some(state) = self.states.get(&hp) else {
                        break;
                    };
                    if state.write_buffer.is_empty() {
                        break;
                    }
                    let cap = self.send_window.min(state.peer_window as usize);
                    if state.bytes_in_flight >= cap {
                        break;
                    }
                    let remaining = cap - state.bytes_in_flight;
                    let n = state.write_buffer.len().min(self.mss).min(remaining);
                    if n == 0 {
                        break;
                    }
                    let v: Vec<u8> = state.write_buffer.iter().take(n).copied().collect();
                    Arc::from(v)
                };

                let chunk_len = chunk.len();
                if self.psh(chunk, hp).await.is_err() {
                    break;
                }
                if let Some(state) = self.states.get_mut(&hp) {
                    state.write_buffer.drain(..chunk_len);
                }
            }
        }

        // Reap connections that were dropped while we had the lock.
        let dropped: Vec<u16> = self.dropped.drain(..).collect();
        for hp in dropped {
            if self.states.contains_key(&hp) {
                self.close(hp).await.ok();
            }
        }

        Ok(())
    }

    /// Check every connection for timed-out unacked segments. Retransmit the
    /// oldest in-flight segment with exponential back-off; kill the connection
    /// after MAX_RETRIES. Head-only retransmit suffices because TCP's
    /// cumulative ACK semantics cause the peer to ACK everything they have
    /// once the missing piece arrives.
    async fn check_retransmissions(&mut self) -> Result<(), std::io::Error> {
        let host_ports: Vec<u16> = self.states.keys().cloned().collect();

        for hp in host_ports {
            // Decide what to do before borrowing mutably.
            enum Action {
                Kill,
                Retransmit { seq: u32, data: Arc<[u8]> },
                None,
            }

            let action = match self.states.get(&hp) {
                Some(state) => match state.unacked.front() {
                    Some(seg) if seg.is_timed_out() => {
                        if seg.retries >= MAX_RETRIES {
                            Action::Kill
                        } else {
                            Action::Retransmit {
                                seq: seg.seq,
                                data: seg.data.clone(),
                            }
                        }
                    }
                    _ => Action::None,
                },
                None => Action::None,
            };

            match action {
                Action::Kill => {
                    warn!("hp={hp} timed out after {MAX_RETRIES} retransmissions; closing");
                    if let Some(state) = self.states.get_mut(&hp) {
                        state.status = ConnectionStatus::Error(ErrorKind::TimedOut);
                    }
                }
                Action::Retransmit { seq, data } => {
                    debug!("retransmitting {} bytes for hp={hp}", data.len());

                    // Bump retry counter before the await so it's visible even if we're cancelled.
                    if let Some(state) = self.states.get_mut(&hp)
                        && let Some(seg) = state.unacked.front_mut()
                    {
                        seg.retries += 1;
                        seg.sent_at = Instant::now();
                    }

                    let ip = {
                        let Some(state) = self.states.get(&hp) else {
                            continue;
                        };
                        let tcp = TcpPacket::create(
                            self.host_ip,
                            self.peer_ip,
                            state.host_port,
                            state.peer_port,
                            seq,
                            state.ack,
                            TcpFlags {
                                psh: true,
                                ack: true,
                                ..Default::default()
                            },
                            u16::MAX - 1,
                            &[],
                            &data,
                        );
                        self.ip_wrap(&tcp)
                    };

                    self.peer.write_all(&ip).await?;
                    self.log_packet(&ip)?;
                }
                Action::None => {}
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Packet processing
    // -----------------------------------------------------------------------

    pub(crate) async fn process_tcp_packet(&mut self) -> Result<(), std::io::Error> {
        tokio::select! {
            ip_packet = self.read_ip_packet() => {
                let (protocol, payload) = ip_packet?;
                match protocol {
                    p if p == ProtocolNumber::Tcp as u8 => {
                        self.process_tcp_packet_from_payload(&payload).await
                    }
                    p if p == ProtocolNumber::Udp as u8 => {
                        self.process_udp_packet(&payload);
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            // Short timeout so retransmissions fire in the AdapterStream case
            // (the AdapterHandle has a 1ms tick that calls write_buffer_flush directly).
            _ = crate::time::sleep(std::time::Duration::from_millis(500)) => {
                self.check_retransmissions().await
            }
        }
    }

    /// Parse an inbound UDP datagram and queue it if its destination port is
    /// bound
    fn process_udp_packet(&mut self, payload: &[u8]) {
        let udp = match UdpPacket::parse(payload) {
            Ok(u) => u,
            Err(_) => return,
        };
        if let Some(queue) = self.udp_sockets.get_mut(&udp.destination_port) {
            trace!(
                "udp {} bytes -> local port {}",
                udp.payload.len(),
                udp.destination_port
            );
            queue.push_back(UdpDatagram {
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                data: udp.payload,
            });
        }
    }

    /// Bind a local UDP port so inbound datagrams to it are queued
    pub(crate) fn bind_udp(&mut self, port: u16) -> u16 {
        let port = if port == 0 {
            loop {
                let p: u16 = rand::random();
                if p >= 1024 && !self.udp_sockets.contains_key(&p) {
                    break p;
                }
            }
        } else {
            port
        };
        self.udp_sockets.entry(port).or_default();
        port
    }

    pub(crate) fn unbind_udp(&mut self, port: u16) {
        self.udp_sockets.remove(&port);
    }

    /// Send a UDP datagram from `source_port` to the peer's `destination_port`.
    pub(crate) async fn send_udp(
        &mut self,
        source_port: u16,
        destination_port: u16,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        let udp = UdpPacket::create(
            self.host_ip,
            self.peer_ip,
            source_port,
            destination_port,
            data,
        );
        let ip = self.ip_wrap_proto(&udp, ProtocolNumber::Udp);
        self.peer.write_all(&ip).await?;
        self.log_packet(&ip)
    }

    /// Drain all queued inbound UDP datagrams across every bound port.
    pub(crate) fn udp_drain(&mut self) -> Vec<UdpDatagram> {
        let mut out = Vec::new();
        for queue in self.udp_sockets.values_mut() {
            out.extend(queue.drain(..));
        }
        out
    }

    pub(crate) async fn process_tcp_packet_from_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        let res = TcpPacket::parse(payload)?;
        let mut ack_me = None;

        if let Some(state) = self.states.get_mut(&res.destination_port) {
            // ------------------------------------------------------------------
            // ACK processing: advance the unacked window.
            // The peer's acknowledgment_number is the next seq they expect from us,
            // so any segment with (seg.seq + seg.len) <= ack_num has been received.
            // ------------------------------------------------------------------
            if res.flags.ack {
                let ack_num = res.acknowledgment_number;
                while let Some(seg) = state.unacked.front() {
                    let seg_end = seg.seq.wrapping_add(seg.data.len() as u32);
                    if seq_lte(seg_end, ack_num) {
                        let popped = state.unacked.pop_front().unwrap();
                        state.bytes_in_flight =
                            state.bytes_in_flight.saturating_sub(popped.data.len());
                    } else {
                        break;
                    }
                }
            }

            // Update peer's advertised receive window
            if !(res.flags.syn) {
                let shift = state.peer_wscale.unwrap_or(0);
                state.peer_window = (res.window_size as u32) << shift;
            }

            // ------------------------------------------------------------------
            // RST: hard close.
            // ------------------------------------------------------------------
            if res.flags.rst {
                warn!("RST on hp={}", res.destination_port);
                state.status = ConnectionStatus::Error(ErrorKind::ConnectionReset);
                return Ok(());
            }

            match state.status {
                ConnectionStatus::WaitingForSyn => {
                    // We expect a SYN-ACK.
                    if res.flags.syn && res.flags.ack {
                        // SYN-ACK: peer's SYN consumes one seq number.
                        state.ack = res.sequence_number.wrapping_add(1);
                        // Our SYN consumed one sequence number on our side.
                        state.seq = state.seq.wrapping_add(1);
                        state.status = ConnectionStatus::Connected;
                        state.peer_wscale = crate::packets::parse_window_scale(&res.options);
                        let shift = state.peer_wscale.unwrap_or(0);
                        state.peer_window = (res.window_size as u32) << shift;
                        ack_me = Some(res.destination_port);
                    }
                    // Anything else while waiting for SYN-ACK is ignored.
                }

                ConnectionStatus::Connected => {
                    // ----------------------------------------------------------
                    // Keep-alive probe: seq == RCV.NXT - 1, no payload.
                    // Just re-ACK without changing state.
                    // ----------------------------------------------------------
                    let is_keepalive = res.payload.is_empty()
                        && !res.flags.fin
                        && res.sequence_number.wrapping_add(1) == state.ack;

                    if is_keepalive {
                        debug!("keep-alive on hp={}", res.destination_port);
                        ack_me = Some(res.destination_port);
                    } else if !res.payload.is_empty() {
                        // ------------------------------------------------------
                        // Data segment: enforce in-order delivery.
                        // ------------------------------------------------------
                        if res.sequence_number == state.ack {
                            // Expected: accept.
                            state.ack = state.ack.wrapping_add(res.payload.len() as u32);
                            state.read_buffer.extend(&res.payload);
                            ack_me = Some(res.destination_port);
                        } else if seq_lt(res.sequence_number, state.ack) {
                            // Duplicate (already received): re-ACK, don't buffer.
                            debug!(
                                "duplicate data seq={} expected={} hp={}",
                                res.sequence_number, state.ack, res.destination_port
                            );
                            ack_me = Some(res.destination_port);
                        } else {
                            // Out-of-order: drop silently.
                            debug!(
                                "out-of-order seq={} expected={} hp={}",
                                res.sequence_number, state.ack, res.destination_port
                            );
                        }
                    }

                    // FIN: peer is closing; FIN consumes one sequence number.
                    if res.flags.fin {
                        state.ack = state.ack.wrapping_add(1);
                        state.status = ConnectionStatus::Error(ErrorKind::UnexpectedEof);
                        ack_me = Some(res.destination_port);
                    }
                }

                ConnectionStatus::Error(_) => {
                    // Connection is already dead; ignore everything.
                    trace!(
                        "packet received on errored connection hp={}",
                        res.destination_port
                    );
                }
            }
        }

        if let Some(hp) = ack_me {
            self.ack(hp).await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Low-level send helpers
    // -----------------------------------------------------------------------

    async fn send_syn(&mut self, host_port: u16) -> Result<(), std::io::Error> {
        let Some(state) = self.states.get(&host_port) else {
            return Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            ));
        };
        // Advertise window scaling so the peer can scale its window field.
        let wscale = crate::packets::window_scale_option(OUR_WSCALE);
        let tcp = TcpPacket::create(
            self.host_ip,
            self.peer_ip,
            state.host_port,
            state.peer_port,
            state.seq,
            0,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            u16::MAX - 1,
            &wscale,
            &[],
        );
        let ip = self.ip_wrap(&tcp);
        self.peer.write_all(&ip).await?;
        self.log_packet(&ip)
    }

    async fn ack(&mut self, host_port: u16) -> Result<(), std::io::Error> {
        let Some(state) = self.states.get(&host_port) else {
            return Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            ));
        };
        let tcp = TcpPacket::create(
            self.host_ip,
            self.peer_ip,
            state.host_port,
            state.peer_port,
            state.seq,
            state.ack,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            u16::MAX - 1,
            &[],
            &[],
        );
        let ip = self.ip_wrap(&tcp);
        let _ = state;
        self.peer.write_all(&ip).await?;
        self.log_packet(&ip)
    }

    /// Send a PSH segment and record it in the unacked queue.
    async fn psh(&mut self, data: Arc<[u8]>, host_port: u16) -> Result<(), std::io::Error> {
        let Some(state) = self.states.get(&host_port) else {
            return Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "not connected",
            ));
        };
        if let ConnectionStatus::Error(e) = state.status {
            return Err(std::io::Error::new(e, "socket error"));
        }
        trace!("psh {} bytes on hp={host_port}", data.len());
        let seq = state.seq;
        let tcp = TcpPacket::create(
            self.host_ip,
            self.peer_ip,
            state.host_port,
            state.peer_port,
            seq,
            state.ack,
            TcpFlags {
                psh: true,
                ack: true,
                ..Default::default()
            },
            u16::MAX - 1,
            &[],
            &data,
        );
        let ip = self.ip_wrap(&tcp);
        let _ = state;

        self.peer.write_all(&ip).await?;
        self.log_packet(&ip)?;

        if let Some(state) = self.states.get_mut(&host_port) {
            let len = data.len();
            state.bytes_in_flight += len;
            state.unacked.push_back(UnackedSegment {
                seq,
                data,
                sent_at: Instant::now(),
                retries: 0,
            });
            state.seq = state.seq.wrapping_add(len as u32);
        }

        Ok(())
    }

    async fn read_ip_packet(&mut self) -> Result<(u8, Vec<u8>), std::io::Error> {
        self.write_buffer_flush().await?;
        loop {
            let parsed = match self.host_ip {
                IpAddr::V4(_) => Self::try_parse_v4(&self.read_buf[..self.bytes_in_buf]),
                IpAddr::V6(_) => {
                    match Ipv6Packet::parse(&self.read_buf[..self.bytes_in_buf], &self.pcap) {
                        IpParseError::Ok {
                            packet,
                            bytes_consumed,
                        } => IpParseError::Ok {
                            packet: (packet.next_header, packet.payload),
                            bytes_consumed,
                        },
                        IpParseError::NotEnough => IpParseError::NotEnough,
                        IpParseError::Invalid => IpParseError::Invalid,
                    }
                }
            };
            match parsed {
                IpParseError::Ok {
                    packet,
                    bytes_consumed,
                } => {
                    if let Some(pcap) = &self.pcap
                        && matches!(self.host_ip, IpAddr::V4(_))
                    {
                        crate::log_packet(pcap, &self.read_buf[..bytes_consumed]);
                    }

                    self.read_buf
                        .copy_within(bytes_consumed..self.bytes_in_buf, 0);
                    self.bytes_in_buf -= bytes_consumed;
                    return Ok(packet);
                }
                IpParseError::NotEnough => {}
                IpParseError::Invalid => {
                    let kind = if matches!(self.host_ip, IpAddr::V4(_)) {
                        "invalid IPv4 packet"
                    } else {
                        "invalid IPv6 packet"
                    };
                    return Err(std::io::Error::new(ErrorKind::InvalidData, kind));
                }
            }
            let n = self
                .peer
                .read(&mut self.read_buf[self.bytes_in_buf..])
                .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "transport closed",
                ));
            }
            self.bytes_in_buf += n;
        }
    }

    /// Inspect the buffer for a complete IPv4 packet. Returns `(protocol,
    /// payload)` and the number of bytes consumed.
    fn try_parse_v4(buf: &[u8]) -> IpParseError<(u8, Vec<u8>)> {
        if buf.len() < 20 {
            return IpParseError::NotEnough;
        }
        if (buf[0] >> 4) != 4 {
            return IpParseError::Invalid;
        }
        let ihl_bytes = ((buf[0] & 0x0F) as usize) * 4;
        let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if ihl_bytes < 20 || total_length < ihl_bytes {
            return IpParseError::Invalid;
        }
        if buf.len() < total_length {
            return IpParseError::NotEnough;
        }
        let packet = match Ipv4Packet::parse(&buf[..total_length]) {
            Some(p) => p,
            None => return IpParseError::Invalid,
        };
        IpParseError::Ok {
            packet: (packet.protocol, packet.payload),
            bytes_consumed: total_length,
        }
    }

    fn log_packet(&self, packet: &[u8]) -> Result<(), std::io::Error> {
        if let Some(file) = &self.pcap {
            crate::log_packet(file, packet);
        }
        Ok(())
    }

    fn ip_wrap(&self, packet: &[u8]) -> Vec<u8> {
        self.ip_wrap_proto(packet, ProtocolNumber::Tcp)
    }

    fn ip_wrap_proto(&self, packet: &[u8], protocol: ProtocolNumber) -> Vec<u8> {
        match (self.host_ip, self.peer_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                Ipv4Packet::create(src, dst, protocol, 255, packet)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                Ipv6Packet::create(src, dst, protocol, 255, packet)
            }
            _ => panic!("host_ip and peer_ip must be the same IP version"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::{IpParseError, ProtocolNumber, TcpFlags, TcpPacket};
    use std::net::{IpAddr, Ipv6Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    const HOST_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const PEER_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const PEER_PORT: u16 = 80;
    /// Peer's initial sequence number
    const PEER_ISN: u32 = 5000;

    // ------------------------------------------------------------------
    // Test transport
    // ------------------------------------------------------------------

    struct TestTransport(DuplexStream);

    impl std::fmt::Debug for TestTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestTransport")
        }
    }

    impl AsyncRead for TestTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestTransport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    // ------------------------------------------------------------------
    // Packet helpers
    // ------------------------------------------------------------------

    /// Build a raw TCP segment (not IP-wrapped) from PEER→adapter.
    fn tcp_seg(dst_port: u16, seq: u32, ack_num: u32, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
        tcp_seg_with_opts(dst_port, seq, ack_num, flags, &[], payload)
    }

    fn tcp_seg_with_opts(
        dst_port: u16,
        seq: u32,
        ack_num: u32,
        flags: TcpFlags,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        TcpPacket::create(
            IpAddr::V6(PEER_IP),
            IpAddr::V6(HOST_IP),
            PEER_PORT,
            dst_port,
            seq,
            ack_num,
            flags,
            u16::MAX - 1,
            options,
            payload,
        )
    }

    /// Build an IPv6-wrapped TCP packet from PEER→adapter (for injection into transport).
    fn peer_ipv6_pkt(
        dst_port: u16,
        seq: u32,
        ack_num: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp = tcp_seg(dst_port, seq, ack_num, flags, payload);
        crate::packets::Ipv6Packet::create(PEER_IP, HOST_IP, ProtocolNumber::Tcp, 255, &tcp)
    }

    /// Read one complete IPv6 packet the adapter wrote to the transport.
    async fn read_pkt(reader: &mut (impl AsyncRead + Unpin)) -> TcpPacket {
        let mut hdr = [0u8; 40];
        reader.read_exact(&mut hdr).await.unwrap();
        let plen = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
        let mut rest = vec![0u8; plen];
        reader.read_exact(&mut rest).await.unwrap();
        let mut full = hdr.to_vec();
        full.extend_from_slice(&rest);
        let ip = match crate::packets::Ipv6Packet::parse(&full, &None) {
            IpParseError::Ok { packet, .. } => packet,
            _ => panic!("not a valid IPv6 packet from adapter"),
        };
        TcpPacket::parse(&ip.payload).unwrap()
    }

    // ------------------------------------------------------------------
    // Handshake helper
    // ------------------------------------------------------------------

    /// Drive the adapter's `connect` and the test-peer response concurrently.
    /// Returns the host port the adapter chose.
    async fn handshake(
        adapter: &mut Adapter,
        test_rx: &mut (impl AsyncRead + Unpin),
        test_tx: &mut (impl AsyncWrite + Unpin),
    ) -> u16 {
        let (hp_result, peer_hp) = tokio::join!(adapter.connect(PEER_PORT), async {
            // Read the SYN the adapter sends immediately on connect().
            let syn = read_pkt(test_rx).await;
            assert!(syn.flags.syn, "first packet from adapter should be SYN");
            let hp = syn.source_port;

            // Send SYN-ACK.
            test_tx
                .write_all(&peer_ipv6_pkt(
                    hp,
                    PEER_ISN,
                    syn.sequence_number.wrapping_add(1),
                    TcpFlags {
                        syn: true,
                        ack: true,
                        ..Default::default()
                    },
                    &[],
                ))
                .await
                .unwrap();

            // Consume the ACK the adapter sends to complete the handshake.
            let ack = read_pkt(test_rx).await;
            assert!(
                ack.flags.ack,
                "adapter should send ACK to complete handshake"
            );

            hp
        });
        let hp = hp_result.expect("connect failed");
        assert_eq!(hp, peer_hp);
        hp
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    /// After the RTO elapses without an ACK, the same segment is retransmitted
    /// with the same sequence number.
    #[tokio::test]
    async fn retransmit_fires_after_rto() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        // Queue and flush data; the adapter sends a PSH segment.
        adapter.queue_send(b"hello", hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();

        let psh1 = read_pkt(&mut test_rx).await;
        assert_eq!(psh1.payload, b"hello");
        let original_seq = psh1.sequence_number;

        // Advance past the initial RTO without ACKing.
        tokio::time::advance(Duration::from_millis(INITIAL_RTO_MS + 1)).await;
        adapter.write_buffer_flush().await.unwrap();

        // The adapter should retransmit the same segment.
        let psh2 = read_pkt(&mut test_rx).await;
        assert_eq!(
            psh2.payload, b"hello",
            "retransmit payload must match original"
        );
        assert_eq!(
            psh2.sequence_number, original_seq,
            "retransmit must reuse the original sequence number"
        );
    }

    /// Advancing through all retry intervals marks the connection as
    /// `Error(TimedOut)` once MAX_RETRIES is exhausted.
    #[tokio::test]
    async fn connection_killed_after_max_retries() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        adapter.queue_send(b"data", hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();
        read_pkt(&mut test_rx).await; // initial send

        // Drive through MAX_RETRIES retransmits (each with its doubled RTO),
        // then one more check which should kill the connection.
        for i in 0..=MAX_RETRIES {
            let rto = Duration::from_millis(INITIAL_RTO_MS << i.min(6));
            tokio::time::advance(rto + Duration::from_millis(1)).await;
            adapter.write_buffer_flush().await.unwrap();

            if i < MAX_RETRIES {
                // Drain the retransmit so the duplex buffer doesn't fill up.
                read_pkt(&mut test_rx).await;
            }
            // On the final iteration the connection is killed instead of retransmitting.
        }

        assert_eq!(
            adapter.get_status(hp).unwrap(),
            ConnectionStatus::Error(ErrorKind::TimedOut),
            "connection should be Error(TimedOut) after exhausting retries"
        );
    }

    #[tokio::test]
    async fn ack_clears_unacked_queue() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );
        adapter.set_send_window(5);

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        adapter.queue_send(b"first", hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();
        let psh1 = read_pkt(&mut test_rx).await;
        assert_eq!(psh1.payload, b"first");

        // Queue second chunk; window is full, must be held.
        adapter.queue_send(b"secnd", hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();

        // Nothing should appear on the wire yet.
        let nothing = tokio::time::timeout(Duration::from_millis(10), read_pkt(&mut test_rx)).await;
        assert!(
            nothing.is_err(),
            "second chunk must not be sent while window is full"
        );

        // ACK the first chunk (ack = psh1.seq + len).
        let peer_ack_num = psh1.sequence_number.wrapping_add(psh1.payload.len() as u32);
        adapter
            .process_tcp_packet_from_payload(&tcp_seg(
                hp,
                PEER_ISN + 1,
                peer_ack_num,
                TcpFlags {
                    ack: true,
                    ..Default::default()
                },
                &[],
            ))
            .await
            .unwrap();

        // ACK frees window; second chunk goes out on the next flush.
        adapter.write_buffer_flush().await.unwrap();
        let psh2 = read_pkt(&mut test_rx).await;
        assert_eq!(psh2.payload, b"secnd");
        assert_eq!(
            psh2.sequence_number, peer_ack_num,
            "second segment starts where first left off"
        );
    }

    /// With a window larger than `mss`, multiple segments go out back-to-back
    /// before any ACK is received.
    #[tokio::test]
    async fn sliding_window_sends_multiple_segments() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );
        adapter.set_mss(10);
        adapter.set_send_window(40); // 4 segments worth.

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        adapter.queue_send(&[b'x'; 35], hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();

        let mut total = 0;
        for _ in 0..4 {
            let pkt = read_pkt(&mut test_rx).await;
            total += pkt.payload.len();
        }
        assert_eq!(total, 35, "all 35 bytes should be on the wire pre-ACK");
    }

    /// `send_window` caps how much can be in flight; data past the cap waits.
    #[tokio::test]
    async fn send_window_caps_in_flight_bytes() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );
        adapter.set_mss(10);
        adapter.set_send_window(20);

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        adapter.queue_send(&[b'x'; 50], hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();

        // First 20 bytes go out as two 10-byte segments.
        let p1 = read_pkt(&mut test_rx).await;
        let p2 = read_pkt(&mut test_rx).await;
        assert_eq!(p1.payload.len() + p2.payload.len(), 20);

        // The next 30 bytes are blocked behind the window.
        let blocked = tokio::time::timeout(Duration::from_millis(10), read_pkt(&mut test_rx)).await;
        assert!(blocked.is_err(), "must not exceed send_window before ACK");
    }

    /// Our outbound SYN advertises the Window Scale option (RFC 7323).
    #[tokio::test]
    async fn syn_advertises_window_scale() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, _test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );

        // Drive connect() far enough that the SYN hits the wire.
        let connect_fut = adapter.connect(PEER_PORT);
        let (_unused, syn) = tokio::join!(connect_fut, async { read_pkt(&mut test_rx).await });

        assert!(syn.flags.syn, "first packet must be SYN");
        let shift =
            crate::packets::parse_window_scale(&syn.options).expect("SYN should include WSopt");
        assert_eq!(shift, OUR_WSCALE, "advertised wscale should match constant");
    }

    /// When the peer's SYN-ACK includes a window scale, subsequent window
    /// advertisements are interpreted as `field << peer_wscale`.
    #[tokio::test]
    async fn peer_window_scale_is_honored() {
        tokio::time::pause();

        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );
        adapter.set_mss(10);
        adapter.set_send_window(1 << 20); // effectively unlimited from our side.

        let peer_wscale = 4u8;
        let peer_raw_window = 2u16; // scaled: 2 << 4 = 32 bytes.

        // Drive connect() while we manually act as the peer.
        let (hp_result, peer_hp) = tokio::join!(adapter.connect(PEER_PORT), async {
            let syn = read_pkt(&mut test_rx).await;
            assert!(syn.flags.syn);
            let hp = syn.source_port;

            // SYN-ACK with WSopt and a tiny scaled window.
            let wscale_opt = crate::packets::window_scale_option(peer_wscale);
            let tcp = TcpPacket::create(
                IpAddr::V6(PEER_IP),
                IpAddr::V6(HOST_IP),
                PEER_PORT,
                hp,
                PEER_ISN,
                syn.sequence_number.wrapping_add(1),
                TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
                peer_raw_window,
                &wscale_opt,
                &[],
            );
            let ip = crate::packets::Ipv6Packet::create(
                PEER_IP,
                HOST_IP,
                ProtocolNumber::Tcp,
                255,
                &tcp,
            );
            test_tx.write_all(&ip).await.unwrap();

            // Consume the adapter's ACK.
            let _ack = read_pkt(&mut test_rx).await;
            hp
        });
        let hp = hp_result.expect("connect failed");
        assert_eq!(hp, peer_hp);

        // Try to send 100 bytes. With peer_window=32 and mss=10, we expect
        // 3 full segments (30 bytes) plus one short segment (2 bytes) = 32
        // bytes on the wire; the remaining 68 bytes must be held.
        adapter.queue_send(&[b'a'; 100], hp).unwrap();
        adapter.write_buffer_flush().await.unwrap();

        let mut sent = 0;
        while sent < 32 {
            let p = read_pkt(&mut test_rx).await;
            sent += p.payload.len();
            assert!(sent <= 32, "must never exceed peer_window={}", 32);
        }
        assert_eq!(sent, 32);

        let blocked = tokio::time::timeout(Duration::from_millis(10), read_pkt(&mut test_rx)).await;
        assert!(blocked.is_err(), "must not exceed peer's scaled window");
    }

    #[tokio::test]
    async fn out_of_order_packet_dropped() {
        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        // After handshake the adapter expects seq = PEER_ISN + 1 from the peer.
        // Send seq = PEER_ISN + 100
        adapter
            .process_tcp_packet_from_payload(&tcp_seg(
                hp,
                PEER_ISN + 100,
                0,
                TcpFlags {
                    psh: true,
                    ack: true,
                    ..Default::default()
                },
                b"ooo",
            ))
            .await
            .unwrap();

        // No data should have been buffered.
        let buffered = adapter.uncache_all(hp).unwrap();
        assert!(
            buffered.is_empty(),
            "out-of-order data must not be buffered"
        );

        // No ACK should have been written to the transport.
        let no_ack = tokio::time::timeout(Duration::from_millis(10), read_pkt(&mut test_rx)).await;
        assert!(
            no_ack.is_err(),
            "out-of-order packet must not trigger an ACK"
        );
    }

    /// A duplicate segment (seq < expected, already received) is re-ACKed but
    /// its payload is not buffered a second time.
    #[tokio::test]
    async fn duplicate_packet_reacked_not_buffered() {
        let (adapter_end, test_end) = tokio::io::duplex(1 << 16);
        let (mut test_rx, mut test_tx) = tokio::io::split(test_end);
        let mut adapter = Adapter::new(
            Box::new(TestTransport(adapter_end)),
            IpAddr::V6(HOST_IP),
            IpAddr::V6(PEER_IP),
        );

        let hp = handshake(&mut adapter, &mut test_rx, &mut test_tx).await;

        // Inject the expected data packet.
        let data_seq = PEER_ISN + 1;
        adapter
            .process_tcp_packet_from_payload(&tcp_seg(
                hp,
                data_seq,
                0,
                TcpFlags {
                    psh: true,
                    ack: true,
                    ..Default::default()
                },
                b"hi",
            ))
            .await
            .unwrap();

        // Consume the ACK for the first delivery.
        let ack1 = read_pkt(&mut test_rx).await;
        assert!(ack1.flags.ack);
        assert_eq!(
            ack1.acknowledgment_number,
            data_seq.wrapping_add(2),
            "ACK should cover both bytes"
        );

        // Drain the read buffer so we can check it is not doubled.
        let first_read = adapter.uncache_all(hp).unwrap();
        assert_eq!(first_read, b"hi");

        // Re-inject the same segment (peer retransmit / duplicate).
        adapter
            .process_tcp_packet_from_payload(&tcp_seg(
                hp,
                data_seq,
                0,
                TcpFlags {
                    psh: true,
                    ack: true,
                    ..Default::default()
                },
                b"hi",
            ))
            .await
            .unwrap();

        // Should get a re-ACK with the same acknowledgment number.
        let ack2 = read_pkt(&mut test_rx).await;
        assert!(ack2.flags.ack);
        assert_eq!(
            ack2.acknowledgment_number, ack1.acknowledgment_number,
            "re-ACK must use same ack number as original"
        );

        // Data must NOT have been buffered again.
        let second_read = adapter.uncache_all(hp).unwrap();
        assert!(
            second_read.is_empty(),
            "duplicate payload must not be re-buffered"
        );
    }
}

# jktcp

A userspace TCP stack that runs over any async read/write transport.

Designed for **reliable, ordered transports**: such as CDTunnel from idevice
or a Unix socket carrying raw IP frames where real packet loss is rare but
correctness still matters.
The stack handles the TCP handshake, ACK tracking, and retransmission
so that the rest of your code can work with ordinary `AsyncRead` / `AsyncWrite`
streams.

## Features

- **3-way handshake** with SYN retransmission on timeout
- **Stop-and-wait reliability**: a segment is retransmitted with exponential
  back-off (200 ms -> 400 ms -> … → 6.4 s) until acknowledged
- **Connection timeout**: after 5 failed retransmissions the connection is
  closed with `ErrorKind::TimedOut`
- **In-order delivery**: out-of-order segments are dropped; duplicate segments
  are re-ACKed without re-buffering
- **IPv4 and IPv6** transports
- **PCAP capture** for Wireshark debugging
- Two usage patterns to match your lifetime and threading needs (see below)

## Two usage patterns

### 1. `AdapterStream` - single-task, lifetime-bound

`AdapterStream<'a>` holds a `&'a mut Adapter`.  While the stream exists it has
exclusive access to the adapter; there can only be one open stream at a time.

**Use this when:**

- You open one connection at a time.
- The stream lives entirely within a single async task.
- You don't need to store the stream in a struct or send it across tasks.

```rust
use jktcp::adapter::Adapter;
use jktcp::stream::AdapterStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::IpAddr;

let mut adapter = Adapter::new(Box::new(transport), host_ip, peer_ip);

// Optional: write a .pcap for Wireshark
adapter.pcap("capture.pcap").await?;

let mut stream = AdapterStream::connect(&mut adapter, 1234).await?;
stream.write_all(b"hello").await?;

let mut buf = [0u8; 1024];
let n = stream.read(&mut buf).await?;
println!("got: {:?}", &buf[..n]);

stream.close().await?;
```

### 2. `AdapterHandle` / `StreamHandle`: multi-task, `'static`

`AdapterHandle::new` (or `Adapter::to_async_handle`) spawns the adapter's I/O
loop onto the Tokio runtime.  Streams are created by calling
`handle.connect(port)` and the returned `StreamHandle` is `Send + Sync +
'static`.

A 1 ms internal tick drives retransmission and write-buffer flushing even when
no callers are actively awaiting, so retransmit timeouts are accurate regardless
of what the caller is doing.

**Use this when:**

- You need **multiple concurrent connections** on the same adapter.
- The stream must cross a `tokio::spawn` boundary.
- You store the stream in a struct (no lifetime parameter needed).
- You expose the stream through a `'static` trait object or FFI boundary.

```rust
use jktcp::adapter::Adapter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::IpAddr;

let adapter = Adapter::new(Box::new(transport), host_ip, peer_ip);
let mut handle = adapter.to_async_handle();

// Optional PCAP
handle.pcap("capture.pcap").await?;

// Open two connections concurrently
let mut s1 = handle.connect(1234).await?;
let mut s2 = handle.connect(5678).await?;

// StreamHandle is Send, move it into another task
tokio::spawn(async move {
    s1.write_all(b"from task").await.unwrap();
    let mut buf = [0u8; 64];
    s1.read(&mut buf).await.unwrap();
});

s2.write_all(b"direct").await?;
```

## Choosing between the two

| | `AdapterStream` | `AdapterHandle` / `StreamHandle` |
| --- | --- | --- |
| Concurrent connections | One at a time | Many |
| Cross-task (`tokio::spawn`) | No | Yes |
| `'static` bound | No | Yes |
| Store in struct without lifetime | No | Yes |
| Overhead | Minimal (direct `&mut`) | Small channel round-trip per write |
| Retransmit timer | Fires on next `process_tcp_packet` timeout (≤500 ms) | 1 ms background tick |

## Transport requirements

The transport passed to `Adapter::new` must implement `AsyncRead + AsyncWrite +
Unpin + Send + Sync + Debug` (the [`jktcp::ReadWrite`] trait).  It must carry
**framed IPv4 or IPv6 packets**, jktcp does not add its own framing. TUN
devices, CDTunnel connections, and in-process pipes (e.g. `tokio::io::duplex`)
all work.

## PCAP debugging

Call `adapter.pcap("out.pcap")` (or `handle.pcap(…)`) before opening any
connections.  The file is a standard libpcap capture
and can be opened directly in Wireshark.

## Retransmission details

| Retry | RTO |
| --- | --- |
| 1st | 200 ms |
| 2nd | 400 ms |
| 3rd | 800 ms |
| 4th | 1.6 s |
| 5th | 3.2 s |
| (killed) | after 6.4 s without ACK |

After the 5th retry the connection is marked `Error(TimedOut)`.  The next read
or write on the stream will return that error.

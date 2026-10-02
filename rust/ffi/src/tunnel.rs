use std::collections::HashMap;
use std::net::IpAddr;

use idevice::heartbeat::HeartbeatClient;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::remote_pairing::{
    connect_tls_psk_tunnel_native, RemotePairingClient, RpPairingFile, RpPairingSocket,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::RsdService;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::pairing::PairingError;

/// Connection info for an established tunnel, returned once so the caller
/// doesn't need a round-trip just to see what got negotiated.
#[derive(uniffi::Record, Clone)]
pub struct TunnelInfo {
    pub client_address: String,
    pub server_address: String,
    pub mtu: u16,
    /// Names of RSD services the device advertised over this tunnel (e.g.
    /// `com.apple.coredevice.appservice`, `com.apple.mobile.installation_proxy`).
    pub rsd_services: Vec<String>,
    pub device_uuid: String,
}

#[derive(uniffi::Record)]
pub struct InstalledApp {
    pub name: String,
    pub bundle_identifier: String,
    pub version: Option<String>,
}

/// A live TLS-PSK tunnel to an already-paired Apple TV, established over the
/// device's RemotePairing control channel (see `PairingSession`). Holds the
/// userspace TCP adapter open so further RSD services can be reached without
/// re-doing the tunnel handshake for every call.
#[derive(uniffi::Object)]
pub struct TunnelSession {
    pub(crate) handle: Mutex<AdapterHandle>,
    pub(crate) services: HashMap<String, idevice::rsd::RsdService>,
    info: TunnelInfo,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    // The listener belongs to this RemotePairing control connection. Dropping
    // it after setup lets the device tear down the tunnel underneath us.
    _control: Mutex<RemotePairingClient<RpPairingSocket<TcpStream>>>,
}

impl Drop for TunnelSession {
    fn drop(&mut self) {
        if let Some(heartbeat) = &self.heartbeat {
            heartbeat.abort();
        }
    }
}

async fn maintain_heartbeat(mut client: HeartbeatClient) -> Result<(), idevice::IdeviceError> {
    let mut interval = 15;
    loop {
        interval = client.get_marco(interval).await?.saturating_add(5);
        client.send_polo().await?;
    }
}

impl TunnelSession {
    /// Looks up the tunnel-local port for an RSD service by name (see
    /// `idevice::RsdService::rsd_service_name()` for the various `*Client`
    /// types), e.g. `"com.apple.afc.shim.remote"`.
    pub(crate) fn service_port(&self, name: &str) -> Result<u16, PairingError> {
        self.services
            .get(name)
            .map(|s| s.port)
            .ok_or_else(|| PairingError::Message(format!("{name} not advertised by this device")))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TunnelSession {
    /// Reconnects to `host:port` using a pairing record from a prior
    /// `PairingSession::pair` call (no PIN needed -- pair-verify alone
    /// re-establishes trust), then opens the device's TLS-PSK tunnel and
    /// performs the RSD handshake through it.
    #[uniffi::constructor]
    pub async fn connect(
        host: String,
        port: u16,
        sending_host: String,
        pairing_file: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, PairingError> {
        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| PairingError::Message(format!("connect to {host}:{port} failed: {e}")))?;
        let conn = RpPairingSocket::new(stream);

        let mut pairing_file = RpPairingFile::from_bytes(&pairing_file)?;
        let mut client = RemotePairingClient::new(conn, &sending_host);

        // A saved pairing record should always verify without needing a new
        // PIN; if the device no longer recognizes it (e.g. it was un-paired
        // on the TV), this dummy PIN deliberately fails SRP rather than
        // silently completing a surprise re-pair.
        client
            .connect(&mut pairing_file, || async { "000000".to_string() })
            .await?;

        let listener_port = client.create_tcp_listener().await?;
        let tunnel_stream = TcpStream::connect((host.as_str(), listener_port))
            .await
            .map_err(|e| {
                PairingError::Message(format!(
                    "tunnel connect to {host}:{listener_port} failed: {e}"
                ))
            })?;
        let tunnel = connect_tls_psk_tunnel_native(tunnel_stream, client.encryption_key()).await?;

        let client_ip: IpAddr = tunnel
            .info
            .client_address
            .parse()
            .map_err(|e| PairingError::Message(format!("bad tunnel client address: {e}")))?;
        let server_ip: IpAddr = tunnel
            .info
            .server_address
            .parse()
            .map_err(|e| PairingError::Message(format!("bad tunnel server address: {e}")))?;
        let rsd_port = tunnel.info.server_rsd_port;
        let client_address = tunnel.info.client_address.clone();
        let server_address = tunnel.info.server_address.clone();
        let mtu = tunnel.info.mtu;

        let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
        // Size TCP segments to the tunnel's negotiated MTU (minus IPv6 + TCP
        // headers) rather than jktcp's conservative 1280-byte default. The
        // RemoteXPC tunnel negotiates a much larger MTU, so this cuts a
        // 100 MB+ IPA from ~100k tiny segments down to far fewer -- a large
        // throughput win that also shrinks the window in which a device stall
        // could trip the retransmit timeout.
        if (mtu as usize) > 60 {
            adapter.set_mss(mtu as usize - 60);
        }
        let mut handle = adapter.to_async_handle();

        let rsd_stream = handle.connect(rsd_port).await.map_err(|e| {
            PairingError::Message(format!("connect to RSD through tunnel failed: {e}"))
        })?;
        let handshake = RsdHandshake::new(rsd_stream).await?;

        // Device services close idle connections without a Marco/Polo client.
        // Keep it running while the user picks an IPA and while signing runs.
        let heartbeat_client = if let Some(service) = handshake
            .services
            .get(HeartbeatClient::rsd_service_name().as_ref())
        {
            let stream = handle.connect(service.port).await.map_err(|e| {
                PairingError::Message(format!("connect to heartbeat through tunnel failed: {e}"))
            })?;
            Some(HeartbeatClient::from_stream(Box::new(stream)).await?)
        } else {
            None
        };

        // Apple's addDevice.action wants the device's hardware UDID, which the
        // RSD handshake exposes in its Properties under "UniqueDeviceID" (the
        // same key lockdown uses). `handshake.uuid` is only the RemoteXPC
        // session id -- Apple rejects it with "invalid value for deviceNumber",
        // so fall back to it only if the real UDID is somehow absent.
        let device_uuid = handshake
            .properties
            .get("UniqueDeviceID")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| handshake.uuid.clone());

        let rsd_services: Vec<String> = handshake.services.keys().cloned().collect();

        let info = TunnelInfo {
            client_address,
            server_address,
            mtu,
            rsd_services,
            device_uuid,
        };

        let heartbeat = heartbeat_client.map(|client| {
            tokio::spawn(async move {
                // A heartbeat timeout or service EOF is local to this stream.
                // Let the adapter's transport detect tunnel failures; closing
                // it here also kills unrelated AFC/installation connections.
                let _ = maintain_heartbeat(client).await;
            })
        });

        Ok(std::sync::Arc::new(Self {
            handle: Mutex::new(handle),
            services: handshake.services,
            info,
            heartbeat,
            _control: Mutex::new(client),
        }))
    }

    pub fn info(&self) -> TunnelInfo {
        self.info.clone()
    }

    /// Lists apps installed on the device via `installation_proxy` (the
    /// service `sign-rsd`-style installs also use -- `AppService` isn't
    /// advertised on tvOS, only on iOS/Xcode-era CoreDevice targets).
    pub async fn list_installed_apps(&self) -> Result<Vec<InstalledApp>, PairingError> {
        let install_port = self.service_port(&InstallationProxyClient::rsd_service_name())?;

        let mut handle = self.handle.lock().await;
        let stream = handle.connect(install_port).await.map_err(|e| {
            PairingError::Message(format!(
                "connect to installation_proxy through tunnel failed: {e}"
            ))
        })?;
        let mut client = InstallationProxyClient::from_stream(Box::new(stream)).await?;
        let apps = client.get_apps(Some("User"), None).await?;

        Ok(apps
            .into_iter()
            .map(|(bundle_identifier, info)| {
                let dict = info.as_dictionary();
                let name = dict
                    .and_then(|d| {
                        d.get("CFBundleDisplayName")
                            .or_else(|| d.get("CFBundleName"))
                    })
                    .and_then(|v| v.as_string())
                    .unwrap_or(&bundle_identifier)
                    .to_string();
                let version = dict
                    .and_then(|d| {
                        d.get("CFBundleShortVersionString")
                            .or_else(|| d.get("CFBundleVersion"))
                    })
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_string());
                InstalledApp {
                    name,
                    bundle_identifier,
                    version,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn pairing_control_stays_open_until_session_is_dropped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let (transport, _device) = tokio::io::duplex(4096);
        let handle = Adapter::new(
            Box::new(transport),
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
        )
        .to_async_handle();
        let session = TunnelSession {
            handle: Mutex::new(handle),
            services: HashMap::new(),
            info: TunnelInfo {
                client_address: String::new(),
                server_address: String::new(),
                mtu: 16000,
                rsd_services: Vec::new(),
                device_uuid: String::new(),
            },
            heartbeat: None,
            _control: Mutex::new(RemotePairingClient::new(
                RpPairingSocket::new(control),
                "test",
            )),
        };
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.read(&mut byte))
                .await
                .is_err()
        );
        drop(session);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn closed_adapter_keeps_transport_failure_reason() {
        let (transport, device) = tokio::io::duplex(4096);
        let mut handle = Adapter::new(
            Box::new(transport),
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
        )
        .to_async_handle();
        drop(device);
        let error = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let error = handle.connect(1234).await.unwrap_err();
                if error.to_string().contains("adapter closed") {
                    break error;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains("transport closed"));
    }

    #[tokio::test]
    async fn heartbeat_replies_to_repeated_marco_and_stops_on_disconnect() {
        let (stream, mut device) = tokio::io::duplex(4096);
        let client = HeartbeatClient::new(idevice::Idevice::new(Box::new(stream), "test"));
        let task = tokio::spawn(maintain_heartbeat(client));

        for interval in [1, 2] {
            let marco = format!(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Interval</key><integer>{interval}</integer></dict></plist>"
            );
            device
                .write_all(&(marco.len() as u32).to_be_bytes())
                .await
                .unwrap();
            device.write_all(marco.as_bytes()).await.unwrap();
            let response = tokio::time::timeout(Duration::from_secs(2), async {
                let length = device.read_u32().await.unwrap();
                let mut reply = vec![0; length as usize];
                device.read_exact(&mut reply).await.unwrap();
                String::from_utf8(reply).unwrap()
            })
            .await
            .expect("heartbeat did not respond");
            assert!(response.contains("<key>Command</key>"));
            assert!(response.contains("<string>Polo</string>"));
        }

        drop(device);
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("heartbeat stayed alive after disconnect")
            .unwrap()
            .is_err());
    }
}

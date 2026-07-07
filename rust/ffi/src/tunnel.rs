use std::collections::HashMap;
use std::net::IpAddr;

use idevice::RsdService;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::remote_pairing::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
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
                PairingError::Message(format!("tunnel connect to {host}:{listener_port} failed: {e}"))
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

        let rsd_stream = handle
            .connect(rsd_port)
            .await
            .map_err(|e| PairingError::Message(format!("connect to RSD through tunnel failed: {e}")))?;
        let handshake = RsdHandshake::new(rsd_stream).await?;

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

        Ok(std::sync::Arc::new(Self {
            handle: Mutex::new(handle),
            services: handshake.services,
            info,
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
            PairingError::Message(format!("connect to installation_proxy through tunnel failed: {e}"))
        })?;
        let mut client = InstallationProxyClient::from_stream(Box::new(stream)).await?;
        let apps = client.get_apps(Some("User"), None).await?;

        Ok(apps
            .into_iter()
            .map(|(bundle_identifier, info)| {
                let dict = info.as_dictionary();
                let name = dict
                    .and_then(|d| d.get("CFBundleDisplayName").or_else(|| d.get("CFBundleName")))
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
                InstalledApp { name, bundle_identifier, version }
            })
            .collect())
    }
}

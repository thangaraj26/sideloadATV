use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use tokio::net::TcpStream;

#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum PairingError {
    #[error("{0}")]
    Message(String),
}

impl From<idevice::IdeviceError> for PairingError {
    fn from(e: idevice::IdeviceError) -> Self {
        // Several IdeviceError variants (notably `Socket`, which just says
        // "device socket io failed") hide the real cause in their `source()`
        // chain -- the wrapped io::Error carries the useful part
        // ("connection reset by peer", "broken pipe", "timed out", ...).
        // Flatten the whole chain so the Kotlin side sees it.
        let mut msg = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            msg.push_str(": ");
            msg.push_str(&cause.to_string());
            source = cause.source();
        }
        PairingError::Message(msg)
    }
}

/// Implemented on the Kotlin side: shows the user a prompt and suspends until
/// they type in the PIN currently displayed on the Apple TV's screen. Only
/// called when pairing with a device for the first time -- reconnecting with
/// a previously-saved pairing record never needs a PIN.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PinPrompter: Send + Sync {
    async fn request_pin(&self) -> String;
}

/// Result of a successful `PairingSession::pair` call.
#[derive(uniffi::Record)]
pub struct PairingResult {
    /// Opaque pairing record (identity key + peer identifier) to persist and
    /// pass back into `pair` on the next connection attempt, so re-pairing
    /// (and the PIN prompt) can be skipped.
    pub pairing_file: Vec<u8>,
    /// Populated only when this call performed a fresh pairing (i.e. no
    /// `existing_pairing_file` was supplied, or it didn't validate).
    pub device_name: Option<String>,
    pub device_model: Option<String>,
    pub device_udid: Option<String>,
}

#[derive(uniffi::Object)]
pub struct PairingSession;

#[uniffi::export(async_runtime = "tokio")]
impl PairingSession {
    #[uniffi::constructor]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self)
    }

    /// Connects to the Apple TV at `host:port` (as already resolved by
    /// Kotlin's `NsdManager`) and pairs with it, prompting for the on-screen
    /// PIN via `pin_prompter` if needed. `sending_host` is this app's
    /// self-chosen device name, shown on the Apple TV during pairing.
    ///
    /// Pass a previously-returned `pairing_file` in `existing_pairing_file`
    /// to reuse an existing pairing; `pin_prompter` is only invoked if that
    /// record no longer validates (e.g. the user un-paired on the TV).
    pub async fn pair(
        &self,
        host: String,
        port: u16,
        sending_host: String,
        existing_pairing_file: Option<Vec<u8>>,
        pin_prompter: std::sync::Arc<dyn PinPrompter>,
    ) -> Result<PairingResult, PairingError> {
        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| PairingError::Message(format!("connect to {host}:{port} failed: {e}")))?;
        let conn = RpPairingSocket::new(stream);

        let mut pairing_file = match existing_pairing_file {
            Some(bytes) => RpPairingFile::from_bytes(&bytes)?,
            None => RpPairingFile::generate(&sending_host),
        };

        let mut client = RemotePairingClient::new(conn, &sending_host);
        client
            .connect(&mut pairing_file, move || {
                let pin_prompter = pin_prompter.clone();
                async move { pin_prompter.request_pin().await }
            })
            .await?;

        let peer = client.paired_peer_device().ok();
        Ok(PairingResult {
            pairing_file: pairing_file.to_bytes(),
            device_name: peer.map(|p| p.name.clone()),
            device_model: peer.map(|p| p.model.clone()),
            device_udid: peer.map(|p| p.remotepairing_udid.clone()),
        })
    }
}

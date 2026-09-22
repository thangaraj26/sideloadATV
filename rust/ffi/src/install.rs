use idevice::RsdService;
use idevice::afc::AfcClient;
use idevice::afc::opcode::AfcFopenMode;
use idevice::installation_proxy::InstallationProxyClient;

use crate::pairing::PairingError;
use crate::tunnel::TunnelSession;

/// Implemented on the Kotlin side to receive install progress updates.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait InstallProgressListener: Send + Sync {
    /// `percent_complete` matches whatever `installation_proxy` reports on
    /// the device -- not guaranteed to be monotonic or evenly spaced.
    async fn on_progress(&self, percent_complete: u32);
}

#[uniffi::export(async_runtime = "tokio")]
impl TunnelSession {
    /// Uploads the IPA at `ipa_path` to the device's `PublicStaging` directory
    /// via AFC, then asks `installation_proxy` to install it.
    ///
    /// Accepts a file path rather than bytes so that large IPAs never have to
    /// be passed across the JNI boundary. The file is read on the Rust side
    /// and deleted after a successful upload.
    ///
    /// The IPA must already be signed with a certificate + provisioning
    /// profile valid for this device's UDID -- this call only performs the
    /// transfer and install RPC, not signing.
    pub async fn install_ipa(
        &self,
        ipa_path: String,
        file_name: String,
        progress: std::sync::Arc<dyn InstallProgressListener>,
    ) -> Result<(), PairingError> {
        let ipa_bytes = tokio::fs::read(&ipa_path)
            .await
            .map_err(|e| PairingError::Message(format!("could not read signed IPA: {e}")))?;

        let afc_port = self.service_port(&AfcClient::rsd_service_name())?;
        let install_port = self.service_port(&InstallationProxyClient::rsd_service_name())?;
        let remote_path = format!("PublicStaging/{file_name}");

        let mut handle = self.handle.lock().await;

        let afc_stream = handle
            .connect(afc_port)
            .await
            .map_err(|e| PairingError::Message(format!("connect to AFC through tunnel failed: {e}")))?;
        let mut afc = AfcClient::from_stream(Box::new(afc_stream)).await?;
        // Ignore the error: PublicStaging already exists on every device
        // we've seen, and mk_dir has no "already exists, that's fine" variant.
        let _ = afc.mk_dir("PublicStaging").await;
        let mut fd = afc.open_owned(remote_path.clone(), AfcFopenMode::WrOnly).await?;
        fd.write_entire(&ipa_bytes).await?;
        fd.close().await?;
        drop(ipa_bytes);
        let _ = tokio::fs::remove_file(&ipa_path).await;

        let install_stream = handle.connect(install_port).await.map_err(|e| {
            PairingError::Message(format!("connect to installation_proxy through tunnel failed: {e}"))
        })?;
        let mut installer = InstallationProxyClient::from_stream(Box::new(install_stream)).await?;
        installer
            .install_with_callback(
                remote_path,
                None,
                move |(percent, _)| {
                    let progress = progress.clone();
                    async move { progress.on_progress(percent as u32).await }
                },
                (),
            )
            .await?;

        Ok(())
    }
}

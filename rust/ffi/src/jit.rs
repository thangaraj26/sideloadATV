use idevice::RsdService;
use idevice::debug_proxy::DebugProxyClient;
use idevice::dvt::device_info::DeviceInfoClient;
use idevice::dvt::remote_server::RemoteServerClient;

use crate::pairing::PairingError;
use crate::tunnel::TunnelSession;

#[uniffi::export(async_runtime = "tokio")]
impl TunnelSession {
    /// Enables JIT compilation for a running app identified by `bundle_id`.
    ///
    /// Free-account provisioning profiles always include `get-task-allow = true`,
    /// which permits debugger attachment. This method uses that permission to
    /// briefly attach via the GDB RSP debug proxy (same technique as AltJIT /
    /// StikJIT on iOS), which causes the OS to mark the process as JIT-enabled.
    /// The app must already be running on the Apple TV when this is called.
    pub async fn enable_jit(&self, bundle_id: String) -> Result<(), PairingError> {
        // Service name strings needed for port lookups.
        let dvt_service = RemoteServerClient::<Box<dyn idevice::ReadWrite>>::rsd_service_name();
        let dbg_service = DebugProxyClient::<Box<dyn idevice::ReadWrite>>::rsd_service_name();

        let dvt_port = self.service_port(&dvt_service)?;
        let dbg_port = self.service_port(&dbg_service)?;

        let mut handle = self.handle.lock().await;

        // Step 1: find the PID of the running app via DVT DeviceInfo.
        let pid = {
            let dvt_stream = handle.connect(dvt_port).await.map_err(|e| {
                PairingError::Message(format!("connect to DVT through tunnel failed: {e}"))
            })?;
            let mut dvt = RemoteServerClient::new(dvt_stream);
            let mut device_info = DeviceInfoClient::new(&mut dvt).await.map_err(|e| {
                PairingError::Message(format!("open DVT DeviceInfo channel failed: {e}"))
            })?;
            let processes = device_info.running_processes().await.map_err(|e| {
                PairingError::Message(format!("list running processes failed: {e}"))
            })?;

            processes
                .into_iter()
                .filter(|p| p.is_application)
                .find(|p| p.real_app_name.contains(bundle_id.as_str()) || p.name == bundle_id)
                .ok_or_else(|| {
                    PairingError::Message(format!(
                        "{bundle_id} is not running — launch it on the Apple TV first"
                    ))
                })?
                .pid
        };

        // Step 2: connect to the GDB RSP debug proxy and attach to the process.
        // Attaching causes the OS to enable JIT (W^X writable+executable pages)
        // for the process. We then immediately send continue so it resumes.
        let dbg_stream = handle.connect(dbg_port).await.map_err(|e| {
            PairingError::Message(format!("connect to DebugProxy through tunnel failed: {e}"))
        })?;
        let mut dbg = DebugProxyClient::from_stream(Box::new(dbg_stream))
            .await
            .map_err(|e| PairingError::Message(format!("DebugProxy init failed: {e}")))?;

        // Switch to no-ack mode so we don't have to handle '+' ACKs.
        dbg.send_raw(&gdb_packet("QStartNoAckMode")).await.map_err(|e| {
            PairingError::Message(format!("send QStartNoAckMode failed: {e}"))
        })?;
        dbg.read_response()
            .await
            .map_err(|e| PairingError::Message(format!("read QStartNoAckMode response failed: {e}")))?;
        dbg.set_ack_mode(false);

        // Attach: the device suspends the process and replies with a T stop packet.
        let attach = format!("vAttach;{pid:x}");
        dbg.send_raw(&gdb_packet(&attach)).await.map_err(|e| {
            PairingError::Message(format!("send vAttach failed: {e}"))
        })?;
        dbg.read_response()
            .await
            .map_err(|e| PairingError::Message(format!("read vAttach response failed: {e}")))?;

        // Continue: the process resumes with JIT now enabled. We don't wait for
        // a response — just drop the connection and the proxy detaches implicitly.
        dbg.send_raw(&gdb_packet("c"))
            .await
            .map_err(|e| PairingError::Message(format!("send continue failed: {e}")))?;

        Ok(())
    }
}

/// Formats a GDB Remote Serial Protocol packet: `$<data>#<checksum>`.
fn gdb_packet(data: &str) -> Vec<u8> {
    let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    format!("${data}#{checksum:02x}").into_bytes()
}

uniffi::setup_scaffolding!();

mod auth;
pub use auth::{GrandslamSession, GsError, GsLoginState};

mod pairing;
pub use pairing::{PairingError, PairingResult, PairingSession, PinPrompter};

mod tunnel;
pub use tunnel::{InstalledApp, TunnelInfo, TunnelSession};

mod install;
pub use install::InstallProgressListener;

mod signing;
pub use signing::{SigningError, SigningSession, TeamInfo};

mod store;
pub use store::{StoredAppInfo, list_stored_apps, refresh_stored_app, remove_stored_app};

/// Build-pipeline smoke test: exercises plume_core's TLS client (rustls/reqwest/
/// rcgen/x509 stack) and idevice's pairing-file parser, to prove both dependency
/// graphs actually cross-compile and link into an Android cdylib.
#[uniffi::export]
pub fn ffi_smoke_test() -> String {
    let core_result = match plume_core::client() {
        Ok(_) => "plume_core::client() OK".to_string(),
        Err(e) => format!("plume_core::client() FAILED: {e}"),
    };

    let idevice_result = match idevice::pairing_file::PairingFile::from_bytes(&[]) {
        Ok(_) => "idevice::PairingFile::from_bytes(empty) unexpectedly OK".to_string(),
        Err(e) => format!("idevice::PairingFile::from_bytes(empty) errored as expected: {e}"),
    };

    format!("{core_result}\n{idevice_result}")
}

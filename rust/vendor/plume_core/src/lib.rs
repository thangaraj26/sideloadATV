pub mod auth;
pub mod developer;
pub mod store;
mod utils;

pub use apple_codesign::{AppleCodesignError, SettingsScope, SigningSettings, UnifiedSigner};

pub use omnisette::AnisetteConfiguration;

pub use utils::{CertificateIdentity, MachO, MachOExt, MobileProvision};

use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Executable not found")]
    BundleExecutableMissing,
    #[error("Entitlements not found")]
    ProvisioningEntitlementsUnknown,
    #[error("Missing certificate PEM data")]
    CertificatePemMissing,
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("Developer API error {result_code} (HTTP {http_code:?}): {message} [URL: {url}]")]
    DeveloperApi {
        url: String,
        result_code: i64,
        http_code: Option<u16>,
        message: String,
    },
    #[error("Request to developer session failed")]
    DeveloperSessionRequestFailed,
    #[error("Authentication SRP error {0}: {1}")]
    AuthSrpWithMessage(i64, String),
    #[error("Authentication extra step required: {0}")]
    ExtraStep(String),
    #[error("Bad 2FA code")]
    Bad2faCode,
    #[error("Failed to parse")]
    Parse, // TODO: better parsing errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),
    #[error("Codesign error: {0}")]
    Codesign(#[from] apple_codesign::AppleCodesignError),
    #[error("CodeSignBuilder error: {0}")]
    CodeSignBuilder(#[from] apple_codesign::UniversalMachOError),
    #[error("Certificate PEM error: {0}")]
    Pem(#[from] pem::PemError),
    #[error("X509 certificate error: {0}")]
    X509(#[from] x509_certificate::X509CertificateError),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Anisette error: {0}")]
    Anisette(#[from] omnisette::AnisetteError),
    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("PKCS1 RSA error: {0}")]
    PKCS1(#[from] rsa::pkcs1::Error),
    #[error("PKCS8 RSA error: {0}")]
    PKCS8(#[from] rsa::pkcs8::Error),
    #[error("RCGen error: {0}")]
    RcGen(#[from] rcgen::RcgenError),
}

// rustls 0.23's `aws_lc_rs` feature is on by default; since some dependency
// in this graph pulls that in alongside the `ring` feature we request
// explicitly (and aws-lc-rs's BoringSSL-derived C code doesn't build for
// Android anyway), rustls can no longer auto-select a process-wide default
// and errors at the first TLS handshake instead. `client()` looked like the
// right chokepoint to install one explicitly, but it isn't early enough:
// `Account::new`'s anisette provisioning step (via `omnisette`) makes its own
// network call, with its own reqwest/rustls stack, before `client()` is ever
// invoked. A `#[ctor]` function instead runs when the dynamic linker loads
// this code (Android's JNA-based native loading still triggers ELF
// constructors, unlike the JNI-specific `JNI_OnLoad` hook, which JNA never
// calls) -- guaranteed to run before any exported FFI function, regardless
// of which one is called first.
#[ctor::ctor]
fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn client() -> Result<reqwest::Client, Error> {
    const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");
    let client = reqwest::ClientBuilder::new()
        .add_root_certificate(reqwest::Certificate::from_der(APPLE_ROOT)?)
        // uncomment when debugging w/ charles proxy
        // .danger_accept_invalid_certs(true)
        .http1_title_case_headers()
        .connection_verbose(true)
        .build()?;

    Ok(client)
}

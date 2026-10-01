//! Provision on the target device without sending Apple ID credentials.
use omnisette::{
    anisette_headers_provider::AnisetteHeadersProvider,
    remote_anisette_v3::RemoteAnisetteProviderV3,
};

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = std::env::args()
        .nth(1)
        .expect("usage: anisette_check <state-directory> [server-url]");
    let mut provider = RemoteAnisetteProviderV3::new(
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| omnisette::DEFAULT_ANISETTE_URL_V3.into()),
        directory.into(),
        "0".into(),
    );
    match provider.get_authentication_headers().await {
        Ok(_) => println!("Anisette v3 provisioning and header generation succeeded"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

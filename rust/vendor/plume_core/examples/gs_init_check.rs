//! Probe the SRP init response using a nonexistent account, without a password.
use plist::{Dictionary, Value};
use plume_core::{
    AnisetteConfiguration,
    auth::{
        Account,
        account::{grandslam_headers, parse_response},
    },
};
use sha2::Sha256;
use srp::{client::SrpClient, groups::G_2048};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = std::env::args()
        .nth(1)
        .expect("usage: gs_init_check <state-directory>");
    let account =
        Account::new(AnisetteConfiguration::new().set_configuration_path(path.into())).await?;
    let anisette = account.get_anisette().await;
    let headers = grandslam_headers(&anisette)?;
    let a: [u8; 32] = rand::random();
    let mut request = Dictionary::new();
    request.insert(
        "A2k".into(),
        Value::Data(SrpClient::<Sha256>::new(&G_2048).compute_public_ephemeral(&a)),
    );
    request.insert(
        "cpd".into(),
        Value::Dictionary(anisette.to_plist(true, false, false)),
    );
    request.insert("o".into(), Value::String("init".into()));
    request.insert(
        "ps".into(),
        Value::Array(vec![
            Value::String("s2k".into()),
            Value::String("s2k_fo".into()),
        ]),
    );
    request.insert(
        "u".into(),
        Value::String("protocol-check@example.invalid".into()),
    );
    let mut header = Dictionary::new();
    header.insert("Version".into(), Value::String("1.0.1".into()));
    let mut packet = Dictionary::new();
    packet.insert("Header".into(), Value::Dictionary(header));
    packet.insert("Request".into(), Value::Dictionary(request));
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, &packet)?;
    let response = account
        .client
        .post("https://gsa.apple.com/grandslam/GsService2")
        .headers(headers)
        .body(body)
        .send()
        .await?;
    println!("SRP init HTTP {}", response.status().as_u16());
    let response = parse_response(Ok(response)).await?;
    let status = response.get("Status").and_then(Value::as_dictionary);
    println!(
        "Valid authentication plist, status code {:?}",
        status
            .and_then(|s| s.get("ec"))
            .and_then(Value::as_signed_integer)
    );
    Ok(())
}

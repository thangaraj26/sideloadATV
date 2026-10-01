use std::{collections::HashMap, time::SystemTime};

use omnisette::{
    AnisetteConfiguration,
    anisette_headers_provider::AnisetteHeadersProvider,
    remote_anisette_v3::{AnisetteState, ProvisionInput, RemoteAnisetteProviderV3},
};
use plume_core::auth::anisette_data::AnisetteData;

async fn mock_anisette_server(
    unavailable: bool,
) -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let request = String::from_utf8_lossy(&request);
            let (status, body) = if unavailable {
                ("503 Service Unavailable", "{}")
            } else if request.starts_with("GET /v3/client_info ") {
                (
                    "200 OK",
                    r#"{"client_info":"<TestMac> <macOS;13.1;TEST> <com.apple.AuthKit/1 (com.apple.akd/1.0)>","user_agent":"test"}"#,
                )
            } else {
                assert!(request.starts_with("POST /v3/get_headers "));
                (
                    "200 OK",
                    r#"{"result":"Headers","X-Apple-I-MD":"test-otp","X-Apple-I-MD-M":"test-machine","X-Apple-I-MD-RINFO":"17106176"}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, requests, task)
}

#[tokio::test]
async fn failed_server_falls_back_and_remembers_the_working_server() {
    use std::sync::atomic::Ordering;
    let (primary, primary_calls, primary_task) = mock_anisette_server(true).await;
    let (fallback, fallback_calls, fallback_task) = mock_anisette_server(false).await;
    let directory =
        std::env::temp_dir().join(format!("sideloadatv-failover-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let mut state = plist::Dictionary::new();
    state.insert(
        "keychain_identifier".into(),
        plist::Value::Data(vec![7; 16]),
    );
    state.insert("adi_pb".into(), plist::Value::Data(vec![1, 2, 3]));
    // A saved URL outside the configured pool must never be contacted.
    state.insert(
        "server_url".into(),
        plist::Value::String("http://127.0.0.1:1".into()),
    );
    plist::to_file_xml(directory.join("state.plist"), &state).unwrap();
    let provider = || {
        RemoteAnisetteProviderV3::new(primary.clone(), directory.clone(), "0".into())
            .with_fallback_urls(vec![fallback.clone()])
    };
    let first = provider().get_authentication_headers().await.unwrap();
    assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 2);
    let saved: plist::Dictionary = plist::from_file(directory.join("state.plist")).unwrap();
    assert_eq!(saved["server_url"].as_string(), Some(fallback.as_str()));
    assert_eq!(saved["keychain_identifier"], state["keychain_identifier"]);
    assert_eq!(saved["adi_pb"], state["adi_pb"]);
    let second = provider().get_authentication_headers().await.unwrap();
    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        1,
        "reopened provider retried the broken server"
    );
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 4);
    assert!(first["X-Mme-Device-Id"] == second["X-Mme-Device-Id"]);
    primary_task.abort();
    fallback_task.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn provisioning_server_failures_preserve_the_actual_reason() {
    for stage in ["StartProvisioningError", "EndProvisioningError"] {
        let packet =
            serde_json::json!({"result": stage, "message": "ADI error -45061 (request id: test)"});
        let error = ProvisionInput::parse(&packet.to_string()).unwrap_err();
        assert!(
            matches!(&error, omnisette::AnisetteError::RemoteProvisioning { stage: actual, message }
            if actual == stage && message == "ADI error -45061 (request id: test)")
        );
        assert!(error.to_string().contains("-45061"));
        assert!(error.is_retryable_provisioning());
    }
    for stage in ["Timeout", "InvalidIdentifier"] {
        let packet = serde_json::json!({"result": stage});
        assert!(matches!(ProvisionInput::parse(&packet.to_string()),
            Err(omnisette::AnisetteError::RemoteProvisioning { stage: actual, .. }) if actual == stage));
    }
    assert!(matches!(
        ProvisionInput::parse(r#"{"result":"GiveIdentifier"}"#).unwrap(),
        ProvisionInput::GiveIdentifier
    ));
    let invalid = ProvisionInput::parse(r#"{"result":"InvalidIdentifier"}"#).unwrap_err();
    assert!(!invalid.is_retryable_provisioning());
    let timeout = ProvisionInput::parse(r#"{"result":"Timeout"}"#).unwrap_err();
    assert!(timeout.is_retryable_provisioning());
    assert!(
        !omnisette::AnisetteError::InvalidArgument("bad configuration".into())
            .is_retryable_provisioning()
    );
}

#[test]
fn header_lookup_preserves_case_sensitive_values() {
    let data = AnisetteData {
        base_headers: HashMap::from([
            ("X-Apple-I-MD".into(), "AbCdEf+/==".into()),
            (
                "X-Mme-Client-Info".into(),
                "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                    .into(),
            ),
        ]),
        generated_at: SystemTime::now(),
        config: AnisetteConfiguration::new(),
    };
    assert_eq!(data.get_header("x-apple-i-md").unwrap(), "AbCdEf+/==");
    assert!(
        data.get_header("X-MME-CLIENT-INFO")
            .unwrap()
            .starts_with("<MacBookPro13,2> <macOS;")
    );
    assert!(data.get_header("missing").is_err());
}

#[test]
fn v3_state_rejects_invalid_identifier_without_panicking() {
    let mut state = plist::Dictionary::new();
    state.insert(
        "keychain_identifier".into(),
        plist::Value::Data(vec![0; 15]),
    );
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &state).unwrap();
    assert!(plist::from_bytes::<AnisetteState>(&bytes).is_err());
}

#[tokio::test]
#[ignore = "contacts Apple and SideStore to provision a test device; no account credentials"]
async fn live_v3_provisioning_reuses_persisted_identity() {
    let directory =
        std::env::temp_dir().join(format!("sideloadatv-anisette-{}", uuid::Uuid::new_v4()));
    let provider = || {
        RemoteAnisetteProviderV3::new(
            omnisette::DEFAULT_ANISETTE_URL_V3.into(),
            directory.clone(),
            "0".into(),
        )
    };
    let first = provider().get_authentication_headers().await.unwrap();
    let second = provider().get_authentication_headers().await.unwrap();
    for key in ["X-Mme-Device-Id", "X-Apple-I-MD-LU", "X-Apple-I-MD-M"] {
        assert!(first.get(key).is_some_and(|value| !value.is_empty()));
        assert!(
            first.get(key) == second.get(key),
            "persisted identity changed: {key}"
        );
    }
    assert!(
        second
            .get("X-Apple-I-MD")
            .is_some_and(|value| !value.is_empty())
    );
    std::fs::remove_dir_all(directory).unwrap();
}

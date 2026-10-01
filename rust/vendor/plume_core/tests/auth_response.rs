use plume_core::{
    Error,
    auth::account::{check_error, send_grandslam_request},
};
use reqwest::header::HeaderMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn auth_headers_replace_the_blocked_xcode_client_identifier() {
    let anisette = plume_core::auth::anisette_data::AnisetteData {
        base_headers: std::collections::HashMap::from([("X-Mme-Client-Info".into(),
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>".into())]),
        generated_at: std::time::SystemTime::now(),
        config: plume_core::AnisetteConfiguration::new(),
    };
    let headers = plume_core::auth::account::grandslam_headers(&anisette).unwrap();
    let client_info = headers["X-Mme-Client-Info"].to_str().unwrap();
    assert!(!client_info.contains("com.apple.dt.Xcode"));
    assert!(client_info.contains("com.apple.akd/1.0"));
    assert_eq!(headers["Accept"], "text/x-xml-plist");
    assert_eq!(headers["X-Apple-App-Info"], "com.apple.gs.xcode.auth");
    assert_eq!(headers["Connection"], "close");
}

fn authentication_reply() -> String {
    let status = plist::Dictionary::from_iter([
        ("ec", plist::Value::Integer((-20101).into())),
        (
            "em",
            plist::Value::String("Invalid account credentials".into()),
        ),
    ]);
    let response = plist::Dictionary::from_iter([("Status", plist::Value::Dictionary(status))]);
    let packet = plist::Dictionary::from_iter([("Response", plist::Value::Dictionary(response))]);
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &packet).unwrap();
    String::from_utf8(bytes).unwrap()
}

async fn server(
    replies: Vec<(u16, String)>,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    server_with_headers(
        replies
            .into_iter()
            .map(|(status, body)| (status, body, String::new()))
            .collect(),
    )
    .await
}

async fn server_with_headers(
    replies: Vec<(u16, String, String)>,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/grandslam", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        for (status, body, headers) in replies {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    if request.len() >= end + 4 + b"protocol-fixture".len() {
                        assert_eq!(&request[end + 4..], b"protocol-fixture");
                        break;
                    }
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, calls, task)
}

#[tokio::test]
async fn temporary_html_failure_recovers_with_the_same_packet() {
    let (url, calls, task) = server(vec![
        (503, "<html>temporary edge failure</html>".into()),
        (200, authentication_reply()),
    ])
    .await;
    let response = send_grandslam_request(
        &plume_core::client().unwrap(),
        &url,
        HeaderMap::new(),
        b"protocol-fixture".to_vec(),
        "SRP complete",
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        check_error(&response),
        Err(Error::AuthSrpWithMessage(-20101, _))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn html_failures_report_status_and_stage_without_exposing_the_body() {
    for (status, expected_calls) in [(503, 2), (429, 11), (200, 1)] {
        let body = "<html>private diagnostic content</html>";
        let (url, calls, task) = server(vec![(status, body.into()); expected_calls]).await;
        let error = send_grandslam_request(
            &plume_core::client().unwrap(),
            &url,
            HeaderMap::new(),
            b"protocol-fixture".to_vec(),
            "SRP init",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, Error::AuthResponse { http_code, message, .. } if *http_code == status && message.starts_with("SRP init:"))
        );
        assert!(!error.to_string().contains("private diagnostic content"));
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn proof_request_recovers_from_429_without_restarting_srp() {
    let (url, calls, task) = server(vec![
        (429, "<html>Too Many Requests</html>".into()),
        (429, "<html>Too Many Requests</html>".into()),
        (200, authentication_reply()),
    ])
    .await;
    let started = std::time::Instant::now();
    let response = send_grandslam_request(
        &plume_core::client().unwrap(),
        &url,
        HeaderMap::new(),
        b"protocol-fixture".to_vec(),
        "SRP complete",
    )
    .await
    .unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(6));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(matches!(
        check_error(&response),
        Err(Error::AuthSrpWithMessage(-20101, _))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn retry_after_is_respected_and_long_cooldowns_are_returned_immediately() {
    for header in [
        "120".to_owned(),
        httpdate::fmt_http_date(std::time::SystemTime::now() + std::time::Duration::from_secs(120)),
    ] {
        let (url, calls, task) = server_with_headers(vec![(
            429,
            "<html>Too Many Requests</html>".into(),
            format!("Retry-After: {header}\r\n"),
        )])
        .await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            send_grandslam_request(
                &plume_core::client().unwrap(),
                &url,
                HeaderMap::new(),
                b"protocol-fixture".to_vec(),
                "SRP complete",
            ),
        )
        .await
        .expect("must not sleep through a long cooldown")
        .unwrap_err();
        assert!(error.to_string().contains("Wait at least"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.await.unwrap();
    }
    let (url, calls, task) = server_with_headers(vec![
        (
            429,
            "<html>Too Many Requests</html>".into(),
            "Retry-After: 3\r\n".into(),
        ),
        (200, authentication_reply(), String::new()),
    ])
    .await;
    let started = std::time::Instant::now();
    send_grandslam_request(
        &plume_core::client().unwrap(),
        &url,
        HeaderMap::new(),
        b"protocol-fixture".to_vec(),
        "SRP complete",
    )
    .await
    .unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.await.unwrap();
}

#[tokio::test]
async fn credential_error_is_returned_without_a_retry() {
    let (url, calls, task) = server(vec![(200, authentication_reply())]).await;
    let response = send_grandslam_request(
        &plume_core::client().unwrap(),
        &url,
        HeaderMap::new(),
        b"protocol-fixture".to_vec(),
        "SRP init",
    )
    .await
    .unwrap();
    assert!(matches!(
        check_error(&response),
        Err(Error::AuthSrpWithMessage(-20101, _))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.await.unwrap();
}

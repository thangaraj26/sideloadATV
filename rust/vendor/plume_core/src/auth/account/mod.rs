mod login;
mod token;
mod two_factor_auth;

use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use reqwest::Response;
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
};
use sha2::Sha256;

use crate::Error;
use crate::auth::anisette_data::AnisetteData;

/// Match the AuthKit request headers used by current GrandSlam clients.
pub fn grandslam_headers(anisette: &AnisetteData) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
    headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
    headers.insert("Connection", HeaderValue::from_static("close"));
    headers.insert(
        "User-Agent",
        HeaderValue::from_static("akd/1.0 CFNetwork/808.1.4"),
    );
    headers.insert(
        "X-Apple-App-Info",
        HeaderValue::from_static("com.apple.gs.xcode.auth"),
    );
    headers.insert(
        "X-Xcode-Version",
        HeaderValue::from_static("27.0 (27A5218g)"),
    );
    headers.insert(
        "X-Mme-Client-Info",
        HeaderValue::from_str(&anisette.get_header("x-mme-client-info")?).map_err(|_| {
            Error::AuthSrpWithMessage(0, "Invalid AuthKit client-info header".into())
        })?,
    );
    Ok(headers)
}

/// Recover intermittent Apple edge failures without restarting the SRP exchange.
/// Keep the packet unchanged and never retry an authentication plist error.
pub async fn send_grandslam_request(
    client: &Client,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    operation: &str,
) -> Result<plist::Dictionary, Error> {
    let mut service_retries = 0;
    let mut rate_limit_retries = 0;
    loop {
        let response = client
            .post(url)
            .headers(headers.clone())
            .body(body.clone())
            .send()
            .await?;
        let delay = if response.status().as_u16() == 429 && rate_limit_retries < 10 {
            // Match the reference client's ten retries, spaced to avoid a tight
            // loop while honoring Apple when it requests a longer delay.
            let delay =
                retry_after(&response).unwrap_or_else(|| std::time::Duration::from_millis(500));
            if delay <= std::time::Duration::from_secs(30) {
                rate_limit_retries += 1;
                Some(delay)
            } else {
                // A long cooldown belongs in the error, not a hidden sleep.
                None
            }
        } else if service_retries == 0 && matches!(response.status().as_u16(), 502 | 503 | 504) {
            service_retries += 1;
            Some(std::time::Duration::from_millis(500))
        } else {
            None
        };
        if let Some(delay) = delay {
            // Drop the failed response before opening another connection.
            drop(response);
            tokio::time::sleep(delay).await;
            continue;
        }
        return parse_response(Ok(response))
            .await
            .map_err(|error| match error {
                Error::AuthResponse {
                    url,
                    http_code,
                    message,
                } => Error::AuthResponse {
                    url,
                    http_code,
                    message: format!("{}: {}", operation, message),
                },
                other => other,
            });
    }
}

fn retry_after(response: &Response) -> Option<std::time::Duration> {
    let value = response.headers().get("Retry-After")?.to_str().ok()?;
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(std::time::Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value).ok().map(|date| {
        date.duration_since(std::time::SystemTime::now())
            .unwrap_or_default()
    })
}

pub async fn parse_response(
    res: Result<Response, reqwest::Error>,
) -> Result<plist::Dictionary, Error> {
    let res = res?;
    let http_code = res.status().as_u16();
    let url = res.url().to_string();
    let retry_delay = retry_after(&res);
    let bytes = res.bytes().await?;
    // Never include the raw body: successful responses contain session secrets.
    let invalid_response = || Error::AuthResponse {
        url: url.clone(),
        http_code,
        message: if http_code == 429 {
            match retry_delay {
                Some(delay) => format!("Apple limited authentication requests. Wait at least {} seconds before trying again.", delay.as_secs()),
            None => "Apple is still rejecting authentication requests with HTTP 429 after 10 retries. Try again later.".into(),
            }
        } else if http_code >= 500 {
            "Apple returned an unavailable-service page instead of an authentication response."
                .into()
        } else {
            "Apple returned an unexpected response instead of an authentication plist.".into()
        },
    };
    let res: plist::Dictionary = plist::from_bytes(&bytes).map_err(|_| invalid_response())?;
    res.get("Response")
        .and_then(plist::Value::as_dictionary)
        .cloned()
        .ok_or_else(invalid_response)
}

pub fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
    let res = match res.get("Status") {
        Some(plist::Value::Dictionary(d)) => d,
        _ => &res,
    };

    if res.get("ec").unwrap().as_signed_integer().unwrap() != 0 {
        return Err(Error::AuthSrpWithMessage(
            res.get("ec").unwrap().as_signed_integer().unwrap().into(),
            res.get("em").unwrap().as_string().unwrap().to_owned(),
        ));
    }

    Ok(())
}

pub fn decrypt_cbc(key: &[u8], data: &[u8]) -> Vec<u8> {
    let extra_data_key = create_session_key(key, "extra data key:");
    let extra_data_iv = create_session_key(key, "extra data iv:");
    let extra_data_iv = &extra_data_iv[..16];

    cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
        .unwrap()
        .decrypt_padded_vec_mut::<Pkcs7>(&data)
        .unwrap()
}

pub fn create_session_key(key: &[u8], name: &str) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(key)
        .unwrap()
        .chain_update(name.as_bytes())
        .finalize()
        .into_bytes()
        .to_vec()
}

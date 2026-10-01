// Implementing the SideStore Anisette v3 protocol

use std::{collections::HashMap, fs, io::Cursor, path::PathBuf, time::Duration};

use async_trait::async_trait;
use base64::engine::general_purpose;
use base64::Engine;
use chrono::{DateTime, SubsecRound, Utc};
use futures_util::{stream::StreamExt, SinkExt};
use log::debug;
use plist::{Data, Dictionary};
use rand::Rng;
use reqwest::{Client, ClientBuilder, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

use crate::{anisette_headers_provider::AnisetteHeadersProvider, AnisetteError};

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    s.try_into()
        .map_err(|_| serde::de::Error::custom("keychain identifier must be 16 bytes"))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, AnisetteError> {
    general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|_| protocol_error("invalid base64 provisioning data"))
}

fn protocol_error(message: &str) -> AnisetteError {
    AnisetteError::Anyhow(anyhow::anyhow!("Anisette v3: {}", message))
}

fn required_string<'a>(dict: &'a Dictionary, key: &str) -> Result<&'a str, AnisetteError> {
    dict.get(key)
        .and_then(plist::Value::as_string)
        .ok_or_else(|| protocol_error(&format!("missing or invalid {}", key)))
}

fn provisioning_response(bytes: &[u8]) -> Result<Dictionary, AnisetteError> {
    let value = plist::Value::from_reader(Cursor::new(bytes))?;
    let response = value
        .as_dictionary()
        .and_then(|d| d.get("Response"))
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| protocol_error("missing provisioning Response"))?;
    if let Some(status) = response.get("Status").and_then(plist::Value::as_dictionary) {
        if let Some(code) = status.get("ec").and_then(plist::Value::as_signed_integer) {
            if code != 0 {
                return Err(protocol_error(&format!(
                    "Apple provisioning error {}",
                    code
                )));
            }
        }
    }
    Ok(response.clone())
}

#[derive(Deserialize)]
struct AnisetteClientInfo {
    client_info: String,
    user_agent: String,
}

/// Messages sent by the anisette v3 provisioning server.
#[derive(Debug, Deserialize)]
#[serde(tag = "result")]
pub enum ProvisionInput {
    GiveIdentifier,
    GiveStartProvisioningData,
    GiveEndProvisioningData { cpim: String },
    ProvisioningSuccess { adi_pb: String },
    StartProvisioningError { message: String },
    EndProvisioningError { message: String },
    Timeout,
    InvalidIdentifier,
}

impl ProvisionInput {
    /// Preserve server failures instead of reporting them as JSON errors.
    pub fn parse(text: &str) -> Result<Self, AnisetteError> {
        let message: Self = serde_json::from_str(text)?;
        let (stage, detail) = match message {
            Self::StartProvisioningError { message } => ("StartProvisioningError", message),
            Self::EndProvisioningError { message } => ("EndProvisioningError", message),
            Self::Timeout => (
                "Timeout",
                "The server timed out waiting for provisioning data".into(),
            ),
            Self::InvalidIdentifier => (
                "InvalidIdentifier",
                "The server rejected the device identifier".into(),
            ),
            other => return Ok(other),
        };
        Err(AnisetteError::RemoteProvisioning {
            stage: stage.into(),
            message: detail,
        })
    }
}

impl AnisetteError {
    pub fn is_retryable_provisioning(&self) -> bool {
        use tokio_tungstenite::tungstenite::{error::ProtocolError, Error as WsError};
        match self {
            Self::RemoteProvisioning { stage, .. } => matches!(
                stage.as_str(),
                "StartProvisioningError" | "EndProvisioningError" | "Timeout"
            ),
            Self::WsError(
                WsError::ConnectionClosed
                | WsError::AlreadyClosed
                | WsError::Io(_)
                | WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake),
            ) => true,
            Self::ReqwestError(error) => {
                error.is_timeout()
                    || error.is_connect()
                    || error
                        .status()
                        .is_some_and(|status| status.is_server_error())
            }
            _ => false,
        }
    }
}

fn provisioning_timeout(message: &str) -> AnisetteError {
    AnisetteError::RemoteProvisioning {
        stage: "Timeout".into(),
        message: message.into(),
    }
}

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(
        serialize_with = "bin_serialize",
        deserialize_with = "bin_deserialize_16"
    )]
    keychain_identifier: [u8; 16],
    #[serde(
        serialize_with = "bin_serialize_opt",
        deserialize_with = "bin_deserialize_opt"
    )]
    adi_pb: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::rng().random::<[u8; 16]>(),
            adi_pb: None,
            server_url: None,
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct AnisetteClient {
    client_info: AnisetteClientInfo,
    url: String,
    http_client: Client,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String,
}

impl AnisetteData {
    pub fn get_headers(&self, serial: String) -> HashMap<String, String> {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        HashMap::from_iter(
            [
                (
                    "X-Apple-I-Client-Time".to_string(),
                    dt.format("%+").to_string().replace("+00:00", "Z"),
                ),
                ("X-Apple-I-SRL-NO".to_string(), serial),
                ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
                ("X-Apple-Locale".to_string(), "en_US".to_string()),
                ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
                ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
                (
                    "X-Mme-Device-Id".to_string(),
                    self.device_unique_identifier.clone(),
                ),
                ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
                ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
                (
                    "X-Mme-Client-Info".to_string(),
                    self.device_description.clone(),
                ),
            ]
            .into_iter(),
        )
    }
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        // Apple GSA uses Apple's root, which is absent from WebPKI's roots.
        .add_root_certificate(reqwest::Certificate::from_der(include_bytes!(
            "apple_root.der"
        ))?)
        .http1_title_case_headers()
        .timeout(Duration::from_secs(30))
        .build()?)
}

impl AnisetteClient {
    pub async fn new(url: String) -> Result<AnisetteClient, AnisetteError> {
        let path = format!("{}/v3/client_info", url);
        let http_client = make_reqwest()?;
        let client_info = http_client
            .get(path)
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteClientInfo>()
            .await?;
        Ok(AnisetteClient {
            client_info,
            url,
            http_client,
        })
    }

    fn build_apple_request(
        &self,
        state: &AnisetteState,
        builder: RequestBuilder,
    ) -> RequestBuilder {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        builder
            .header("X-Mme-Client-Info", &self.client_info.client_info)
            .header("User-Agent", &self.client_info.user_agent)
            .header("Content-Type", "text/x-xml-plist")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
            .header("X-Apple-I-TimeZone", "UTC")
            .header("X-Apple-Locale", "en_US")
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData, AnisetteError> {
        let path = format!("{}/v3/get_headers", self.url);

        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(
                state
                    .adi_pb
                    .as_ref()
                    .ok_or(AnisetteError::AnisetteNotProvisioned)?,
            ),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String,
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            },
        }

        let headers = self
            .http_client
            .post(path)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteHeaders>()
            .await?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } => {
                if message.contains("-45061") {
                    Err(AnisetteError::AnisetteNotProvisioned)
                } else {
                    Err(protocol_error(&format!(
                        "header generation failed: {}",
                        message
                    )))
                }
            }
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                device_description: self.client_info.client_info.clone(),
                local_user_id: encode_hex(&state.md_lu()),
                device_unique_identifier: state.device_id(),
            }),
        }
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        match self.provision_once(state).await {
            Err(error) if error.is_retryable_provisioning() => {
                // A failed server session must be restarted from the beginning.
                // Retry once while retaining the device identifier; never retry
                // Apple ID authentication or fall back to a shared v1 identity.
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.provision_once(state).await
            }
            result => result,
        }
    }

    async fn provision_once(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        debug!("Provisioning Anisette");
        // The lookup needs client-info and user-agent headers. A bare GET can
        // fail even though the endpoint is available.
        let lookup = self
            .build_apple_request(
                state,
                self.http_client
                    .get("https://gsa.apple.com/grandslam/GsService2/lookup"),
            )
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let lookup: plist::Value = plist::from_bytes(&lookup)?;
        let urls = lookup
            .as_dictionary()
            .and_then(|d| d.get("urls"))
            .and_then(plist::Value::as_dictionary)
            .ok_or_else(|| protocol_error("lookup is missing urls"))?;
        let start_provisioning_url = required_string(urls, "midStartProvisioning")?;
        let end_provisioning_url = required_string(urls, "midFinishProvisioning")?;
        debug!(
            "Using provisioning urls: {} and {}",
            start_provisioning_url, end_provisioning_url
        );

        let provision_ws_url =
            format!("{}/v3/provisioning_session", self.url).replace("https://", "wss://");
        let (mut connection, _) =
            tokio::time::timeout(Duration::from_secs(30), connect_async(&provision_ws_url))
                .await
                .map_err(|_| provisioning_timeout("provisioning connection timed out"))??;

        loop {
            let data = tokio::time::timeout(Duration::from_secs(30), connection.next())
                .await
                .map_err(|_| provisioning_timeout("provisioning response timed out"))?
                .ok_or(tokio_tungstenite::tungstenite::Error::ConnectionClosed)??;
            if data.is_text() {
                let txt = data.to_text().unwrap();
                let msg = ProvisionInput::parse(txt)?;
                match msg {
                    ProvisionInput::GiveIdentifier => {
                        #[derive(Serialize)]
                        struct Identifier {
                            identifier: String, // base64
                        }
                        let identifier = Identifier {
                            identifier: base64_encode(&state.keychain_identifier),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&identifier)?.into()))
                            .await?;
                    }
                    ProvisionInput::GiveStartProvisioningData => {
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::new(),
                        };
                        let resp = self
                            .build_apple_request(
                                state,
                                self.http_client.post(start_provisioning_url),
                            )
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?
                            .error_for_status()?;
                        let response = provisioning_response(&resp.bytes().await?)?;
                        let spim = required_string(&response, "spim")?;

                        debug!("GiveStartProvisioningData");
                        #[derive(Serialize)]
                        struct Spim {
                            spim: String, // base64
                        }
                        let spim = Spim {
                            spim: spim.to_string(),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&spim)?.into()))
                            .await?;
                    }
                    ProvisionInput::GiveEndProvisioningData { cpim } => {
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::from_iter([("cpim", cpim)].into_iter()),
                        };
                        let resp = self
                            .build_apple_request(state, self.http_client.post(end_provisioning_url))
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?
                            .error_for_status()?;
                        let response = provisioning_response(&resp.bytes().await?)?;

                        debug!("GiveEndProvisioningData");

                        #[derive(Serialize)]
                        struct EndProvisioning<'t> {
                            ptm: &'t str,
                            tk: &'t str,
                        }
                        let end_provisioning = EndProvisioning {
                            ptm: required_string(&response, "ptm")?,
                            tk: required_string(&response, "tk")?,
                        };
                        connection
                            .send(Message::Text(
                                serde_json::to_string(&end_provisioning)?.into(),
                            ))
                            .await?;
                    }
                    ProvisionInput::ProvisioningSuccess { adi_pb } => {
                        debug!("ProvisioningSuccess");
                        state.adi_pb = Some(base64_decode(&adi_pb)?);
                        // The provisioning data is complete. A server disconnect
                        // during the closing handshake must not discard it.
                        let _ = connection.close(None).await;
                        break;
                    }
                    // parse() returns these as structured errors.
                    ProvisionInput::StartProvisioningError { .. }
                    | ProvisionInput::EndProvisioningError { .. }
                    | ProvisionInput::Timeout
                    | ProvisionInput::InvalidIdentifier => unreachable!(),
                }
            } else if data.is_close() {
                return Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed.into());
            }
        }

        Ok(())
    }
}

pub struct RemoteAnisetteProviderV3 {
    client_url: String,
    fallback_urls: Vec<String>,
    client: Option<AnisetteClient>,
    pub state: Option<AnisetteState>,
    configuration_path: PathBuf,
    serial: String,
}

impl RemoteAnisetteProviderV3 {
    pub fn new(
        url: String,
        configuration_path: PathBuf,
        serial: String,
    ) -> RemoteAnisetteProviderV3 {
        RemoteAnisetteProviderV3 {
            fallback_urls: if url == crate::DEFAULT_ANISETTE_URL_V3 {
                // Also used by the current isideload client. Keep this list
                // fixed so a saved state cannot redirect requests arbitrarily.
                vec!["https://ani.stikstore.app".into()]
            } else {
                Vec::new()
            },
            client_url: url,
            client: None,
            state: None,
            configuration_path,
            serial,
        }
    }

    /// Explicitly supply alternate v3 servers for a custom deployment.
    pub fn with_fallback_urls(mut self, urls: Vec<String>) -> Self {
        self.fallback_urls = urls;
        self
    }

    async fn headers_from_server(
        &mut self,
        url: &str,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        if self.client.as_ref().is_none_or(|client| client.url != url) {
            self.client = Some(AnisetteClient::new(url.to_string()).await?);
        }
        let client = self.client.as_ref().unwrap();
        let state = self.state.as_mut().unwrap();
        let config_path = self.configuration_path.join("state.plist");
        if !state.is_provisioned() {
            client.provision(state).await?;
            state.server_url = Some(url.into());
            plist::to_file_xml(&config_path, &*state)?;
        }
        let data = match client.get_headers(state).await {
            Ok(data) => data,
            Err(AnisetteError::AnisetteNotProvisioned) => {
                state.adi_pb = None;
                client.provision(state).await?;
                state.server_url = Some(url.into());
                plist::to_file_xml(&config_path, &*state)?;
                client.get_headers(state).await?
            }
            Err(error) => return Err(error),
        };
        state.server_url = Some(url.into());
        plist::to_file_xml(&config_path, state)?;
        Ok(data.get_headers(self.serial.clone()))
    }
}

#[async_trait]
impl AnisetteHeadersProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(
        &mut self,
        _skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        fs::create_dir_all(&self.configuration_path)?;

        let config_path = self.configuration_path.join("state.plist");
        if self.state.is_none() {
            self.state = Some(if let Ok(text) = plist::from_file(&config_path) {
                text
            } else {
                AnisetteState::new()
            });
        }

        let mut urls = vec![self.client_url.clone()];
        for url in &self.fallback_urls {
            if !urls.contains(url) {
                urls.push(url.clone());
            }
        }
        if let Some(saved_url) = self
            .state
            .as_ref()
            .and_then(|state| state.server_url.as_ref())
        {
            if let Some(index) = urls.iter().position(|url| url == saved_url) {
                let saved = urls.remove(index);
                urls.insert(0, saved);
            }
        }
        let mut last_error = None;
        for url in urls {
            match self.headers_from_server(&url).await {
                Ok(headers) => return Ok(headers),
                Err(error) if error.is_retryable_provisioning() => {
                    debug!(
                        "Anisette server {} failed; trying next configured server",
                        url
                    );
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or(AnisetteError::AnisetteNotProvisioned))
    }
}

#[cfg(test)]
mod tests {
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::remote_anisette_v3::RemoteAnisetteProviderV3;
    use crate::{AnisetteError, DEFAULT_ANISETTE_URL_V3};
    use log::info;

    #[tokio::test]
    async fn fetch_anisette_remote_v3() -> Result<(), AnisetteError> {
        crate::tests::init_logger();

        let mut provider = RemoteAnisetteProviderV3::new(
            DEFAULT_ANISETTE_URL_V3.to_string(),
            "anisette_test".into(),
            "0".to_string(),
        );
        info!(
            "Remote headers: {:?}",
            (&mut provider as &mut dyn AnisetteHeadersProvider)
                .get_authentication_headers()
                .await?
        );
        Ok(())
    }
}

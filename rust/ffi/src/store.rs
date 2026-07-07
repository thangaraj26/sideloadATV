use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::signing::{SigningError, SigningSession};

/// Locally-remembered metadata about an app we've signed for a specific
/// Apple TV, so "refresh" (re-sign to reset the free-account 7-day
/// provisioning profile clock) doesn't require re-picking the IPA file, and
/// so the installed-apps list can show a remaining-days countdown. This is
/// purely local bookkeeping -- Apple's developer portal is the source of
/// truth for whether a profile is actually still valid.
#[derive(uniffi::Record, Debug, Clone, Serialize, Deserialize)]
pub struct StoredAppInfo {
    pub bundle_identifier: String,
    pub app_name: String,
    pub file_name: String,
    pub device_udid: String,
    pub device_name: String,
    pub team_id: String,
    /// Unix seconds.
    pub signed_at: i64,
    /// Unix seconds -- when the provisioning profile we last signed with expires.
    pub expires_at: i64,
}

fn app_dir(data_dir: &str, bundle_identifier: &str) -> PathBuf {
    // Bundle identifiers are dot-separated alnum/hyphen by Apple's own rules,
    // so no filesystem-unsafe characters are expected, but sanitize anyway
    // since this ultimately comes from an IPA someone else built.
    let safe = bundle_identifier.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-', "_");
    Path::new(data_dir).join("stored_apps").join(safe)
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) async fn save_stored_app(
    data_dir: &str,
    info: &StoredAppInfo,
    original_ipa_bytes: &[u8],
) -> Result<(), SigningError> {
    let dir = app_dir(data_dir, &info.bundle_identifier);
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(dir.join("meta.json"), serde_json::to_vec(info)?).await?;
    tokio::fs::write(dir.join("original.ipa"), original_ipa_bytes).await?;
    Ok(())
}

async fn load_stored_app(data_dir: &str, bundle_identifier: &str) -> Result<(StoredAppInfo, Vec<u8>), SigningError> {
    let dir = app_dir(data_dir, bundle_identifier);
    let meta_bytes = tokio::fs::read(dir.join("meta.json"))
        .await
        .map_err(|e| SigningError::Message(format!("no stored app for {bundle_identifier}: {e}")))?;
    let meta: StoredAppInfo = serde_json::from_slice(&meta_bytes)?;
    let ipa_bytes = tokio::fs::read(dir.join("original.ipa")).await?;
    Ok((meta, ipa_bytes))
}

/// Apps previously signed+installed through this app, with their last-known
/// provisioning profile expiry. Used to enrich the on-device installed-apps
/// list (which has no notion of expiry) and to power the "Refresh" action.
#[uniffi::export(async_runtime = "tokio")]
pub async fn list_stored_apps(data_dir: String) -> Result<Vec<StoredAppInfo>, SigningError> {
    let dir = Path::new(&data_dir).join("stored_apps");
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        let meta_path = entry.path().join("meta.json");
        if let Ok(bytes) = tokio::fs::read(&meta_path).await {
            if let Ok(info) = serde_json::from_slice::<StoredAppInfo>(&bytes) {
                out.push(info);
            }
        }
    }
    Ok(out)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn remove_stored_app(data_dir: String, bundle_identifier: String) -> Result<(), SigningError> {
    let dir = app_dir(&data_dir, &bundle_identifier);
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Re-signs a previously-installed app from its locally-stored original IPA,
/// requesting a fresh provisioning profile (and so a fresh 7-day expiry)
/// without the user having to re-pick the file. The result is ready for
/// `TunnelSession::install_ipa`, same as a fresh `SigningSession::sign_ipa` call.
#[uniffi::export(async_runtime = "tokio")]
pub async fn refresh_stored_app(
    signing: std::sync::Arc<SigningSession>,
    data_dir: String,
    cache_dir: String,
    bundle_identifier: String,
) -> Result<Vec<u8>, SigningError> {
    let (meta, ipa_bytes) = load_stored_app(&data_dir, &bundle_identifier).await?;
    signing
        .sign_ipa(ipa_bytes, meta.team_id, meta.device_udid, meta.device_name, data_dir, cache_dir)
        .await
}

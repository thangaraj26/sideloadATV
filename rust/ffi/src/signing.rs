use std::path::PathBuf;
use std::sync::Arc;

use plume_core::CertificateIdentity;
use plume_core::developer::DeveloperSession;
use plume_core::developer::qh::devices::DeviceType;
use plume_utils::{Package, PlistInfoTrait, Signer, SignerMode, SignerOptions};

use crate::auth::GrandslamSession;
use crate::store::{self, StoredAppInfo};

/// Metadata for one registered App ID slot on the Apple Developer portal.
#[derive(uniffi::Record, Debug, Clone)]
pub struct AppIdInfo {
    /// Opaque portal identifier, e.g. "A1B2C3D4E5" – pass back to `delete_registered_app_id`.
    pub id: String,
    pub name: String,
    pub identifier: String,
}

#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum SigningError {
    #[error("{0}")]
    Message(String),
    /// Returned when a free Apple ID already has 3 App IDs registered and the
    /// IPA being installed requires a new slot. The caller should ask the user
    /// to remove one of the `existing_app_ids`, call `delete_registered_app_id`,
    /// then retry `sign_ipa`.
    #[error("Free accounts support 3 apps. Remove one to make room.")]
    AppIdLimitReached { existing_app_ids: Vec<AppIdInfo> },
}

impl From<plume_core::Error> for SigningError {
    fn from(e: plume_core::Error) -> Self {
        SigningError::Message(e.to_string())
    }
}

impl From<plume_utils::Error> for SigningError {
    fn from(e: plume_utils::Error) -> Self {
        SigningError::Message(e.to_string())
    }
}

impl From<crate::auth::GsError> for SigningError {
    fn from(e: crate::auth::GsError) -> Self {
        SigningError::Message(e.to_string())
    }
}

impl From<std::io::Error> for SigningError {
    fn from(e: std::io::Error) -> Self {
        SigningError::Message(e.to_string())
    }
}

impl From<serde_json::Error> for SigningError {
    fn from(e: serde_json::Error) -> Self {
        SigningError::Message(e.to_string())
    }
}

/// One Apple Developer team the logged-in Apple ID belongs to. Free accounts
/// normally have exactly one (their personal team); paid accounts can have more.
#[derive(uniffi::Record)]
pub struct TeamInfo {
    pub id: String,
    pub name: String,
}

/// A Developer-API session built from an already-logged-in `GrandslamSession`,
/// used to certify + provision + codesign an IPA for a specific Apple TV before
/// `TunnelSession::install_ipa` transfers it.
#[derive(uniffi::Object)]
pub struct SigningSession {
    developer: DeveloperSession,
}

#[uniffi::export(async_runtime = "tokio")]
impl SigningSession {
    // Named (not `new`) deliberately: uniffi 0.28's Kotlin backend silently
    // skips generating any wrapper at all for an async *primary* (`new`)
    // constructor -- async constructors only get a companion-object factory
    // function when they're a named/"alternate" constructor (matches
    // `TunnelSession::connect`, which uses the same pattern).
    #[uniffi::constructor]
    pub async fn create(grandslam: Arc<GrandslamSession>) -> Result<Arc<Self>, SigningError> {
        let account = grandslam.cloned_account().await?;
        let developer = DeveloperSession::using_account(account).await?;
        Ok(Arc::new(Self { developer }))
    }

    /// Rebuilds a session from a previously-exported `StoredAccount`
    /// (`GrandslamSession::export_account`), skipping the SRP login entirely.
    /// Also serves as a validity check for the stored credentials: this
    /// fails (and the caller should fall back to a fresh login) if Apple has
    /// since expired the `xcode_gs_token`, since the underlying
    /// `DeveloperSession::new` self-tests by listing teams.
    #[uniffi::constructor]
    pub async fn from_stored(
        data_dir: String,
        adsid: String,
        xcode_gs_token: String,
    ) -> Result<Arc<Self>, SigningError> {
        let config = plume_core::AnisetteConfiguration::new()
            .set_configuration_path(data_dir.into())
            .set_anisette_url("https://ani.sidestore.io".to_string());
        let developer = DeveloperSession::new(adsid, xcode_gs_token, config).await?;
        Ok(Arc::new(Self { developer }))
    }

    /// Returns all App IDs registered under the given team. Use this to let the
    /// user see and delete slots before hitting the 10/7-day limit.
    pub async fn list_registered_app_ids(
        &self,
        team_id: String,
    ) -> Result<Vec<AppIdInfo>, SigningError> {
        let response = self.developer.qh_list_app_ids(&team_id).await?;
        Ok(response
            .app_ids
            .into_iter()
            .map(|a| AppIdInfo { id: a.app_id_id, name: a.name, identifier: a.identifier })
            .collect())
    }

    /// Removes one registered App ID slot from the Apple Developer portal.
    /// Use this after receiving `SigningError::AppIdLimitReached` to free a slot,
    /// then call `sign_ipa` again.
    pub async fn delete_registered_app_id(
        &self,
        team_id: String,
        app_id_id: String,
    ) -> Result<(), SigningError> {
        self.developer.qh_delete_app_id(&team_id, &app_id_id).await?;
        Ok(())
    }

    /// Teams this Apple ID can sign under. Only prompt the user to pick one if
    /// this returns more than one entry.
    pub async fn list_teams(&self) -> Result<Vec<TeamInfo>, SigningError> {
        let response = self.developer.qh_list_teams().await?;
        Ok(response
            .teams
            .into_iter()
            .map(|t| TeamInfo { id: t.team_id, name: t.name })
            .collect())
    }

    /// Signs the IPA at `ipa_path` for the Apple TV identified by `device_udid`
    /// and returns the path to the signed IPA (inside `cache_dir`), ready for
    /// `TunnelSession::install_ipa`. The caller is responsible for deleting the
    /// returned file after the install completes.
    ///
    /// Accepts a file path rather than bytes so that large IPAs (e.g. 800 MB+
    /// emulators) never have to be loaded into the JVM heap or passed across
    /// the JNI boundary.
    ///
    /// `data_dir` must be a persistent, app-private directory (e.g. Android's
    /// `filesDir`) -- the signing certificate's private key is cached there,
    /// keyed by team id, so repeat sign calls reuse the same certificate
    /// instead of requesting (and, on free accounts, potentially revoking) a
    /// new one every time. `cache_dir` may be a volatile scratch directory
    /// (e.g. `cacheDir`); it only holds the extracted bundle and the re-zipped
    /// IPA for the duration of this call.
    pub async fn sign_ipa(
        &self,
        ipa_path: String,
        team_id: String,
        device_udid: String,
        device_name: String,
        data_dir: String,
        cache_dir: String,
    ) -> Result<String, SigningError> {
        // plume_utils' Package/archive helpers stage work under
        // std::env::temp_dir(), which reads $TMPDIR at call time and falls back
        // to "/tmp" -- a path that doesn't exist (and wouldn't be writable) in
        // an Android app sandbox. Point it at the caller-supplied cache dir
        // before touching any of them.
        unsafe {
            std::env::set_var("TMPDIR", &cache_dir);
        }

        let ipa_path = PathBuf::from(&ipa_path);
        let package = Package::new(ipa_path.clone())?;
        let bundle = package.get_package_bundle()?;

        self.developer
            .qh_ensure_device(&team_id, &device_name, &device_udid, Some(DeviceType::Tvos))
            .await?;

        let cert = CertificateIdentity::new_with_session(
            &self.developer,
            PathBuf::from(&data_dir),
            Some("sideloadATV".to_string()),
            &team_id,
        )
        .await?;

        let mut signer = Signer::new(
            Some(cert),
            SignerOptions {
                mode: SignerMode::Pem,
                // Always request a tvOS provisioning profile. Without this,
                // register_bundle reads DTPlatformName from the IPA — but iOS
                // IPAs (or those with no DTPlatformName) would request an iOS
                // profile. Apple returns error 8220 because the only registered
                // device is the Apple TV (tvOS), not an iPhone/iPad.
                device_type: Some(DeviceType::Tvos),
                ..Default::default()
            },
        );

        let team_id_opt = Some(team_id.clone());
        signer.modify_bundle(&bundle, &team_id_opt).await?;

        // Read the final bundle id after modify_bundle may have suffixed the team id.
        let final_bundle_id = bundle.get_bundle_identifier().unwrap_or_default();

        // Check whether Apple already has an App ID for this bundle identifier.
        // If it does, register_bundle reuses it (no creation slot consumed).
        // If it doesn't, a new slot is needed — and if the 7-day window is full
        // Apple returns error 9120, which we catch below with a clear message.
        //
        // Use the v1 API (limit=1000) instead of QH which has no page-size param
        // and returns a small default set — causing false "needs new slot" errors
        // for App IDs that are actually registered but not returned by QH.
        let already_on_portal = self.developer
            .v1_get_app_id(&team_id, &final_bundle_id)
            .await
            .ok()
            .flatten()
            .is_some();
        let portal_ids = self.developer.qh_list_app_ids(&team_id).await?;

        if let Err(e) = signer.register_bundle(&bundle, &self.developer, &team_id, false).await {
            let msg = e.to_string();
            if msg.contains("9120") {
                let active = portal_ids.app_ids.len();
                if already_on_portal {
                    // App ID exists but Apple still returned 9120 — unexpected,
                    // possibly a transient server error. Tell the user to retry.
                    return Err(SigningError::Message(format!(
                        "Apple returned a rate-limit error (9120) for '{final_bundle_id}' even though \
                         the App ID already exists. This is a transient Apple server issue — please try again in a few minutes."
                    )));
                } else {
                    return Err(SigningError::Message(format!(
                        "'{final_bundle_id}' needs a new App ID slot on Apple's portal, but the \
                         7-day creation limit (10 IDs max) is full. \
                         You currently have {active} active App ID(s) — deleting them won't help, \
                         the creation window must elapse. \
                         Try again in a day or two as older slots age out, or check 'Manage App IDs' for what's registered."
                    )));
                }
            }
            return Err(e.into());
        }
        signer.sign_bundle(&bundle).await?;

        let signed_path = package.get_archive_based_on_path(bundle.bundle_dir())?;

        // Best-effort: remember this app + its provisioning profile expiry so
        // "refresh" (re-sign without re-picking the file) and the
        // remaining-days countdown in the UI both work. Failure here
        // shouldn't fail the signing operation the caller actually asked
        // for -- it just means refresh/expiry tracking won't be available
        // for this particular app until it's signed again successfully.
        //
        // This MUST run before `remove_package_stage()`: `get_bundle_identifier`
        // and `get_bundle_name` read the extracted bundle's on-disk Info.plist,
        // and removing the stage deletes it (which previously left every app
        // showing "Expiry unknown" with no Refresh button).
        if let Some(bundle_identifier) = bundle.get_bundle_identifier() {
            if let Err(e) = self
                .remember_stored_app(&bundle, &bundle_identifier, &team_id, &device_udid, &device_name, &data_dir, &ipa_path.to_string_lossy())
                .await
            {
                eprintln!("sideloadATV: failed to persist stored-app metadata for {bundle_identifier}: {e}");
            }
        }

        package.remove_package_stage();

        Ok(signed_path.to_string_lossy().into_owned())
    }
}

impl SigningSession {
    /// See the comment at its call site in `sign_ipa`.
    async fn remember_stored_app(
        &self,
        bundle: &plume_utils::Bundle,
        bundle_identifier: &str,
        team_id: &str,
        device_udid: &str,
        device_name: &str,
        data_dir: &str,
        original_ipa_path: &str,
    ) -> Result<(), SigningError> {
        let app_name = bundle.get_bundle_name().unwrap_or_else(|| bundle_identifier.to_string());

        let app_id = self
            .developer
            .qh_get_app_id(&team_id.to_string(), &bundle_identifier.to_string())
            .await?
            .ok_or_else(|| SigningError::Message("app id not found right after registering it".into()))?;
        let profile = self
            .developer
            .qh_get_profile(&team_id.to_string(), &app_id.app_id_id, Some(DeviceType::Tvos))
            .await?;
        let expires_at = std::time::SystemTime::from(profile.provisioning_profile.date_expire)
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let info = StoredAppInfo {
            bundle_identifier: bundle_identifier.to_string(),
            app_name,
            file_name: format!("{bundle_identifier}.ipa"),
            device_udid: device_udid.to_string(),
            device_name: device_name.to_string(),
            team_id: team_id.to_string(),
            signed_at: store::unix_now(),
            expires_at,
        };
        store::save_stored_app(data_dir, &info, original_ipa_path).await
    }
}


use plume_core::AnisetteConfiguration;
use plume_core::auth::{Account, LoginState as CoreLoginState, VerifyBody};
use tokio::sync::Mutex;

/// Mirrors `plume_core::auth::LoginState` for the FFI boundary -- kept as a
/// separate type so the vendored upstream crate doesn't need uniffi derives.
/// `NeedsSmsVerification`'s `VerifyBody` payload is intentionally dropped here;
/// `GrandslamSession` remembers it internally and `verify_sms_2fa` reuses it,
/// so Kotlin only ever deals with plain state + a code string.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum GsLoginState {
    LoggedIn,
    NeedsDevice2fa,
    Needs2faVerification,
    NeedsSms2fa,
    NeedsSmsVerification,
    NeedsExtraStep { step: String },
    NeedsLogin,
}

#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum GsError {
    #[error("{0}")]
    Message(String),
}

impl From<plume_core::Error> for GsError {
    fn from(e: plume_core::Error) -> Self {
        GsError::Message(e.to_string())
    }
}

#[derive(Default)]
struct SessionState {
    account: Option<Account>,
    pending_sms: Option<VerifyBody>,
}

impl SessionState {
    fn account_mut(&mut self) -> Result<&mut Account, GsError> {
        self.account
            .as_mut()
            .ok_or_else(|| GsError::Message("not logged in yet: call login_email_pass first".into()))
    }
}

fn map_state(state: CoreLoginState, pending: &mut Option<VerifyBody>) -> GsLoginState {
    match state {
        CoreLoginState::LoggedIn => GsLoginState::LoggedIn,
        CoreLoginState::NeedsDevice2FA => GsLoginState::NeedsDevice2fa,
        CoreLoginState::Needs2FAVerification => GsLoginState::Needs2faVerification,
        CoreLoginState::NeedsSMS2FA => GsLoginState::NeedsSms2fa,
        CoreLoginState::NeedsSMS2FAVerification(body) => {
            *pending = Some(body);
            GsLoginState::NeedsSmsVerification
        }
        CoreLoginState::NeedsExtraStep(step) => GsLoginState::NeedsExtraStep { step },
        CoreLoginState::NeedsLogin => GsLoginState::NeedsLogin,
    }
}

/// One in-progress (or completed) Apple ID GrandSlam login. Create one per
/// login attempt; `data_dir` should be the app's private files directory
/// (anisette provisioning caches a device identifier there).
#[derive(uniffi::Object)]
pub struct GrandslamSession {
    state: Mutex<SessionState>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrandslamSession {
    #[uniffi::constructor]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { state: Mutex::new(SessionState::default()) })
    }

    /// Starts (or restarts, after a completed 2FA challenge) the SRP login.
    pub async fn login_email_pass(
        &self,
        data_dir: String,
        username: String,
        password: String,
    ) -> Result<GsLoginState, GsError> {
        let mut guard = self.state.lock().await;

        if guard.account.is_none() {
            let config = AnisetteConfiguration::new().set_configuration_path(data_dir.into());
            let account = Account::new(config).await?;
            guard.account = Some(account);
        }

        let core_state = guard.account_mut()?.login_email_pass(&username, &password).await?;
        Ok(map_state(core_state, &mut guard.pending_sms))
    }

    /// Requests a 2FA push to the user's trusted Apple devices.
    pub async fn send_2fa_to_devices(&self) -> Result<GsLoginState, GsError> {
        let mut guard = self.state.lock().await;
        let core_state = guard.account_mut()?.send_2fa_to_devices().await?;
        Ok(map_state(core_state, &mut guard.pending_sms))
    }

    /// Verifies the 6-digit code from a trusted-device push.
    pub async fn verify_2fa(&self, code: String) -> Result<GsLoginState, GsError> {
        let mut guard = self.state.lock().await;
        let core_state = guard.account_mut()?.verify_2fa(code).await?;
        Ok(map_state(core_state, &mut guard.pending_sms))
    }

    /// Requests an SMS code be sent to the given trusted phone number id
    /// (see `trusted_phone_ids` for the available ids).
    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<GsLoginState, GsError> {
        let mut guard = self.state.lock().await;
        let core_state = guard.account_mut()?.send_sms_2fa_to_devices(phone_id).await?;
        Ok(map_state(core_state, &mut guard.pending_sms))
    }

    /// Verifies the code from an SMS challenge (must follow `send_sms_2fa_to_devices`).
    pub async fn verify_sms_2fa(&self, code: String) -> Result<GsLoginState, GsError> {
        let mut guard = self.state.lock().await;
        let body = guard
            .pending_sms
            .clone()
            .ok_or_else(|| GsError::Message("no pending SMS challenge".into()))?;
        let core_state = guard.account_mut()?.verify_sms_2fa(code, body).await?;
        Ok(map_state(core_state, &mut guard.pending_sms))
    }

    /// Trusted phone numbers available for SMS 2FA, as "id:last two digits" pairs.
    pub async fn trusted_phone_ids(&self) -> Result<Vec<String>, GsError> {
        let guard = self.state.lock().await;
        let account = guard
            .account
            .as_ref()
            .ok_or_else(|| GsError::Message("not logged in yet".into()))?;
        let extras = account.get_auth_extras().await?;
        Ok(extras
            .trusted_phone_numbers
            .into_iter()
            .map(|p| format!("{}:{}", p.id, p.last_two_digits))
            .collect())
    }

    /// The Apple ID's first/last name, once logged in.
    pub async fn display_name(&self) -> Result<String, GsError> {
        let guard = self.state.lock().await;
        let account = guard
            .account
            .as_ref()
            .ok_or_else(|| GsError::Message("not logged in yet".into()))?;
        let (first, last) = account.get_name();
        Ok(format!("{first} {last}"))
    }

    /// Extracts the durable credentials (Apple's `adsid` + a long-lived
    /// `com.apple.gs.xcode.auth` app token) needed to rebuild a working
    /// `SigningSession` later via `SigningSession::from_stored`, without
    /// redoing the SRP login. These -- not the full GrandSlam session -- are
    /// what should be persisted across app restarts; the caller is
    /// responsible for storing them securely (e.g. an Android EncryptedFile).
    pub async fn export_account(&self) -> Result<StoredAccount, GsError> {
        let guard = self.state.lock().await;
        let account = guard
            .account
            .as_ref()
            .ok_or_else(|| GsError::Message("not logged in yet".into()))?;
        let spd = account
            .spd
            .as_ref()
            .ok_or_else(|| GsError::Message("not logged in yet".into()))?;
        let email = spd
            .get("appleId")
            .and_then(|v| v.as_string())
            .unwrap_or_default()
            .to_string();
        let adsid = spd
            .get("adsid")
            .and_then(|v| v.as_string())
            .ok_or_else(|| GsError::Message("session missing adsid".into()))?
            .to_string();
        let (first_name, _) = account.get_name();
        let xcode_gs_token = account.get_app_token("com.apple.gs.xcode.auth").await?.auth_token;

        Ok(StoredAccount { email, first_name, adsid, xcode_gs_token })
    }
}

/// Durable Apple ID credentials safe to persist to disk (encrypted) so the
/// user doesn't have to re-enter their password on every app launch. Does
/// NOT contain the password itself -- `adsid` + `xcode_gs_token` are enough
/// to rebuild a `SigningSession` (see `SigningSession::from_stored`), but
/// notably NOT enough to rebuild a `GrandslamSession` for e.g. re-pairing;
/// if these tokens expire, the user has to log in again from scratch.
#[derive(uniffi::Record, Debug, Clone)]
pub struct StoredAccount {
    pub email: String,
    pub first_name: String,
    pub adsid: String,
    pub xcode_gs_token: String,
}

impl GrandslamSession {
    /// Cheap clone of the logged-in `Account` (its fields are `Arc`/`Client`-backed)
    /// for `SigningSession` to build a `DeveloperSession` from -- kept crate-private
    /// so Kotlin never sees the raw plume_core account type.
    pub(crate) async fn cloned_account(&self) -> Result<plume_core::auth::Account, GsError> {
        let guard = self.state.lock().await;
        guard
            .account
            .clone()
            .ok_or_else(|| GsError::Message("not logged in yet: call login_email_pass first".into()))
    }
}

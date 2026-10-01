use num_bigint::BigUint;
use omnisette::AnisetteConfiguration;
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::utils::compute_k;

use crate::Error;

use crate::auth::account::{check_error, grandslam_headers, send_grandslam_request};
use crate::auth::anisette_data::AnisetteData;
use crate::auth::{
    Account, ChallengeRequest, ChallengeRequestBody, GSA_ENDPOINT, InitRequest, InitRequestBody,
    LoginState, RequestHeader,
};

#[macro_export]
macro_rules! plist_get_string {
    ($base:expr, $( $path:literal )+, $final_key:literal) => {{
        let mut current_val = $base;
        $(
            current_val = current_val
                .get($path)
                .expect(concat!("Missing dictionary key: ", $path))
                .as_dictionary()
                .expect(concat!("Key value is not a dictionary: ", $path));
        )+
        current_val
            .get($final_key)
            .expect(concat!("Missing string key: ", $final_key))
            .as_string()
            .expect(concat!("Value is not a string: ", $final_key))
            .to_string()
    }};

    ($base:expr, $key:literal) => {{
        $base
            .get($key)
            .expect(concat!("Missing key: ", $key))
            .as_string()
            .expect(concat!("Value is not a string: ", $key))
            .to_string()
    }};
}

/// Left-pads `bytes` with zeroes to `width`, leaving it unchanged if already
/// that long or longer. Apple's GSA SRP variant (like RFC 5054's `u`) hashes
/// the public ephemerals as fixed-width, N-sized big-endian integers, not
/// their minimal-length big-endian representation.
fn pad_left(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; width - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

impl Account {
    pub async fn login(
        appleid_closure: impl Fn() -> Result<(String, String), String>,
        tfa_closure: impl Fn() -> Result<String, String>,
        config: AnisetteConfiguration,
    ) -> Result<Account, Error> {
        let anisette = AnisetteData::new(config).await?;
        Account::login_with_anisette(appleid_closure, tfa_closure, anisette).await
    }

    pub async fn login_with_anisette<
        F: Fn() -> Result<(String, String), String>,
        G: Fn() -> Result<String, String>,
    >(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<Account, Error> {
        let mut _self = Account::new_with_anisette(anisette)?;
        let (username, password) = appleid_closure().map_err(|e| {
            Error::AuthSrpWithMessage(0, format!("Failed to get Apple ID credentials: {}", e))
        })?;

        let mut response = _self.login_email_pass(&username, &password).await?;

        loop {
            match response {
                LoginState::NeedsDevice2FA => response = _self.send_2fa_to_devices().await?,
                LoginState::Needs2FAVerification => {
                    response = _self
                        .verify_2fa(tfa_closure().map_err(|e| {
                            Error::AuthSrpWithMessage(0, format!("Failed to get 2FA code: {}", e))
                        })?)
                        .await?
                }
                LoginState::NeedsSMS2FA => response = _self.send_sms_2fa_to_devices(1).await?,
                LoginState::NeedsSMS2FAVerification(body) => {
                    response = _self
                        .verify_sms_2fa(
                            tfa_closure().map_err(|e| {
                                Error::AuthSrpWithMessage(
                                    0,
                                    format!("Failed to get SMS 2FA code: {}", e),
                                )
                            })?,
                            body,
                        )
                        .await?
                }
                LoginState::NeedsLogin => {
                    response = _self.login_email_pass(&username, &password).await?
                }
                LoginState::LoggedIn => return Ok(_self),
                LoginState::NeedsExtraStep(step) => {
                    if _self.get_pet().is_some() {
                        return Ok(_self);
                    } else {
                        return Err(Error::ExtraStep(step));
                    }
                }
            }
        }
    }

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<LoginState, Error> {
        let username_for_spd = username.to_string();
        let srp_client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let anisette = self.get_anisette().await;

        let gsa_headers = grandslam_headers(&anisette)?;

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let init_body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: anisette.to_plist(true, false, false),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.to_string(),
        };

        let init_packet = InitRequest {
            header: header.clone(),
            request: init_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &init_packet)?;

        let res = send_grandslam_request(
            &self.client,
            GSA_ENDPOINT,
            gsa_headers.clone(),
            buffer,
            "SRP init",
        )
        .await?;
        check_error(&res)?;

        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();
        // Apple picks which of the two protocols we advertised in `ps` (above)
        // it wants to use; "s2k_fo" additionally hex-encodes the password hash
        // before PBKDF2. Assuming plain "s2k" unconditionally produces a wrong
        // SRP proof (and a misleading "wrong password" error from Apple) for
        // any account where the server selects "s2k_fo".
        let protocol = res.get("sp").and_then(|v| v.as_string()).unwrap_or("s2k");

        let hashed_password = Sha256::digest(password.as_bytes());
        let hashed_password: Vec<u8> = if protocol == "s2k_fo" {
            hex::encode(hashed_password).into_bytes()
        } else {
            hashed_password.to_vec()
        };

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &hashed_password,
            salt,
            iters as u32,
            &mut password_buf,
        );

        // Apple's GSA SRP variant deviates from both RFC 5054 and the `srp`
        // crate's `process_reply` in several specific ways -- verified against
        // a known-working reference (pysrp configured with the exact
        // `rfc5054_enable()` + `no_username_in_x()` combination Apple's real
        // protocol requires, as used by e.g. JJTech0130's GSA client gist).
        // This is exactly what the original (now 404'd) `plume-PAKEs` SRP
        // fork must have patched in; the vanilla crate doesn't expose a way
        // to override just these pieces, so we call its lower-level public
        // primitives directly instead of `process_reply`:
        //   - x = H(salt || H(":" || password)) -- the RFC 5054 identity hash
        //     and its ":" separator are still computed, just with the
        //     username blanked out (NOT simply H(salt || password)).
        //   - u = H(PAD(A) || PAD(B)), A/B zero-padded to N's byte length
        //     (256 bytes for the 2048-bit group) -- the crate's `compute_u`
        //     hashes them unpadded.
        //   - K = H(S) -- the session key is a hash of the premaster secret;
        //     `process_reply` uses raw S directly as the session key, which
        //     skips this.
        //   - M1 = H(H(N) xor H(PAD(g)) || H(username) || salt || A || B || K),
        //     the full RFC 5054 M1 formula with the *real* username and A/B
        //     UNPADDED here -- not the crate's simplified H(A || B || K).
        let n_bytes = G_2048.n.to_bytes_be();
        let width = n_bytes.len();

        let a_big = BigUint::from_bytes_be(&a);
        let a_pub_big = srp_client.compute_a_pub(&a_big);
        let b_pub_big = BigUint::from_bytes_be(b_pub);
        let a_pub_bytes = a_pub_big.to_bytes_be();
        let b_pub_bytes = b_pub_big.to_bytes_be();

        let mut identity_hasher = Sha256::new();
        identity_hasher.update(b":");
        identity_hasher.update(&password_buf);
        let identity_hash = identity_hasher.finalize();

        let mut x_hasher = Sha256::new();
        x_hasher.update(salt);
        x_hasher.update(&identity_hash);
        let x = BigUint::from_bytes_be(&x_hasher.finalize());

        let mut u_hasher = Sha256::new();
        u_hasher.update(pad_left(&a_pub_bytes, width));
        u_hasher.update(pad_left(&b_pub_bytes, width));
        let u = BigUint::from_bytes_be(&u_hasher.finalize());

        let k = compute_k::<Sha256>(&G_2048);
        let premaster = srp_client.compute_premaster_secret(&b_pub_big, &k, &x, &a_big, &u);
        let session_key = Sha256::digest(premaster.to_bytes_be());

        let g_bytes = G_2048.g.to_bytes_be();
        let h_n = Sha256::digest(&n_bytes);
        let h_g = Sha256::digest(pad_left(&g_bytes, width));
        let hn_xor_g: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(x, y)| x ^ y).collect();
        let h_username = Sha256::digest(username.as_bytes());

        let mut m1_hasher = Sha256::new();
        m1_hasher.update(&hn_xor_g);
        m1_hasher.update(h_username);
        m1_hasher.update(salt);
        m1_hasher.update(&a_pub_bytes);
        m1_hasher.update(&b_pub_bytes);
        m1_hasher.update(session_key);
        let m1 = m1_hasher.finalize();

        let mut m2_hasher = Sha256::new();
        m2_hasher.update(&a_pub_bytes);
        m2_hasher.update(m1);
        m2_hasher.update(session_key);
        let m2_expected = m2_hasher.finalize();

        let challenge_body = ChallengeRequestBody {
            m: plist::Value::Data(m1.to_vec()),
            c: c.to_string(),
            cpd: anisette.to_plist(true, false, false),
            operation: "complete".to_string(),
            username: username.to_string(),
        };

        let challenge_packet = ChallengeRequest {
            header,
            request: challenge_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &challenge_packet)?;

        let res = send_grandslam_request(
            &self.client,
            GSA_ENDPOINT,
            gsa_headers,
            buffer,
            "SRP complete",
        )
        .await?;
        check_error(&res)?;

        let m2 = res.get("M2").unwrap().as_data().unwrap();
        if m2_expected.as_slice() != m2 {
            return Err(Error::AuthSrpWithMessage(
                0,
                "server SRP proof (M2) verification failed".to_string(),
            ));
        }

        let spd_encrypted = res.get("spd").unwrap().as_data().unwrap();
        let spd_decrypted = super::decrypt_cbc(&session_key, spd_encrypted);
        let mut spd: Dictionary = plist::from_bytes(&spd_decrypted).unwrap();

        if !spd.contains_key("appleId") {
            spd.insert(
                "appleId".to_string(),
                plist::Value::String(username_for_spd),
            );
        }

        self.spd = Some(spd);

        let status = res.get("Status").unwrap().as_dictionary().unwrap();
        if let Some(Value::String(auth_type)) = status.get("au") {
            return match auth_type.as_str() {
                "trustedDeviceSecondaryAuth" => Ok(LoginState::NeedsDevice2FA),
                "secondaryAuth" => Ok(LoginState::NeedsSMS2FA),
                other => Ok(LoginState::NeedsExtraStep(other.to_string())),
            };
        }

        Ok(LoginState::LoggedIn)
    }

    pub fn get_pet(&self) -> Option<String> {
        let base = self.spd.as_ref().unwrap();
        let token = base.get("t")?.as_dictionary()?;

        Some(plist_get_string!(token, "com.apple.gs.idms.pet", "token"))
    }

    pub fn get_name(&self) -> (String, String) {
        let base = self.spd.as_ref().unwrap();
        (plist_get_string!(base, "fn"), plist_get_string!(base, "ln"))
    }

    pub async fn get_anisette(&self) -> AnisetteData {
        let mut locked = self.anisette.lock().await;
        if locked.needs_refresh() {
            *locked = locked.refresh().await.unwrap();
        }
        locked.clone()
    }
}

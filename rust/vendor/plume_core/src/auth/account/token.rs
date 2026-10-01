use aes_gcm::aead::generic_array::{GenericArray, typenum::U16};
use aes_gcm::aes::Aes256;
use aes_gcm::{
    AesGcm,
    aead::{Aead, Payload},
};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};

use crate::Error;
use sha2::Sha256;

use crate::auth::account::{check_error, grandslam_headers, send_grandslam_request};
use crate::auth::{
    Account, AppToken, AuthTokenRequest, AuthTokenRequestBody, GSA_ENDPOINT, RequestHeader,
};

type Aes256Gcm16 = AesGcm<Aes256, U16>;

impl Account {
    pub async fn get_app_token(&self, app_name: &str) -> Result<AppToken, Error> {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let auth_token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let valid_anisette = self.get_anisette().await;

        let sk = spd.get("sk").unwrap().as_data().unwrap();
        let c = spd.get("c").unwrap().as_data().unwrap();

        let checksum = Self::create_checksum(&sk.to_vec(), dsid, app_name);

        let gsa_headers = grandslam_headers(&valid_anisette)?;

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = AuthTokenRequestBody {
            cpd: valid_anisette.to_plist(true, false, false),
            app: vec![app_name.to_string()],
            c: plist::Value::Data(c.to_vec()),
            operation: "apptokens".to_owned(),
            t: auth_token.to_string(),
            u: dsid.to_string(),
            checksum: plist::Value::Data(checksum),
        };

        let packet = AuthTokenRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let res =
            send_grandslam_request(&self.client, GSA_ENDPOINT, gsa_headers, buffer, "App token")
                .await?;
        let err_check = check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }

        let encrypted_token = res
            .get("et")
            .ok_or(Error::Parse)?
            .as_data()
            .ok_or(Error::Parse)?;

        if encrypted_token.len() < 3 + 16 + 16 {
            return Err(Error::Parse);
        }
        let header = &encrypted_token[0..3];
        if header != b"XYZ" {
            return Err(Error::AuthSrpWithMessage(
                0,
                "Encrypted token is in an unknown format.".to_string(),
            ));
        }
        let iv = &encrypted_token[3..19];
        let ciphertext_and_tag = &encrypted_token[19..];

        if sk.len() != 32 {
            return Err(Error::Parse);
        }
        if iv.len() != 16 {
            return Err(Error::Parse);
        }
        // TODO: fucking botan
        let cipher = Aes256Gcm16::new(GenericArray::from_slice(sk));

        let nonce = GenericArray::from_slice(iv);

        let decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext_and_tag,
                    aad: header, // b"XYZ"
                },
            )
            .map_err(|_| {
                Error::AuthSrpWithMessage(
                    0,
                    "Failed to decrypt app token (AES-256-GCM).".to_string(),
                )
            })?;

        let decrypted_token: plist::Dictionary =
            plist::from_bytes(&decrypted).map_err(|_| Error::Parse)?;

        let t_val = decrypted_token.get("t").ok_or(Error::Parse)?;
        let app_tokens = t_val.as_dictionary().ok_or(Error::Parse)?;
        let app_token_dict = app_tokens.get(app_name).ok_or(Error::Parse)?;
        let app_token = app_token_dict.as_dictionary().ok_or(Error::Parse)?;
        let token = app_token
            .get("token")
            .and_then(|v| v.as_string())
            .ok_or(Error::Parse)?;

        Ok(AppToken {
            app_tokens: app_tokens.clone(),
            auth_token: token.to_string(),
            app: app_name.to_string(),
        })
    }

    fn create_checksum(session_key: &Vec<u8>, dsid: &str, app_name: &str) -> Vec<u8> {
        <Hmac<Sha256> as KeyInit>::new_from_slice(&session_key)
            .unwrap()
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app_name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }
}

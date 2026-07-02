//! Web Push sender: RFC 8030 delivery, RFC 8291 (aes128gcm) payload
//! encryption, RFC 8292 (VAPID) authorization.
//!
//! Implemented directly on the RustCrypto stack (p256 + hkdf + aes-gcm) so the
//! relay stays pure-Rust/rustls — the off-the-shelf `web-push` crate drags in
//! OpenSSL via `ece`. Correctness is pinned by the RFC 8291 Appendix A test
//! vector below.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use serde::Deserialize;
use sha2::Sha256;

use crate::db::{Database, DbError};

const VAPID_CONFIG_KEY: &str = "vapid_private_pem";
/// VAPID `sub` claim — a contact URI push services may use for abuse reports.
const VAPID_SUBJECT: &str = "mailto:sean2by4@gmail.com";
/// How long a push service should retain an undelivered message.
const PUSH_TTL_SECS: u32 = 24 * 60 * 60;

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("VAPID key error: {0}")]
    Key(String),
    #[error("subscription error: {0}")]
    Subscription(String),
    #[error("encryption error: {0}")]
    Crypto(String),
}

/// A browser PushSubscription as serialized by `subscription.toJSON()`.
#[derive(Debug, Deserialize)]
struct SubscriptionInfo {
    endpoint: String,
    keys: SubscriptionKeys,
}

#[derive(Debug, Deserialize)]
struct SubscriptionKeys {
    /// Client's P-256 public key (base64url, uncompressed point).
    p256dh: String,
    /// 16-byte authentication secret (base64url).
    auth: String,
}

pub struct PushManager {
    secret: SecretKey,
    public_key_b64: String,
    http: reqwest::Client,
    db: Database,
}

impl PushManager {
    pub fn init(db: Database) -> Result<Self, PushError> {
        let pem = match db.get_config(VAPID_CONFIG_KEY)? {
            Some(pem) => pem,
            None => {
                let secret = SecretKey::random(&mut rand::rngs::OsRng);
                let pem = secret
                    .to_sec1_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| PushError::Key(e.to_string()))?
                    .to_string();
                db.set_config(VAPID_CONFIG_KEY, &pem)?;
                tracing::info!("generated new VAPID keypair");
                pem
            }
        };

        let secret =
            SecretKey::from_sec1_pem(&pem).map_err(|e| PushError::Key(e.to_string()))?;
        let public_key_b64 =
            URL_SAFE_NO_PAD.encode(secret.public_key().to_encoded_point(false).as_bytes());

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| PushError::Key(e.to_string()))?;

        Ok(Self {
            secret,
            public_key_b64,
            http,
            db,
        })
    }

    /// Base64url uncompressed P-256 public point — the `applicationServerKey`
    /// a browser passes to pushManager.subscribe().
    pub fn public_key(&self) -> &str {
        &self.public_key_b64
    }

    /// Push `payload` to every subscription registered for `username`,
    /// pruning subscriptions the push service reports as gone.
    pub async fn send_to_user(&self, username: &str, payload: &serde_json::Value) {
        let subs = match self.db.list_push_subscriptions(username) {
            Ok(subs) => subs,
            Err(e) => {
                tracing::error!(error = %e, "failed to list push subscriptions");
                return;
            }
        };

        let body = payload.to_string();

        for (device_id, sub_json) in subs {
            match self.send_one(&sub_json, body.as_bytes()).await {
                Ok(status) if status == 404 || status == 410 => {
                    tracing::info!(device_id = %device_id, "push endpoint gone — pruning subscription");
                    let _ = self.db.remove_push_subscription(&device_id);
                }
                Ok(status) if status >= 400 => {
                    tracing::warn!(device_id = %device_id, status, "push service rejected message");
                }
                Ok(_) => {}
                Err(PushError::Subscription(e)) => {
                    tracing::warn!(device_id = %device_id, error = %e, "invalid subscription — pruning");
                    let _ = self.db.remove_push_subscription(&device_id);
                }
                Err(e) => {
                    tracing::warn!(device_id = %device_id, error = %e, "push send failed");
                }
            }
        }
    }

    async fn send_one(&self, sub_json: &str, plaintext: &[u8]) -> Result<u16, PushError> {
        let sub: SubscriptionInfo = serde_json::from_str(sub_json)
            .map_err(|e| PushError::Subscription(e.to_string()))?;

        let ua_public = b64url_decode(&sub.keys.p256dh)
            .map_err(|e| PushError::Subscription(format!("p256dh: {e}")))?;
        let auth_secret = b64url_decode(&sub.keys.auth)
            .map_err(|e| PushError::Subscription(format!("auth: {e}")))?;

        let body = encrypt_aes128gcm(&ua_public, &auth_secret, plaintext)?;

        if !is_valid_push_endpoint(&sub.endpoint) {
            return Err(PushError::Subscription("endpoint rejected".into()));
        }
        let endpoint: reqwest::Url = sub
            .endpoint
            .parse()
            .map_err(|_| PushError::Subscription("bad endpoint URL".into()))?;
        let origin = format!(
            "{}://{}",
            endpoint.scheme(),
            endpoint
                .host_str()
                .ok_or_else(|| PushError::Subscription("endpoint has no host".into()))?
        );
        let jwt = self.vapid_jwt(&origin)?;

        let resp = self
            .http
            .post(endpoint)
            .header("TTL", PUSH_TTL_SECS)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("Urgency", "normal")
            .header(
                "Authorization",
                format!("vapid t={jwt}, k={}", self.public_key_b64),
            )
            .body(body)
            .send()
            .await
            .map_err(|e| PushError::Crypto(format!("http: {e}")))?;

        Ok(resp.status().as_u16())
    }

    /// RFC 8292 VAPID token: ES256 JWT with the push service origin as
    /// audience.
    fn vapid_jwt(&self, audience: &str) -> Result<String, PushError> {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PushError::Key(e.to_string()))?
            .as_secs()
            + 12 * 60 * 60;

        let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "aud": audience, "exp": exp, "sub": VAPID_SUBJECT }).to_string(),
        );
        let signing_input = format!("{header}.{claims}");

        let key = SigningKey::from(&self.secret);
        let signature: Signature = key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

/// Decode base64url with or without padding (browsers emit unpadded, but be
/// lenient about stored values).
fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))
}

/// SSRF guard for stored subscription endpoints: real push services are
/// always public HTTPS hostnames — reject IP literals, localhost, and
/// non-HTTPS schemes so the relay can't be pointed at internal services.
pub fn is_valid_push_endpoint(endpoint: &str) -> bool {
    let Ok(url) = endpoint.parse::<reqwest::Url>() else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    !(lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local"))
}

/// RFC 8291 aes128gcm encryption with a fresh ephemeral key and random salt.
fn encrypt_aes128gcm(
    ua_public: &[u8],
    auth_secret: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PushError> {
    let as_secret = SecretKey::random(&mut rand::rngs::OsRng);
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    encrypt_aes128gcm_inner(&as_secret, &salt, ua_public, auth_secret, plaintext)
}

/// Deterministic core, split out so the RFC test vector can pin the ephemeral
/// key and salt.
fn encrypt_aes128gcm_inner(
    as_secret: &SecretKey,
    salt: &[u8; 16],
    ua_public: &[u8],
    auth_secret: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PushError> {
    let ua_key = PublicKey::from_sec1_bytes(ua_public)
        .map_err(|e| PushError::Subscription(format!("p256dh key: {e}")))?;
    let as_public = as_secret.public_key().to_encoded_point(false);

    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_key.as_affine());

    // IKM = HKDF(salt=auth_secret, ikm=ecdh, info="WebPush: info"||0x00||ua_pub||as_pub)
    let mut info = Vec::with_capacity(14 + 65 + 65);
    info.extend_from_slice(b"WebPush: info\x00");
    info.extend_from_slice(ua_public);
    info.extend_from_slice(as_public.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes());
    let mut ikm = [0u8; 32];
    hk.expand(&info, &mut ikm)
        .map_err(|e| PushError::Crypto(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    hk.expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .map_err(|e| PushError::Crypto(e.to_string()))?;
    let mut nonce = [0u8; 12];
    hk.expand(b"Content-Encoding: nonce\x00", &mut nonce)
        .map_err(|e| PushError::Crypto(e.to_string()))?;

    // Single record: plaintext || 0x02 (last-record delimiter).
    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(0x02);
    let ciphertext = Aes128Gcm::new(cek.as_slice().into())
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|e| PushError::Crypto(e.to_string()))?;

    // aes128gcm header: salt(16) || rs(4) || idlen(1) || keyid(as_public, 65)
    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8291 Appendix A — full worked example. Byte-exact output proves the
    /// key schedule, AEAD, and framing.
    #[test]
    fn test_rfc8291_vector() {
        let ua_public = b64url_decode(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        )
        .unwrap();
        let auth_secret = b64url_decode("BTBZMqHH6r4Tts7J_aSIgg").unwrap();
        let as_private = b64url_decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw").unwrap();
        let salt: [u8; 16] = b64url_decode("DGv6ra1nlYgDCS1FRnbzlw")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = b"When I grow up, I want to be a watermelon";

        let as_secret = SecretKey::from_slice(&as_private).unwrap();
        let body =
            encrypt_aes128gcm_inner(&as_secret, &salt, &ua_public, &auth_secret, plaintext)
                .unwrap();

        let expected = b64url_decode(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
        )
        .unwrap();
        assert_eq!(body, expected);
    }

    #[test]
    fn test_vapid_jwt_shape() {
        let db = Database::open_in_memory().unwrap();
        let mgr = PushManager::init(db).unwrap();
        let jwt = mgr.vapid_jwt("https://fcm.googleapis.com").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        // ES256 signature is 64 raw bytes
        assert_eq!(b64url_decode(parts[2]).unwrap().len(), 64);
    }

    #[test]
    fn test_endpoint_validation() {
        assert!(is_valid_push_endpoint("https://fcm.googleapis.com/fcm/send/abc123"));
        assert!(is_valid_push_endpoint("https://updates.push.services.mozilla.com/wpush/v2/x"));

        assert!(!is_valid_push_endpoint("http://fcm.googleapis.com/x")); // not https
        assert!(!is_valid_push_endpoint("https://127.0.0.1:8080/x"));
        assert!(!is_valid_push_endpoint("https://[::1]/x"));
        assert!(!is_valid_push_endpoint("https://10.0.0.5/x"));
        assert!(!is_valid_push_endpoint("https://localhost/x"));
        assert!(!is_valid_push_endpoint("https://relay.localhost/x"));
        assert!(!is_valid_push_endpoint("https://printer.local/x"));
        assert!(!is_valid_push_endpoint("not a url"));
    }

    #[test]
    fn test_vapid_key_persists() {
        let db = Database::open_in_memory().unwrap();
        let mgr1 = PushManager::init(db.clone()).unwrap();
        let mgr2 = PushManager::init(db).unwrap();
        assert_eq!(mgr1.public_key(), mgr2.public_key());
    }
}

use crate::db::Database;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("TOTP required")]
    TotpRequired,
    #[error("invalid TOTP code")]
    InvalidTotp,
    #[error("rate limited")]
    RateLimited { retry_after: u64 },
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("database error: {0}")]
    Db(#[from] crate::db::DbError),
    #[error("TOTP error: {0}")]
    Totp(String),
    #[error("encryption error: {0}")]
    Encryption(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // username
    pub device_id: String,
    pub exp: usize,
    pub iat: usize,
    pub aud: String,
    pub iss: String,
}

const JWT_AUDIENCE: &str = "command-center-relay";
const JWT_ISSUER: &str = "command-center-relay";

struct RateLimitEntry {
    failures: u32,
    locked_until: Option<Instant>,
}

pub struct AuthManager {
    db: Database,
    jwt_secret: Vec<u8>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

const MAX_FAILURES: u32 = 5;
const LOCKOUT_DURATION: Duration = Duration::from_secs(900); // 15 min
const JWT_EXPIRY: Duration = Duration::from_secs(86400); // 24 hours

impl AuthManager {
    pub fn new(db: Database) -> Result<Self, AuthError> {
        let jwt_secret = match db.get_config("jwt_secret")? {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .unwrap_or_else(|_| {
                    let s = generate_random_bytes(64);
                    let _ = db.set_config(
                        "jwt_secret",
                        &base64::engine::general_purpose::STANDARD.encode(&s),
                    );
                    s
                }),
            None => {
                let secret = generate_random_bytes(64);
                db.set_config(
                    "jwt_secret",
                    &base64::engine::general_purpose::STANDARD.encode(&secret),
                )?;
                secret
            }
        };

        Ok(Self {
            db,
            jwt_secret,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if a username is currently rate-limited.
    pub fn check_rate_limit(&self, username: &str) -> Result<(), AuthError> {
        let limits = self.rate_limits.read().unwrap();
        if let Some(entry) = limits.get(username) {
            if let Some(locked_until) = entry.locked_until {
                if Instant::now() < locked_until {
                    let remaining = locked_until.duration_since(Instant::now()).as_secs();
                    return Err(AuthError::RateLimited {
                        retry_after: remaining.max(1),
                    });
                }
            }
        }
        Ok(())
    }

    /// Record a failed authentication attempt.
    pub fn record_failure(&self, username: &str) {
        let mut limits = self.rate_limits.write().unwrap();
        let entry = limits.entry(username.to_string()).or_insert(RateLimitEntry {
            failures: 0,
            locked_until: None,
        });
        entry.failures += 1;
        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
        }
    }

    /// Clear rate limit on successful auth.
    pub fn clear_rate_limit(&self, username: &str) {
        let mut limits = self.rate_limits.write().unwrap();
        limits.remove(username);
    }

    /// Verify password (client sends SHA-256 hex, we compare against bcrypt(sha256)).
    /// Runs bcrypt on a blocking thread to avoid stalling the tokio runtime.
    pub async fn verify_password(
        &self,
        username: &str,
        password_sha256: &str,
    ) -> Result<(), AuthError> {
        let account = self.db.get_account(username)?;
        let hash = account.password_hash.clone();
        let input = password_sha256.to_string();
        let valid = tokio::task::spawn_blocking(move || bcrypt::verify(&input, &hash))
            .await
            .map_err(|_| AuthError::InvalidCredentials)??;
        if !valid {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(())
    }

    /// Check if TOTP is configured for a user.
    pub fn has_totp(&self, username: &str) -> Result<bool, AuthError> {
        let account = self.db.get_account(username)?;
        Ok(account.totp_secret_encrypted.is_some())
    }

    /// Verify TOTP code for a user.
    pub fn verify_totp(&self, username: &str, code: &str) -> Result<(), AuthError> {
        let account = self.db.get_account(username)?;
        let encrypted = account
            .totp_secret_encrypted
            .ok_or(AuthError::Totp("no TOTP configured".into()))?;
        let nonce_bytes = account
            .totp_nonce
            .ok_or(AuthError::Totp("missing TOTP nonce".into()))?;

        let decryption_key = derive_totp_key(&account.password_hash);
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| AuthError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let secret_bytes = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|e| AuthError::Encryption(e.to_string()))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            None,
            String::new(),
        )
        .map_err(|e| AuthError::Totp(e.to_string()))?;

        if !totp.check_current(code).map_err(|e| AuthError::Totp(e.to_string()))? {
            return Err(AuthError::InvalidTotp);
        }
        Ok(())
    }

    /// Create a JWT for an authenticated session.
    pub fn create_jwt(&self, username: &str, device_id: &str) -> Result<String, AuthError> {
        let now = chrono::Utc::now();
        let claims = JwtClaims {
            sub: username.to_string(),
            device_id: device_id.to_string(),
            iat: now.timestamp() as usize,
            exp: (now + JWT_EXPIRY).timestamp() as usize,
            aud: JWT_AUDIENCE.to_string(),
            iss: JWT_ISSUER.to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.jwt_secret),
        )?;
        Ok(token)
    }

    /// Validate a JWT and return claims.
    pub fn validate_jwt(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::default();
        validation.set_audience(&[JWT_AUDIENCE]);
        validation.set_issuer(&[JWT_ISSUER]);
        let data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(&self.jwt_secret),
            &validation,
        )?;
        Ok(data.claims)
    }

    /// Hash a password (SHA-256 hex in, bcrypt hash out).
    pub fn hash_password(password_sha256: &str) -> Result<String, AuthError> {
        Ok(bcrypt::hash(password_sha256, 12)?)
    }

    /// Store the SHA-256 hash of a provisioned desktop key for an account.
    pub fn set_desktop_key(&self, username: &str, key: &str) -> Result<(), AuthError> {
        self.db
            .set_config(&format!("desktop_key:{username}"), &sha256_hex(key))?;
        Ok(())
    }

    /// Verify a presented desktop key against the stored hash (constant-time).
    /// Returns false if no key is provisioned for the account.
    pub fn verify_desktop_key(&self, username: &str, key: &str) -> Result<bool, AuthError> {
        let stored = match self.db.get_config(&format!("desktop_key:{username}"))? {
            Some(h) => h,
            None => return Ok(false),
        };
        Ok(constant_time_eq(
            stored.as_bytes(),
            sha256_hex(key).as_bytes(),
        ))
    }

    /// Generate a TOTP secret, encrypt it, and return (TOTP instance, encrypted_secret, nonce).
    pub fn generate_totp(
        username: &str,
        password_hash: &str,
    ) -> Result<(TOTP, Vec<u8>, Vec<u8>), AuthError> {
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().map_err(|e| AuthError::Totp(e.to_string()))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("CommandCenterRelay".to_string()),
            username.to_string(),
        )
        .map_err(|e| AuthError::Totp(e.to_string()))?;

        let key = derive_totp_key(password_hash);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| AuthError::Encryption(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, secret_bytes.as_ref())
            .map_err(|e| AuthError::Encryption(e.to_string()))?;

        Ok((totp, encrypted, nonce_bytes.to_vec()))
    }

    pub fn db(&self) -> &Database {
        &self.db
    }
}

/// Derive a 256-bit key from the bcrypt hash for TOTP secret encryption.
fn derive_totp_key(password_hash: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, password_hash.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"totp-encryption-key", &mut key)
        .expect("HKDF expand should not fail for 32-byte output");
    key
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn sha256_hex(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Length-independent constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth() -> AuthManager {
        let db = Database::open_in_memory().unwrap();
        AuthManager::new(db).unwrap()
    }

    #[tokio::test]
    async fn test_password_hash_and_verify() {
        let auth = test_auth();
        let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = AuthManager::hash_password(sha256_hex).unwrap();
        auth.db()
            .create_account("testuser", &hash, None, None)
            .unwrap();
        assert!(auth.verify_password("testuser", sha256_hex).await.is_ok());
        assert!(auth.verify_password("testuser", "wronghash").await.is_err());
    }

    #[test]
    fn test_jwt_roundtrip() {
        let auth = test_auth();
        let token = auth.create_jwt("alice", "dev-123").unwrap();
        let claims = auth.validate_jwt(&token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.device_id, "dev-123");
    }

    #[test]
    fn test_rate_limiting() {
        let auth = test_auth();
        assert!(auth.check_rate_limit("bob").is_ok());
        for _ in 0..5 {
            auth.record_failure("bob");
        }
        let err = auth.check_rate_limit("bob").unwrap_err();
        assert!(matches!(err, AuthError::RateLimited { .. }));

        auth.clear_rate_limit("bob");
        assert!(auth.check_rate_limit("bob").is_ok());
    }

    #[test]
    fn test_totp_generation_and_verify() {
        let auth = test_auth();
        let sha256_hex = "abc123";
        let hash = AuthManager::hash_password(sha256_hex).unwrap();

        let (totp, encrypted, nonce) = AuthManager::generate_totp("testuser", &hash).unwrap();
        auth.db()
            .create_account("testuser", &hash, Some(&encrypted), Some(&nonce))
            .unwrap();

        let current_code = totp.generate_current().unwrap();
        assert!(auth.verify_totp("testuser", &current_code).is_ok());
        assert!(auth.verify_totp("testuser", "000000").is_err());
    }

    #[test]
    fn test_has_totp() {
        let auth = test_auth();
        let hash = AuthManager::hash_password("test").unwrap();
        auth.db().create_account("no_totp", &hash, None, None).unwrap();
        assert!(!auth.has_totp("no_totp").unwrap());

        let (_, enc, nonce) = AuthManager::generate_totp("with_totp", &hash).unwrap();
        auth.db()
            .create_account("with_totp", &hash, Some(&enc), Some(&nonce))
            .unwrap();
        assert!(auth.has_totp("with_totp").unwrap());
    }
}

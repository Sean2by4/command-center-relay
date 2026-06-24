use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("account already exists: {0}")]
    AccountExists(String),
    #[error("device not found: {0}")]
    DeviceNotFound(String),
}

#[derive(Debug, Clone)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub totp_secret_encrypted: Option<Vec<u8>>,
    pub totp_nonce: Option<Vec<u8>>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub username: String,
    pub name: String,
    pub approved_at: String,
    pub last_seen_at: Option<String>,
    pub last_ip: Option<String>,
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.run_migrations()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(include_str!("../migrations/001_initial.sql"))?;
        Ok(())
    }

    // --- Accounts ---

    pub fn create_account(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret_encrypted: Option<&[u8]>,
        totp_nonce: Option<&[u8]>,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<String> = conn
            .query_row(
                "SELECT username FROM accounts WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(DbError::AccountExists(username.to_string()));
        }
        conn.execute(
            "INSERT INTO accounts (username, password_hash, totp_secret_encrypted, totp_nonce) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, totp_secret_encrypted, totp_nonce],
        )?;
        Ok(())
    }

    pub fn get_account(&self, username: &str) -> Result<Account, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT username, password_hash, totp_secret_encrypted, totp_nonce, created_at FROM accounts WHERE username = ?1",
            params![username],
            |row| {
                Ok(Account {
                    username: row.get(0)?,
                    password_hash: row.get(1)?,
                    totp_secret_encrypted: row.get(2)?,
                    totp_nonce: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::AccountNotFound(username.to_string()),
            other => DbError::Sqlite(other),
        })
    }

    pub fn remove_account(&self, username: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM accounts WHERE username = ?1",
            params![username],
        )?;
        if rows == 0 {
            return Err(DbError::AccountNotFound(username.to_string()));
        }
        Ok(())
    }

    pub fn list_accounts(&self) -> Result<Vec<Account>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT username, password_hash, totp_secret_encrypted, totp_nonce, created_at FROM accounts ORDER BY username",
        )?;
        let accounts = stmt
            .query_map([], |row| {
                Ok(Account {
                    username: row.get(0)?,
                    password_hash: row.get(1)?,
                    totp_secret_encrypted: row.get(2)?,
                    totp_nonce: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(accounts)
    }

    // --- Devices ---

    pub fn add_device(&self, id: &str, username: &str, name: &str, ip: Option<&str>) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO devices (id, username, name, last_ip) VALUES (?1, ?2, ?3, ?4)",
            params![id, username, name, ip],
        )?;
        Ok(())
    }

    pub fn get_device(&self, device_id: &str) -> Result<Device, DbError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, username, name, approved_at, last_seen_at, last_ip FROM devices WHERE id = ?1",
            params![device_id],
            |row| {
                Ok(Device {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    name: row.get(2)?,
                    approved_at: row.get(3)?,
                    last_seen_at: row.get(4)?,
                    last_ip: row.get(5)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::DeviceNotFound(device_id.to_string()),
            other => DbError::Sqlite(other),
        })
    }

    pub fn list_devices_for_user(&self, username: &str) -> Result<Vec<Device>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, name, approved_at, last_seen_at, last_ip FROM devices WHERE username = ?1 ORDER BY approved_at",
        )?;
        let devices = stmt
            .query_map(params![username], |row| {
                Ok(Device {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    name: row.get(2)?,
                    approved_at: row.get(3)?,
                    last_seen_at: row.get(4)?,
                    last_ip: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(devices)
    }

    pub fn remove_device(&self, device_id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM devices WHERE id = ?1", params![device_id])?;
        if rows == 0 {
            return Err(DbError::DeviceNotFound(device_id.to_string()));
        }
        Ok(())
    }

    pub fn update_device_last_seen(&self, device_id: &str, ip: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET last_seen_at = datetime('now'), last_ip = ?2 WHERE id = ?1",
            params![device_id, ip],
        )?;
        Ok(())
    }

    // --- Config ---

    pub fn get_config(&self, key: &str) -> Result<Option<String>, DbError> {
        let conn = self.conn.lock().unwrap();
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    // --- Audit ---

    pub fn log_event(
        &self,
        event_type: &str,
        username: Option<&str>,
        device_id: Option<&str>,
        ip: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (event_type, username, device_id, ip, details) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![event_type, username, device_id, ip, details],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_in_memory().unwrap()
    }

    #[test]
    fn test_create_and_get_account() {
        let db = test_db();
        db.create_account("alice", "$2b$12$hash", None, None).unwrap();
        let acct = db.get_account("alice").unwrap();
        assert_eq!(acct.username, "alice");
        assert_eq!(acct.password_hash, "$2b$12$hash");
        assert!(acct.totp_secret_encrypted.is_none());
    }

    #[test]
    fn test_duplicate_account() {
        let db = test_db();
        db.create_account("bob", "hash1", None, None).unwrap();
        let err = db.create_account("bob", "hash2", None, None).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_remove_account() {
        let db = test_db();
        db.create_account("carol", "hash", None, None).unwrap();
        db.remove_account("carol").unwrap();
        let err = db.get_account("carol").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_list_accounts() {
        let db = test_db();
        db.create_account("alice", "h1", None, None).unwrap();
        db.create_account("bob", "h2", None, None).unwrap();
        let accounts = db.list_accounts().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].username, "alice");
        assert_eq!(accounts[1].username, "bob");
    }

    #[test]
    fn test_device_crud() {
        let db = test_db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "iPhone", Some("1.2.3.4")).unwrap();
        let dev = db.get_device("dev-1").unwrap();
        assert_eq!(dev.name, "iPhone");
        assert_eq!(dev.last_ip.as_deref(), Some("1.2.3.4"));

        db.update_device_last_seen("dev-1", "5.6.7.8").unwrap();
        let dev = db.get_device("dev-1").unwrap();
        assert_eq!(dev.last_ip.as_deref(), Some("5.6.7.8"));

        let devices = db.list_devices_for_user("alice").unwrap();
        assert_eq!(devices.len(), 1);

        db.remove_device("dev-1").unwrap();
        assert!(db.get_device("dev-1").is_err());
    }

    #[test]
    fn test_config() {
        let db = test_db();
        assert!(db.get_config("jwt_secret").unwrap().is_none());
        db.set_config("jwt_secret", "mysecret").unwrap();
        assert_eq!(db.get_config("jwt_secret").unwrap().unwrap(), "mysecret");
        db.set_config("jwt_secret", "updated").unwrap();
        assert_eq!(db.get_config("jwt_secret").unwrap().unwrap(), "updated");
    }

    #[test]
    fn test_audit_log() {
        let db = test_db();
        db.log_event("auth_success", Some("alice"), None, Some("1.2.3.4"), None)
            .unwrap();
        db.log_event("auth_failure", Some("bob"), None, Some("5.6.7.8"), Some("bad password"))
            .unwrap();
        // Just verify no errors — we don't expose a read API for audit_log in prod
    }

    #[test]
    fn test_cascade_delete() {
        let db = test_db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "Phone", None).unwrap();
        db.remove_account("alice").unwrap();
        // Device should be cascade-deleted
        assert!(db.get_device("dev-1").is_err());
    }
}

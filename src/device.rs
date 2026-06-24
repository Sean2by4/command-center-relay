use crate::db::Database;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("database error: {0}")]
    Db(#[from] crate::db::DbError),
}

/// Register a new device, returning its UUID.
pub fn register_device(
    db: &Database,
    username: &str,
    name: &str,
    ip: Option<&str>,
) -> Result<String, DeviceError> {
    let id = Uuid::new_v4().to_string();
    db.add_device(&id, username, name, ip)?;
    Ok(id)
}

/// Approve a pending device (already registered, just update last_seen).
pub fn approve_device(db: &Database, device_id: &str, ip: &str) -> Result<(), DeviceError> {
    db.update_device_last_seen(device_id, ip)?;
    Ok(())
}

/// Remove a device from the approved list.
pub fn revoke_device(db: &Database, device_id: &str) -> Result<(), DeviceError> {
    db.remove_device(device_id)?;
    Ok(())
}

/// Check if a device is registered for a given user.
pub fn is_device_registered(db: &Database, device_id: &str, username: &str) -> bool {
    match db.get_device(device_id) {
        Ok(dev) => dev.username == username,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_check() {
        let db = Database::open_in_memory().unwrap();
        db.create_account("alice", "hash", None, None).unwrap();

        let dev_id = register_device(&db, "alice", "iPhone", Some("1.2.3.4")).unwrap();
        assert!(is_device_registered(&db, &dev_id, "alice"));
        assert!(!is_device_registered(&db, &dev_id, "bob"));
    }

    #[test]
    fn test_approve_and_revoke() {
        let db = Database::open_in_memory().unwrap();
        db.create_account("alice", "hash", None, None).unwrap();

        let dev_id = register_device(&db, "alice", "Phone", None).unwrap();
        approve_device(&db, &dev_id, "5.6.7.8").unwrap();

        let dev = db.get_device(&dev_id).unwrap();
        assert_eq!(dev.last_ip.as_deref(), Some("5.6.7.8"));

        revoke_device(&db, &dev_id).unwrap();
        assert!(!is_device_registered(&db, &dev_id, "alice"));
    }
}

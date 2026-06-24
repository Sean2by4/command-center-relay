use crate::db::Database;
use tracing::info;

/// Structured audit event types.
#[derive(Debug, Clone, Copy)]
pub enum AuditEvent {
    AuthSuccess,
    AuthFailure,
    AuthRateLimited,
    TotpRequired,
    DesktopConnected,
    DesktopDisconnected,
    ClientConnected,
    ClientDisconnected,
    DeviceApproved,
    DeviceRejected,
    DeviceRevoked,
    AccountCreated,
    AccountRemoved,
}

impl AuditEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthSuccess => "auth_success",
            Self::AuthFailure => "auth_failure",
            Self::AuthRateLimited => "auth_rate_limited",
            Self::TotpRequired => "totp_required",
            Self::DesktopConnected => "desktop_connected",
            Self::DesktopDisconnected => "desktop_disconnected",
            Self::ClientConnected => "client_connected",
            Self::ClientDisconnected => "client_disconnected",
            Self::DeviceApproved => "device_approved",
            Self::DeviceRejected => "device_rejected",
            Self::DeviceRevoked => "device_revoked",
            Self::AccountCreated => "account_created",
            Self::AccountRemoved => "account_removed",
        }
    }
}

/// Log an audit event to both structured tracing and the SQLite audit_log table.
pub fn log_audit(
    db: &Database,
    event: AuditEvent,
    username: Option<&str>,
    device_id: Option<&str>,
    ip: Option<&str>,
    details: Option<&str>,
) {
    let event_str = event.as_str();

    info!(
        event_type = event_str,
        username = username.unwrap_or("-"),
        device_id = device_id.unwrap_or("-"),
        ip = ip.unwrap_or("-"),
        details = details.unwrap_or(""),
        "audit"
    );

    if let Err(e) = db.log_event(event_str, username, device_id, ip, details) {
        tracing::error!(error = %e, "failed to write audit log to database");
    }
}

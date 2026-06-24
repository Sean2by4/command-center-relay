use crate::audit::{self, AuditEvent};
use crate::auth::AuthManager;
use crate::broker::{Broker, ClientInfo, PendingDevice, WsMessage};
use crate::device;
use crate::protocol::{self, ControlMessage};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

/// Max size for text/JSON WebSocket messages (16 KB).
const MAX_TEXT_MESSAGE_SIZE: usize = 16 * 1024;
/// Max size for binary WebSocket messages (64 KB).
const MAX_BINARY_MESSAGE_SIZE: usize = 64 * 1024;
/// Max new WebSocket connections per IP per minute.
const WS_RATE_LIMIT_PER_MINUTE: usize = 10;
/// Shutdown grace period for open connections.
const SHUTDOWN_GRACE_SECS: u64 = 5;

pub struct AppState {
    pub broker: Broker,
    pub auth: AuthManager,
    /// Per-IP WebSocket connection rate limiter: IP -> list of connection timestamps.
    ws_rate_limits: Mutex<HashMap<String, Vec<std::time::Instant>>>,
}

impl AppState {
    pub fn new(broker: Broker, auth: AuthManager) -> Self {
        Self {
            broker,
            auth,
            ws_rate_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a new WebSocket connection from this IP should be allowed.
    async fn check_ws_rate_limit(&self, ip: &str) -> bool {
        let mut limits = self.ws_rate_limits.lock().await;
        let now = std::time::Instant::now();
        let one_minute_ago = now - std::time::Duration::from_secs(60);

        let timestamps = limits.entry(ip.to_string()).or_default();
        timestamps.retain(|t| *t > one_minute_ago);

        if timestamps.len() >= WS_RATE_LIMIT_PER_MINUTE {
            return false;
        }
        timestamps.push(now);
        true
    }
}

pub fn build_router(state: Arc<AppState>, static_dir: PathBuf) -> Router {
    let spa_fallback = static_dir.join("index.html");

    // Always use fallback so the type is consistent (ServeDir<ServeFile>)
    let serve_dir = ServeDir::new(&static_dir)
        .fallback(ServeFile::new(spa_fallback));

    // Restrict CORS to deny cross-origin requests (API-only server)
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(HeaderValue::from_static("null")));

    Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/ws", axum::routing::get(ws_handler))
        .fallback_service(serve_dir)
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'"),
        ))
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let connections = state.broker.total_connection_count();
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "connections": connections,
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();

    // Server-wide connection limit
    if state.broker.try_acquire_connection().is_err() {
        tracing::warn!(ip = %ip, "rejecting WebSocket: server at capacity");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    // Per-IP rate limit for new connections
    if !state.check_ws_rate_limit(&ip).await {
        state.broker.release_connection();
        tracing::warn!(ip = %ip, "rejecting WebSocket: IP rate limited");
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state, addr))
        .into_response()
}

/// State machine for a WebSocket connection after upgrade.
enum ConnectionRole {
    Unauthenticated,
    Desktop { username: String },
    Client { username: String, device_id: String },
}

/// Sanitize a string for safe inclusion in structured log fields.
/// Replaces control characters and newlines to prevent log injection.
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || c == '\n' || c == '\r' { '_' } else { c })
        .collect()
}

/// Validate a username: alphanumeric + underscore, max 32 chars.
fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 32
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validate a device name: printable ASCII, max 64 chars.
fn is_valid_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, addr: SocketAddr) {
    let ip = addr.ip().to_string();
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Channel for outbound messages to this connection
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<WsMessage>(256);

    // Spawn outbound writer
    let writer = tokio::spawn(async move {
        use futures_util::SinkExt;
        while let Some(msg) = outbound_rx.recv().await {
            let ws_msg = match msg {
                WsMessage::Text(t) => Message::Text(t.into()),
                WsMessage::Binary(b) => Message::Binary(b.into()),
                WsMessage::Close => {
                    let _ = ws_sender.close().await;
                    break;
                }
            };
            if ws_sender.send(ws_msg).await.is_err() {
                break;
            }
        }
    });

    // Send server hello
    let hello = ControlMessage::Hello {
        version: 1,
        client_version: None,
        server_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    let _ = outbound_tx
        .send(WsMessage::Text(serde_json::to_string(&hello).unwrap()))
        .await;

    let mut role = ConnectionRole::Unauthenticated;
    let mut ping_misses = 0u32;

    // Ping interval
    let ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    tokio::pin!(ping_interval);

    use futures_util::StreamExt;
    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                ping_misses += 1;
                if ping_misses > 3 {
                    tracing::info!(ip = %ip, "disconnecting due to missed pongs");
                    break;
                }
                let _ = outbound_tx.send(WsMessage::Text(
                    serde_json::to_string(&ControlMessage::Ping).unwrap()
                )).await;
            }
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        ping_misses = 0;
                        let text_str: &str = &text;

                        // Enforce text message size limit
                        if text_str.len() > MAX_TEXT_MESSAGE_SIZE {
                            tracing::warn!(
                                ip = %ip,
                                size = text_str.len(),
                                max = MAX_TEXT_MESSAGE_SIZE,
                                "dropping oversized text message"
                            );
                            continue;
                        }

                        let ctrl: Result<ControlMessage, _> = serde_json::from_str(text_str);
                        match ctrl {
                            Ok(ctrl_msg) => {
                                handle_control_message(
                                    &ctrl_msg,
                                    &mut role,
                                    &state,
                                    &outbound_tx,
                                    &ip,
                                ).await;
                            }
                            Err(e) => {
                                tracing::warn!(ip = %ip, error = %e, "invalid JSON message");
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        ping_misses = 0;

                        // Enforce binary message size limit
                        if data.len() > MAX_BINARY_MESSAGE_SIZE {
                            tracing::warn!(
                                ip = %ip,
                                size = data.len(),
                                max = MAX_BINARY_MESSAGE_SIZE,
                                "dropping oversized binary message"
                            );
                            continue;
                        }

                        handle_binary_message(&data, &role, &state).await;
                    }
                    Some(Ok(Message::Ping(_))) => {
                        ping_misses = 0;
                        // axum auto-responds with pong
                    }
                    Some(Ok(Message::Pong(_))) => {
                        ping_misses = 0;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::warn!(ip = %ip, error = %e, "WebSocket error");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup on disconnect
    match &role {
        ConnectionRole::Desktop { username } => {
            state.broker.unregister_desktop(username).await;
            audit::log_audit(
                state.auth.db(),
                AuditEvent::DesktopDisconnected,
                Some(username),
                None,
                Some(&ip),
                None,
            );
        }
        ConnectionRole::Client {
            username,
            device_id,
        } => {
            state.broker.unregister_client(username, device_id).await;
            audit::log_audit(
                state.auth.db(),
                AuditEvent::ClientDisconnected,
                Some(username),
                Some(device_id),
                Some(&ip),
                None,
            );
        }
        ConnectionRole::Unauthenticated => {}
    }

    // Release the server-wide connection slot
    state.broker.release_connection();

    let _ = outbound_tx.send(WsMessage::Close).await;
    writer.abort();
}

async fn handle_control_message(
    msg: &ControlMessage,
    role: &mut ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &mpsc::Sender<WsMessage>,
    ip: &str,
) {
    match msg {
        ControlMessage::Hello { .. } => {
            // Client hello acknowledged (we already sent server hello)
        }

        ControlMessage::Pong => {
            // Pong received, handled by ping_misses reset
        }

        ControlMessage::Auth {
            username,
            password_hash,
            totp,
            device_token,
            ..
        } => {
            // Validate username before processing
            if !is_valid_username(username) {
                tracing::warn!(
                    ip = %ip,
                    username = %sanitize_for_log(username),
                    "rejected auth: invalid username format"
                );
                send_auth_error(outbound_tx, "invalid_username").await;
                return;
            }

            handle_auth(
                username,
                password_hash,
                totp.as_deref(),
                device_token.as_deref(),
                role,
                state,
                outbound_tx,
                ip,
            )
            .await;
        }

        ControlMessage::DesktopRegister { .. } => {
            if let ConnectionRole::Unauthenticated = role {
                // Must authenticate first
                return;
            }
            if let ConnectionRole::Client { username, .. } = role {
                let username = username.clone();
                match state
                    .broker
                    .register_desktop(&username, outbound_tx.clone())
                    .await
                {
                    Ok(()) => {
                        *role = ConnectionRole::Desktop {
                            username: username.clone(),
                        };
                        let _ = outbound_tx
                            .send(WsMessage::Text(
                                serde_json::to_string(&ControlMessage::DesktopRegistered).unwrap(),
                            ))
                            .await;
                        audit::log_audit(
                            state.auth.db(),
                            AuditEvent::DesktopConnected,
                            Some(&username),
                            None,
                            Some(ip),
                            None,
                        );
                    }
                    Err(e) => {
                        send_auth_error(outbound_tx, "desktop_already_connected").await;
                        tracing::warn!(error = %e, "desktop registration failed");
                    }
                }
            }
        }

        // Client -> Desktop forwarding
        ControlMessage::SessionListRequest | ControlMessage::PtyResize { .. } => {
            if let ConnectionRole::Client { username, .. } = role {
                let json = serde_json::to_string(msg).unwrap();
                let _ = state
                    .broker
                    .send_to_desktop(username, WsMessage::Text(json))
                    .await;
            }
        }

        // Desktop -> Client(s) forwarding
        ControlMessage::SessionList { .. }
        | ControlMessage::SessionCreated { .. }
        | ControlMessage::SessionClosed { .. }
        | ControlMessage::PtyResized { .. } => {
            if let ConnectionRole::Desktop { username } = role {
                let json = serde_json::to_string(msg).unwrap();
                state
                    .broker
                    .broadcast_to_clients(username, WsMessage::Text(json))
                    .await;
            }
        }

        // Device approval from desktop
        ControlMessage::DeviceApproved { device_id } => {
            if let ConnectionRole::Desktop { username } = role {
                if let Some(pending) = state.broker.take_pending_device(username, device_id).await {
                    // Register device in DB
                    if let Err(e) =
                        device::approve_device(state.auth.db(), &pending.device_id, &pending.ip)
                    {
                        tracing::error!(error = %e, "device approval DB update failed");
                    }
                    // Create JWT for the pending client
                    if let Ok(token) = state.auth.create_jwt(username, &pending.device_id) {
                        let result = ControlMessage::AuthResult {
                            success: true,
                            token: Some(token),
                            device_id: Some(pending.device_id.clone()),
                            error: None,
                            retry_after: None,
                        };
                        let _ = pending
                            .client_tx
                            .send(WsMessage::Text(serde_json::to_string(&result).unwrap()))
                            .await;
                    }
                    audit::log_audit(
                        state.auth.db(),
                        AuditEvent::DeviceApproved,
                        Some(username),
                        Some(device_id),
                        Some(&pending.ip),
                        None,
                    );
                }
            }
        }

        ControlMessage::DeviceRejected { device_id } => {
            if let ConnectionRole::Desktop { username } = role {
                if let Some(pending) = state.broker.take_pending_device(username, device_id).await {
                    let result = ControlMessage::AuthResult {
                        success: false,
                        token: None,
                        device_id: None,
                        error: Some("device_rejected".into()),
                        retry_after: None,
                    };
                    let _ = pending
                        .client_tx
                        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()))
                        .await;
                    // Remove device from DB
                    let _ = device::revoke_device(state.auth.db(), &pending.device_id);
                    audit::log_audit(
                        state.auth.db(),
                        AuditEvent::DeviceRejected,
                        Some(username),
                        Some(device_id),
                        Some(&pending.ip),
                        None,
                    );
                }
            }
        }

        // Device management
        ControlMessage::ConnectedDevicesRequest => {
            if let ConnectionRole::Desktop { username } = role {
                let clients = state.broker.get_connected_clients(username).await;
                let devices: Vec<_> = clients
                    .into_iter()
                    .map(|c| crate::protocol::DeviceInfo {
                        id: c.device_id,
                        name: c.device_name,
                        ip: c.ip,
                        connected_at: c.connected_at,
                    })
                    .collect();
                let msg = ControlMessage::ConnectedDevicesList { devices };
                let _ = outbound_tx
                    .send(WsMessage::Text(serde_json::to_string(&msg).unwrap()))
                    .await;
            }
        }

        ControlMessage::DeviceRevoke { device_id } => {
            if let ConnectionRole::Desktop { username } = role {
                // Kick the client
                let revoked_msg = ControlMessage::DeviceRevoked {
                    device_id: device_id.clone(),
                };
                let _ = state
                    .broker
                    .send_to_client(
                        username,
                        device_id,
                        WsMessage::Text(serde_json::to_string(&revoked_msg).unwrap()),
                    )
                    .await;
                state.broker.unregister_client(username, device_id).await;
                let _ = device::revoke_device(state.auth.db(), device_id);
                audit::log_audit(
                    state.auth.db(),
                    AuditEvent::DeviceRevoked,
                    Some(username),
                    Some(device_id),
                    None,
                    None,
                );
                // Confirm to desktop
                let _ = outbound_tx
                    .send(WsMessage::Text(serde_json::to_string(&revoked_msg).unwrap()))
                    .await;
            }
        }

        _ => {
            tracing::debug!("unhandled control message");
        }
    }
}

async fn handle_auth(
    username: &str,
    password_hash: &str,
    totp: Option<&str>,
    device_token: Option<&str>,
    role: &mut ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &mpsc::Sender<WsMessage>,
    ip: &str,
) {
    // Rate limit check
    if let Err(crate::auth::AuthError::RateLimited { retry_after }) =
        state.auth.check_rate_limit(username)
    {
        let result = ControlMessage::AuthResult {
            success: false,
            token: None,
            device_id: None,
            error: Some("rate_limited".into()),
            retry_after: Some(retry_after),
        };
        let _ = outbound_tx
            .send(WsMessage::Text(serde_json::to_string(&result).unwrap()))
            .await;
        audit::log_audit(
            state.auth.db(),
            AuditEvent::AuthRateLimited,
            Some(username),
            None,
            Some(ip),
            None,
        );
        return;
    }

    // Verify password
    if let Err(_) = state.auth.verify_password(username, password_hash).await {
        state.auth.record_failure(username);
        send_auth_error(outbound_tx, "invalid_credentials").await;
        audit::log_audit(
            state.auth.db(),
            AuditEvent::AuthFailure,
            Some(username),
            None,
            Some(ip),
            Some("bad password"),
        );
        return;
    }

    // Check TOTP
    if state.auth.has_totp(username).unwrap_or(false) {
        match totp {
            None => {
                send_auth_error(outbound_tx, "totp_required").await;
                audit::log_audit(
                    state.auth.db(),
                    AuditEvent::TotpRequired,
                    Some(username),
                    None,
                    Some(ip),
                    None,
                );
                return;
            }
            Some(code) => {
                if let Err(_) = state.auth.verify_totp(username, code) {
                    state.auth.record_failure(username);
                    send_auth_error(outbound_tx, "invalid_credentials").await;
                    audit::log_audit(
                        state.auth.db(),
                        AuditEvent::AuthFailure,
                        Some(username),
                        None,
                        Some(ip),
                        Some("bad totp"),
                    );
                    return;
                }
            }
        }
    }

    state.auth.clear_rate_limit(username);

    // Check device token
    if let Some(token) = device_token {
        // Returning client with existing device token
        match state.auth.validate_jwt(token) {
            Ok(claims) if claims.sub == username => {
                // Check device still exists
                if device::is_device_registered(state.auth.db(), &claims.device_id, username) {
                    let _ = state
                        .auth
                        .db()
                        .update_device_last_seen(&claims.device_id, ip);
                    let new_token = state.auth.create_jwt(username, &claims.device_id).unwrap();
                    let result = ControlMessage::AuthResult {
                        success: true,
                        token: Some(new_token),
                        device_id: Some(claims.device_id.clone()),
                        error: None,
                        retry_after: None,
                    };
                    let _ = outbound_tx
                        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()))
                        .await;
                    let dev_id = claims.device_id;
                    *role = ConnectionRole::Client {
                        username: username.to_string(),
                        device_id: dev_id.clone(),
                    };
                    // Register in broker
                    let info = ClientInfo {
                        device_id: dev_id.clone(),
                        device_name: "Returning device".into(),
                        ip: ip.to_string(),
                        connected_at: chrono::Utc::now().to_rfc3339(),
                    };
                    let _ = state
                        .broker
                        .register_client(username, outbound_tx.clone(), info)
                        .await;
                    audit::log_audit(
                        state.auth.db(),
                        AuditEvent::AuthSuccess,
                        Some(username),
                        Some(&dev_id),
                        Some(ip),
                        Some("returning device"),
                    );
                    return;
                }
                // Device was revoked, fall through to new device flow
            }
            _ => {
                // Invalid token, fall through to new device flow
            }
        }
    }

    // New device — needs approval from desktop
    // First check if desktop is online
    if !state.broker.is_desktop_online(username).await {
        send_auth_error(outbound_tx, "desktop_offline").await;
        return;
    }

    // Register a provisional device
    let device_name = "Pending device"; // In real app, client would send user-agent
    let device_id = match device::register_device(state.auth.db(), username, device_name, Some(ip))
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "device registration failed");
            send_auth_error(outbound_tx, "internal_error").await;
            return;
        }
    };

    // Send device_pending to desktop
    let pending_msg = ControlMessage::DevicePending {
        device_id: device_id.clone(),
        device_name: device_name.to_string(),
        ip: ip.to_string(),
    };
    let _ = state
        .broker
        .send_to_desktop(
            username,
            WsMessage::Text(serde_json::to_string(&pending_msg).unwrap()),
        )
        .await;

    // Add to pending list
    state
        .broker
        .add_pending_device(
            username,
            PendingDevice {
                device_id,
                device_name: device_name.to_string(),
                ip: ip.to_string(),
                client_tx: outbound_tx.clone(),
            },
        )
        .await;

    // Don't set role yet — wait for desktop approval
    // The auth_result will be sent when the desktop approves/rejects
}

async fn handle_binary_message(data: &[u8], role: &ConnectionRole, state: &Arc<AppState>) {
    match protocol::parse_binary_frame(data) {
        Ok((frame_type, _session_id, _payload)) => match role {
            ConnectionRole::Client { username, .. } => {
                if frame_type == protocol::PTY_INPUT {
                    let _ = state
                        .broker
                        .send_to_desktop(username, WsMessage::Binary(data.to_vec()))
                        .await;
                }
            }
            ConnectionRole::Desktop { username } => {
                if matches!(
                    frame_type,
                    protocol::PTY_OUTPUT | protocol::PTY_SCROLLBACK
                ) {
                    state
                        .broker
                        .broadcast_to_clients(username, WsMessage::Binary(data.to_vec()))
                        .await;
                }
            }
            ConnectionRole::Unauthenticated => {}
        },
        Err(e) => {
            tracing::warn!(error = %e, "invalid binary frame");
        }
    }
}

async fn send_auth_error(tx: &mpsc::Sender<WsMessage>, error: &str) {
    let result = ControlMessage::AuthResult {
        success: false,
        token: None,
        device_id: None,
        error: Some(error.to_string()),
        retry_after: None,
    };
    let _ = tx
        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()))
        .await;
}

/// Run the server.
pub async fn run(
    host: &str,
    port: u16,
    state: Arc<AppState>,
    static_dir: PathBuf,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = build_router(state.clone(), static_dir);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    tracing::info!("relay listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let mut rx = shutdown_rx;
        let _ = rx.changed().await;
        tracing::info!("shutdown signal received, draining connections");
        state.broker.broadcast_shutdown().await;
        // Give connections time to close gracefully before force-stopping
        tokio::time::sleep(std::time::Duration::from_secs(SHUTDOWN_GRACE_SECS)).await;
        tracing::info!(
            remaining = state.broker.total_connection_count(),
            "shutdown grace period elapsed"
        );
    })
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_username() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("Bob_123"));
        assert!(is_valid_username("a"));
        assert!(is_valid_username(&"x".repeat(32)));

        assert!(!is_valid_username(""));
        assert!(!is_valid_username(&"x".repeat(33)));
        assert!(!is_valid_username("alice!"));
        assert!(!is_valid_username("al ice"));
        assert!(!is_valid_username("alice\ninjection"));
        assert!(!is_valid_username("../etc/passwd"));
    }

    #[test]
    fn test_valid_device_name() {
        assert!(is_valid_device_name("iPhone 15"));
        assert!(is_valid_device_name("My-Device_v2.0"));
        assert!(is_valid_device_name(&"x".repeat(64)));

        assert!(!is_valid_device_name(""));
        assert!(!is_valid_device_name(&"x".repeat(65)));
        assert!(!is_valid_device_name("device\ninjection"));
        assert!(!is_valid_device_name("device\x00null"));
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("normal text"), "normal text");
        assert_eq!(sanitize_for_log("line1\nline2"), "line1_line2");
        assert_eq!(sanitize_for_log("cr\rhere"), "cr_here");
        assert_eq!(sanitize_for_log("null\x00byte"), "null_byte");
    }
}

use crate::audit::{self, AuditEvent};
use crate::auth::AuthManager;
use crate::broker::{
    Broker, ClientInfo, ConnTx, PendingDevice, SupervisorQueryDecision, SupervisorResolveOutcome,
    WsMessage,
};
use crate::device;
use crate::protocol::{self, ControlMessage};
use crate::push::PushManager;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
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
/// Hard cap on a buffered bug-report upload. Reports are small (one screenshot
/// + text); anything larger is rejected before the relay buffers it.
const MAX_BUG_REPORT_UPLOAD_SIZE: u64 = 10 * 1024 * 1024;

pub struct AppState {
    pub broker: Broker,
    pub auth: AuthManager,
    pub push: PushManager,
    /// Base data directory (parent of the SQLite DB). Bug-report screenshots
    /// are written under `<data_dir>/bug-reports/`.
    pub data_dir: PathBuf,
    /// Per-IP WebSocket connection rate limiter: IP -> list of connection timestamps.
    ws_rate_limits: Mutex<HashMap<String, Vec<std::time::Instant>>>,
}

impl AppState {
    pub fn new(broker: Broker, auth: AuthManager, push: PushManager, data_dir: PathBuf) -> Self {
        Self {
            broker,
            auth,
            push,
            data_dir,
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
        .route("/bug-reports", axum::routing::get(list_bug_reports_handler))
        .route(
            "/bug-reports/{id}/screenshot",
            axum::routing::get(bug_report_screenshot_handler),
        )
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

/// Validate a `Authorization: Bearer <jwt>` header and return the authenticated
/// username (JWT `sub`). The JWT is the same 30-day token a phone/desktop client
/// receives in its AuthResult and re-presents as `device_token` on the WS path;
/// we reuse the exact same validation. Any failure maps to 401.
fn authenticate_bearer(state: &AppState, headers: &HeaderMap) -> Result<String, StatusCode> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = state
        .auth
        .validate_jwt(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // Mirror the WS reconnect path: a valid JWT from a revoked (deleted)
    // device must not keep working for the rest of its 30-day lifetime.
    if !device::is_device_registered(state.auth.db(), &claims.device_id, &claims.sub) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(claims.sub)
}

/// Clamp a requested `?limit=` to the API bounds: default 50, hard cap 500.
fn clamp_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(50).clamp(1, 500)
}

#[derive(serde::Deserialize)]
struct BugReportListQuery {
    limit: Option<usize>,
}

/// Wire shape for a listed bug report. Deliberately omits `username`
/// (single-tenant) and the server-internal `screenshot_path`.
#[derive(serde::Serialize)]
struct BugReportView {
    id: i64,
    device_id: String,
    device_name: Option<String>,
    text: String,
    created_at: String,
    app_version: Option<String>,
    has_screenshot: bool,
}

/// GET /bug-reports — newest-first JSON list for the authenticated account.
async fn list_bug_reports_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BugReportListQuery>,
) -> Response {
    let username = match authenticate_bearer(&state, &headers) {
        Ok(u) => u,
        Err(code) => return code.into_response(),
    };
    let limit = clamp_limit(query.limit);
    match state.auth.db().list_bug_reports(&username, limit) {
        Ok(reports) => {
            let views: Vec<BugReportView> = reports
                .into_iter()
                .map(|r| BugReportView {
                    id: r.id,
                    device_id: r.device_id,
                    device_name: r.device_name,
                    text: r.text,
                    created_at: r.created_at,
                    app_version: r.app_version,
                    has_screenshot: r.screenshot_path.is_some(),
                })
                .collect();
            axum::Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to list bug reports");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /bug-reports/{id}/screenshot — streams the stored PNG. 404 when the row
/// is missing/foreign, carries no screenshot, or the file is gone. The path is
/// taken strictly from the DB row; the client only supplies the integer id.
async fn bug_report_screenshot_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let username = match authenticate_bearer(&state, &headers) {
        Ok(u) => u,
        Err(code) => return code.into_response(),
    };
    let report = match state.auth.db().get_bug_report(&username, id) {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to load bug report");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let path = match report.screenshot_path {
        Some(p) => p,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    match std::fs::read(&path) {
        Ok(bytes) => (
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("image/png"),
            )],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(ClientAddr(addr)): ConnectInfo<ClientAddr>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Prefer X-Real-IP set by nginx (unforgeable — always $remote_addr).
    // Fall back to peer addr for direct connections.
    let ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.ip().to_string());

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

    ws.on_upgrade(move |socket| handle_socket(socket, state, ip))
        .into_response()
}

/// State machine for a WebSocket connection after upgrade.
enum ConnectionRole {
    Unauthenticated,
    /// Parked after password/TOTP succeeded but the device still needs desktop
    /// approval. Carries the account + minted device_id so a disconnect before
    /// approval can garbage-collect the pending entry (ghost cleanup).
    PendingApproval { username: String, device_id: String },
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

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, ip: String) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Outbound queue for this connection: unbounded with explicit byte
    // accounting (the broker's per-client budget marks slow clients dirty
    // instead of silently dropping frames — see broker::ConnTx).
    let (raw_tx, mut outbound_rx) = mpsc::unbounded_channel::<WsMessage>();
    let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outbound_tx = ConnTx::new(raw_tx, queued.clone());

    // Spawn outbound writer
    let writer = tokio::spawn(async move {
        use futures_util::SinkExt;
        use std::sync::atomic::Ordering;
        while let Some(msg) = outbound_rx.recv().await {
            let ws_msg = match msg {
                WsMessage::Text(t) => {
                    queued.fetch_sub(t.len(), Ordering::Relaxed);
                    Message::Text(t.into())
                }
                WsMessage::Binary(b) => {
                    queued.fetch_sub(b.len(), Ordering::Relaxed);
                    Message::Binary(b.into())
                }
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
        .send(WsMessage::Text(serde_json::to_string(&hello).unwrap()));

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
                ));
            }
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(m)) => {
                        // Any inbound frame counts as liveness.
                        ping_misses = 0;
                        if matches!(m, Message::Close(_)) {
                            break;
                        }
                        process_ws_message(m, &mut role, &state, &outbound_tx, &ip).await;
                    }
                    None => {
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
            state.broker.unregister_desktop(username, &outbound_tx).await;
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
            state
                .broker
                .unregister_client(username, device_id, &outbound_tx)
                .await;
            audit::log_audit(
                state.auth.db(),
                AuditEvent::ClientDisconnected,
                Some(username),
                Some(device_id),
                Some(&ip),
                None,
            );
        }
        ConnectionRole::PendingApproval { username, device_id } => {
            // Ghost cleanup: the client parked for approval closed before the
            // desktop acted. Drop its pending entry, roll back the provisional
            // device row, and refresh the desktop's pending list so the stale
            // approval card disappears.
            if let Some(pending) =
                state.broker.remove_pending_by_conn(username, &outbound_tx).await
            {
                let _ = device::revoke_device(state.auth.db(), &pending.device_id);
                state.broker.push_pending_devices_list(username).await;
                audit::log_audit(
                    state.auth.db(),
                    AuditEvent::DeviceRejected,
                    Some(username),
                    Some(device_id),
                    Some(&ip),
                    Some("pending client disconnected"),
                );
            }
            // If approval already registered this connection as a client (before
            // it re-authed to promote its role), free that registration too.
            state
                .broker
                .unregister_client(username, device_id, &outbound_tx)
                .await;
        }
        ConnectionRole::Unauthenticated => {}
    }

    // Release the server-wide connection slot
    state.broker.release_connection();

    let _ = outbound_tx.send(WsMessage::Close);
    writer.abort();
}

/// Process one inbound WebSocket frame: enforce the per-frame size gates, then
/// parse+dispatch. Extracted from the receive loop so tests can drive the REAL
/// gates — critically, an oversized text frame is dropped HERE, before JSON
/// parsing, which is why large payloads (bug-report screenshots) must travel as
/// binary chunks rather than inline JSON.
async fn process_ws_message(
    msg: Message,
    role: &mut ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &ConnTx,
    ip: &str,
) {
    match msg {
        Message::Text(text) => {
            let text_str: &str = &text;
            if text_str.len() > MAX_TEXT_MESSAGE_SIZE {
                tracing::warn!(
                    ip = %ip,
                    size = text_str.len(),
                    max = MAX_TEXT_MESSAGE_SIZE,
                    "dropping oversized text message"
                );
                return;
            }
            match serde_json::from_str::<ControlMessage>(text_str) {
                Ok(ctrl_msg) => {
                    handle_control_message(&ctrl_msg, role, state, outbound_tx, ip).await;
                }
                Err(e) => {
                    tracing::warn!(ip = %ip, error = %e, "invalid JSON message");
                }
            }
        }
        Message::Binary(data) => {
            if data.len() > MAX_BINARY_MESSAGE_SIZE {
                tracing::warn!(
                    ip = %ip,
                    size = data.len(),
                    max = MAX_BINARY_MESSAGE_SIZE,
                    "dropping oversized binary message"
                );
                return;
            }
            handle_binary_message(&data, role, state, outbound_tx).await;
        }
        // Ping/Pong/Close are handled by the receive loop; nothing to do here.
        _ => {}
    }
}

async fn handle_control_message(
    msg: &ControlMessage,
    role: &mut ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &ConnTx,
    ip: &str,
) {
    match msg {
        ControlMessage::Hello { .. } => {
            // Client hello acknowledged (we already sent server hello)
        }

        ControlMessage::Ping => {
            let _ = outbound_tx.send(WsMessage::Text(
                serde_json::to_string(&ControlMessage::Pong).unwrap(),
            ));
        }

        ControlMessage::Pong => {
            // Pong received, handled by ping_misses reset
        }

        ControlMessage::Auth {
            username,
            password_hash,
            totp,
            device_token,
            desktop_key,
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
                password_hash.as_deref(),
                totp.as_deref(),
                device_token.as_deref(),
                desktop_key.as_deref(),
                role,
                state,
                outbound_tx,
                ip,
            )
            .await;
        }

        ControlMessage::DesktopRegister { capabilities, .. } => {
            if let ConnectionRole::Unauthenticated = role {
                // Must authenticate first
                return;
            }
            if let ConnectionRole::Client { username, .. } = role {
                let username = username.clone();
                match state
                    .broker
                    .register_desktop(&username, outbound_tx.clone(), capabilities.clone())
                    .await
                {
                    Ok(()) => {
                        *role = ConnectionRole::Desktop {
                            username: username.clone(),
                        };
                        let _ = outbound_tx
                            .send(WsMessage::Text(
                                serde_json::to_string(&ControlMessage::DesktopRegistered).unwrap(),
                            ));
                        // Reconcile the desktop's device UI AFTER the ack: the
                        // strict handshake requires `desktop_registered` to be
                        // the first frame, so the pending snapshot (pushed even
                        // when empty, to clear stale local state) must follow it.
                        state.broker.push_pending_devices_list(&username).await;
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
        ControlMessage::SessionSpawnRequest { .. }
        | ControlMessage::SessionCloseRequest { .. }
        | ControlMessage::PtyResize { .. } => {
            if let ConnectionRole::Client { username, .. } = role {
                let json = serde_json::to_string(msg).unwrap();
                let _ = state
                    .broker
                    .send_to_desktop(username, WsMessage::Text(json))
                    .await;
            }
        }

        // Client announces a file upload. The relay governs it (size / slot /
        // duplicate limits) before forwarding; a rejection is answered with a
        // relay-originated failure result to the sender only.
        ControlMessage::FileUploadBegin { upload_id, kind, size, .. } => {
            if let ConnectionRole::Client { username, .. } = role {
                // Bug reports are buffered and persisted at the relay, so they
                // carry a stricter size cap than the broker's generic limit.
                if kind == "bug_report" && *size > MAX_BUG_REPORT_UPLOAD_SIZE {
                    let fail = ControlMessage::FileUploadResult {
                        upload_id: upload_id.clone(),
                        ok: false,
                        path: None,
                        error: Some("file_too_large".into()),
                    };
                    let _ = outbound_tx
                        .send(WsMessage::Text(serde_json::to_string(&fail).unwrap()));
                    return;
                }
                match state
                    .broker
                    .begin_upload(username, upload_id, *size, outbound_tx)
                    .await
                {
                    Ok(()) => {
                        // Mark bug reports so their chunks are buffered for
                        // persistence; other kinds pass through untouched.
                        if kind == "bug_report" {
                            state
                                .broker
                                .mark_bug_report_upload(username, upload_id, outbound_tx)
                                .await;
                        }
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = state
                            .broker
                            .send_to_desktop(username, WsMessage::Text(json))
                            .await;
                    }
                    Err(reason) => {
                        let fail = ControlMessage::FileUploadResult {
                            upload_id: upload_id.clone(),
                            ok: false,
                            path: None,
                            error: Some(reason.to_string()),
                        };
                        let _ = outbound_tx.send(WsMessage::Text(
                            serde_json::to_string(&fail).unwrap(),
                        ));
                    }
                }
            }
            // The desktop publishes its OWN bug reports over this same governed
            // upload path (screenshot in binary chunks, not inline JSON — which
            // the 16KB text gate would drop). ONLY `bug_report` is accepted from
            // a desktop; this does not open a general desktop-upload capability.
            // Nothing is forwarded — the desktop is the endpoint.
            if let ConnectionRole::Desktop { username } = role {
                if kind != "bug_report" {
                    tracing::warn!("ignoring non-bug_report file_upload_begin from desktop");
                    return;
                }
                if *size > MAX_BUG_REPORT_UPLOAD_SIZE {
                    tracing::warn!(size = *size, "ignoring oversized desktop bug_report upload");
                    return;
                }
                match state.broker.begin_upload(username, upload_id, *size, outbound_tx).await {
                    Ok(()) => {
                        state
                            .broker
                            .mark_bug_report_upload(username, upload_id, outbound_tx)
                            .await;
                    }
                    Err(reason) => {
                        tracing::warn!(reason = %reason, "desktop bug_report upload rejected");
                    }
                }
            }
        }

        // Client signals the upload is complete: mark it finished in governance
        // state and forward to the desktop to finalize the write.
        ControlMessage::FileUploadEnd { upload_id, text } => {
            if let ConnectionRole::Client { username, device_id } = role {
                // Bug reports are persisted at the relay (DB row + screenshot)
                // before the normal pass-through. Persistence failures are
                // logged and never break the pass-through path.
                if let Some(screenshot) = state
                    .broker
                    .take_bug_report_buffer(username, upload_id, outbound_tx)
                    .await
                {
                    persist_bug_report(
                        state,
                        username,
                        device_id,
                        None,
                        text.as_deref().unwrap_or(""),
                        &screenshot,
                    );
                    // With no desktop to finalize and answer, the relay clears
                    // its governance entry and synthesizes the success result
                    // the client would otherwise wait forever for.
                    if !state.broker.is_desktop_online(username).await {
                        let _ = state.broker.resolve_upload(username, upload_id).await;
                        let ok = ControlMessage::FileUploadResult {
                            upload_id: upload_id.clone(),
                            ok: true,
                            path: None,
                            error: None,
                        };
                        let _ = outbound_tx
                            .send(WsMessage::Text(serde_json::to_string(&ok).unwrap()));
                        return;
                    }
                }
                state.broker.finish_upload(username, upload_id, outbound_tx).await;
                let json = serde_json::to_string(msg).unwrap();
                let _ = state
                    .broker
                    .send_to_desktop(username, WsMessage::Text(json))
                    .await;
            }
            // Finalize a desktop-originated bug_report: persist the buffered
            // screenshot + text, then clear governance. Fire-and-forget — no
            // FileUploadResult is routed back (the desktop doesn't await one),
            // and nothing is forwarded. A non-bug_report upload never opened a
            // governance entry, so `take` yields None and nothing persists.
            if let ConnectionRole::Desktop { username } = role {
                if let Some(screenshot) = state
                    .broker
                    .take_bug_report_buffer(username, upload_id, outbound_tx)
                    .await
                {
                    persist_bug_report(
                        state,
                        username,
                        "desktop",
                        Some("Desktop"),
                        text.as_deref().unwrap_or(""),
                        &screenshot,
                    );
                }
                let _ = state.broker.resolve_upload(username, upload_id).await;
            }
        }

        // Desktop reports an upload outcome: routed to the requesting client
        // connection only (clearing governance state). Unknown = client gone.
        ControlMessage::FileUploadResult { upload_id, .. } => {
            if let ConnectionRole::Desktop { username } = role {
                match state.broker.resolve_upload(username, upload_id).await {
                    Some(tx) => {
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = tx.send(WsMessage::Text(json));
                    }
                    None => {
                        tracing::debug!(
                            upload_id = %upload_id,
                            "file_upload_result for unknown upload; dropping"
                        );
                    }
                }
            }
        }

        // Client asks the desktop for a file it rendered in terminal output.
        // The relay registers ownership and enforces the active-download cap
        // before forwarding; a cap rejection is answered with a relay-originated
        // failure end to the requester only. Ignored from a desktop.
        ControlMessage::FileDownloadRequest { download_id, .. } => {
            if let ConnectionRole::Client { username, .. } = role {
                match state
                    .broker
                    .register_download(username, download_id, outbound_tx)
                    .await
                {
                    Ok(()) => {
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = state
                            .broker
                            .send_to_desktop(username, WsMessage::Text(json))
                            .await;
                    }
                    Err(reason) => {
                        let fail = ControlMessage::FileDownloadEnd {
                            download_id: download_id.clone(),
                            ok: false,
                            error: Some(reason.to_string()),
                        };
                        let _ = outbound_tx.send(WsMessage::Text(
                            serde_json::to_string(&fail).unwrap(),
                        ));
                    }
                }
            }
        }

        // Desktop announces the file stream: routed to the requesting client
        // connection ONLY, recording the declared size for chunk budgeting.
        // Unknown download_id → drop + warn. Ignored from a client.
        ControlMessage::FileDownloadBegin { download_id, size, .. } => {
            if let ConnectionRole::Desktop { username } = role {
                match state.broker.note_download_begin(username, download_id, *size).await {
                    Some(tx) => {
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = tx.send(WsMessage::Text(json));
                    }
                    None => {
                        tracing::warn!(
                            download_id = %download_id,
                            "file_download_begin for unknown download; dropping"
                        );
                    }
                }
            }
        }

        // Desktop reports the download outcome (success or failure): routed to
        // the requesting client connection ONLY, clearing governance state.
        // Unknown download_id → drop + warn. Ignored from a client.
        ControlMessage::FileDownloadEnd { download_id, .. } => {
            if let ConnectionRole::Desktop { username } = role {
                match state.broker.resolve_download(username, download_id).await {
                    Some(tx) => {
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = tx.send(WsMessage::Text(json));
                    }
                    None => {
                        tracing::warn!(
                            download_id = %download_id,
                            "file_download_end for unknown download; dropping"
                        );
                    }
                }
            }
        }

        // Client → relay only: scope live PTY output to the session(s) this
        // client is viewing. Never forwarded to the desktop.
        ControlMessage::SessionFocus { session_ids } => {
            if matches!(role, ConnectionRole::Client { .. }) {
                outbound_tx.set_focus(session_ids.clone());
            }
        }

        // List requests are queued so the desktop's reply burst (replay_begin
        // + scrollback + session_list) can be routed back to the requester
        // only, instead of resetting every connected client's terminal.
        ControlMessage::SessionListRequest => {
            if let ConnectionRole::Client { username, device_id } = role {
                state
                    .broker
                    .note_session_list_request(username, device_id, outbound_tx)
                    .await;
                let json = serde_json::to_string(msg).unwrap();
                let _ = state
                    .broker
                    .send_to_desktop(username, WsMessage::Text(json))
                    .await;
            }
        }

        // Desktop announces the start of a replay burst. Consumed here —
        // never forwarded.
        ControlMessage::ReplayBegin => {
            if let ConnectionRole::Desktop { username } = role {
                state.broker.begin_replay(username).await;
            }
        }

        // Client supervisor query. Routed per the wire contract: desktop-offline
        // fast-fail, stored-result replay, in-flight re-own, cap reject, else
        // forward VERBATIM. `kind` is NEVER inspected by the relay.
        ControlMessage::SupervisorQuery { id, .. } => {
            if let ConnectionRole::Client { username, .. } = role {
                // Step 1: desktop offline → synthesize error, no entry, no forward.
                if !state.broker.is_desktop_online(username).await {
                    let err = ControlMessage::SupervisorError {
                        id: id.clone(),
                        message: "desktop offline".into(),
                    };
                    let _ = outbound_tx
                        .send(WsMessage::Text(serde_json::to_string(&err).unwrap()));
                    return;
                }
                match state
                    .broker
                    .begin_supervisor_query(username, id, outbound_tx)
                    .await
                {
                    // Steps 2/3: stored replay or in-flight re-own — no forward.
                    SupervisorQueryDecision::Replay(stored) => {
                        let _ = outbound_tx.send(WsMessage::Text(stored));
                    }
                    SupervisorQueryDecision::Reowned => {}
                    // Step 4: over the pending cap.
                    SupervisorQueryDecision::Capacity => {
                        let err = ControlMessage::SupervisorError {
                            id: id.clone(),
                            message: "too many pending supervisor queries".into(),
                        };
                        let _ = outbound_tx
                            .send(WsMessage::Text(serde_json::to_string(&err).unwrap()));
                    }
                    // Step 5: forward the query unchanged to the desktop.
                    SupervisorQueryDecision::Forward => {
                        let json = serde_json::to_string(msg).unwrap();
                        let _ = state
                            .broker
                            .send_to_desktop(username, WsMessage::Text(json))
                            .await;
                    }
                }
            }
        }

        // Desktop supervisor reply: resolved to the requesting connection ONLY.
        // Unknown id → drop + debug. Owner gone → parked for redelivery. Never
        // broadcast.
        ControlMessage::SupervisorResult { id, .. }
        | ControlMessage::SupervisorError { id, .. } => {
            if let ConnectionRole::Desktop { username } = role {
                let json = serde_json::to_string(msg).unwrap();
                if let SupervisorResolveOutcome::Unknown = state
                    .broker
                    .resolve_supervisor(username, id, WsMessage::Text(json))
                    .await
                {
                    tracing::debug!(
                        id = %id,
                        "supervisor reply for unknown id; dropping"
                    );
                }
            }
        }

        // Bidirectional: client renames forward to desktop, desktop renames broadcast to clients
        ControlMessage::SessionRenamed { .. } => {
            let json = serde_json::to_string(msg).unwrap();
            match role {
                ConnectionRole::Client { username, .. } => {
                    let _ = state
                        .broker
                        .send_to_desktop(username, WsMessage::Text(json))
                        .await;
                }
                ConnectionRole::Desktop { username } => {
                    state
                        .broker
                        .broadcast_to_clients(username, WsMessage::Text(json))
                        .await;
                }
                _ => {}
            }
        }

        // Desktop -> Client(s) forwarding
        ControlMessage::SessionCreated { .. }
        | ControlMessage::SessionClosed { .. }
        | ControlMessage::ContextUpdate { .. }
        | ControlMessage::AccountUsage { .. }
        | ControlMessage::PtyResized { .. } => {
            if let ConnectionRole::Desktop { username } = role {
                let json = serde_json::to_string(msg).unwrap();
                state
                    .broker
                    .broadcast_to_clients(username, WsMessage::Text(json))
                    .await;
            }
        }

        // A session_list terminates a replay burst: routed to the requester
        // when the desktop tagged the burst (replay_begin), broadcast for old
        // desktops that don't.
        ControlMessage::SessionList { .. } => {
            if let ConnectionRole::Desktop { username } = role {
                let json = serde_json::to_string(msg).unwrap();
                match state.broker.end_replay(username).await {
                    Some(tx) => {
                        let _ = tx.send(WsMessage::Text(json));
                    }
                    None => {
                        state
                            .broker
                            .broadcast_to_clients(username, WsMessage::Text(json))
                            .await;
                    }
                }
            }
        }

        // Desktop -> Client(s) + Web Push fan-out
        ControlMessage::SessionNotification {
            session_id,
            title,
            body,
        } => {
            if let ConnectionRole::Desktop { username } = role {
                // Clamp: titles come from arbitrary session renames, and an
                // oversized payload breaks the single-record 4KB push framing.
                let title: String = title.chars().take(120).collect();
                let body: String = body.chars().take(300).collect();

                let clamped = ControlMessage::SessionNotification {
                    session_id: session_id.clone(),
                    title: title.clone(),
                    body: body.clone(),
                };
                state
                    .broker
                    .broadcast_to_clients(
                        username,
                        WsMessage::Text(serde_json::to_string(&clamped).unwrap()),
                    )
                    .await;

                // Fan out web push off the desktop's read loop: HTTP round
                // trips to push services must never stall PTY forwarding.
                let payload = serde_json::json!({
                    "sessionId": session_id,
                    "title": title,
                    "body": body,
                });
                let state = state.clone();
                let username = username.clone();
                tokio::spawn(async move {
                    state.push.send_to_user(&username, &payload).await;
                });
            }
        }

        // --- Web push registration (clients only) ---
        ControlMessage::PushSubscribe { subscription } => {
            if let ConnectionRole::Client {
                username,
                device_id,
            } = role
            {
                // The desktop authenticates with the synthetic "desktop" device
                // id, which has no row in the devices table — skip it.
                if device_id == "desktop" {
                    return;
                }
                let endpoint_ok = subscription
                    .get("endpoint")
                    .and_then(|e| e.as_str())
                    .map(crate::push::is_valid_push_endpoint)
                    .unwrap_or(false);
                if !endpoint_ok {
                    tracing::warn!(device_id = %device_id, "rejecting push subscription with invalid endpoint");
                    return;
                }
                match serde_json::to_string(subscription) {
                    Ok(json) if json.len() <= 4096 => {
                        if let Err(e) =
                            state
                                .auth
                                .db()
                                .upsert_push_subscription(device_id, username, &json)
                        {
                            tracing::error!(error = %e, "failed to store push subscription");
                        }
                    }
                    Ok(_) => {
                        tracing::warn!(device_id = %device_id, "rejecting oversized push subscription");
                    }
                    Err(_) => {}
                }
            }
        }

        ControlMessage::PushUnsubscribe => {
            if let ConnectionRole::Client { device_id, .. } = role {
                let _ = state.auth.db().remove_push_subscription(device_id);
            }
        }

        ControlMessage::VapidKeyRequest => {
            if !matches!(role, ConnectionRole::Unauthenticated) {
                let reply = ControlMessage::VapidPublicKey {
                    key: state.push.public_key().to_string(),
                };
                let _ = outbound_tx
                    .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()));
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
                            .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));

                        // Register with broker so desktopâ†’client messages flow
                        // while the client re-auths to promote its server-side role.
                        let info = ClientInfo {
                            device_id: pending.device_id.clone(),
                            device_name: pending.device_name.clone(),
                            ip: pending.ip.clone(),
                            connected_at: chrono::Utc::now().to_rfc3339(),
                        };
                        let _ = state
                            .broker
                            .register_client(username, pending.client_tx.clone(), info)
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
                    // Reconcile the desktop: the approved entry is gone from the
                    // pending set, so push the fresh list to clear its card.
                    state.broker.push_pending_devices_list(username).await;
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
                        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));
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
                    // Reconcile the desktop: clear the rejected entry's card.
                    state.broker.push_pending_devices_list(username).await;
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
                    .send(WsMessage::Text(serde_json::to_string(&msg).unwrap()));
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
                state.broker.unregister_device(username, device_id).await;
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
                    .send(WsMessage::Text(serde_json::to_string(&revoked_msg).unwrap()));
            }
        }

        _ => {
            tracing::debug!("unhandled control message");
        }
    }
}

async fn handle_auth(
    username: &str,
    password_hash: Option<&str>,
    totp: Option<&str>,
    device_token: Option<&str>,
    desktop_key: Option<&str>,
    role: &mut ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &ConnTx,
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
            .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));
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

    // --- Desktop bootstrap: a provisioned desktop key authorizes the host
    // directly, bypassing password / TOTP / device-approval. The key is the
    // desktop's durable credential, so it can never sit in the approval queue. ---
    if let Some(key) = desktop_key {
        if state.auth.verify_desktop_key(username, key).unwrap_or(false) {
            state.auth.clear_rate_limit(username);
            let result = ControlMessage::AuthResult {
                success: true,
                token: None,
                device_id: Some("desktop".into()),
                error: None,
                retry_after: None,
            };
            let _ = outbound_tx
                .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));
            *role = ConnectionRole::Client {
                username: username.to_string(),
                device_id: "desktop".to_string(),
            };
            audit::log_audit(
                state.auth.db(),
                AuditEvent::AuthSuccess,
                Some(username),
                None,
                Some(ip),
                Some("desktop key"),
            );
        } else {
            state.auth.record_failure(username);
            send_auth_error(outbound_tx, "invalid_credentials").await;
            audit::log_audit(
                state.auth.db(),
                AuditEvent::AuthFailure,
                Some(username),
                None,
                Some(ip),
                Some("bad desktop key"),
            );
        }
        return;
    }

    // --- Returning device: a valid device token short-circuits BEFORE the
    // password / TOTP gates so approved clients reconnect silently. The token
    // is a standalone credential; TOTP already gated its enrollment. ---
    if let Some(token) = device_token {
        match state.auth.validate_jwt(token) {
            Ok(claims) if claims.sub == username => {
                if device::is_device_registered(state.auth.db(), &claims.device_id, username) {
                    state.auth.clear_rate_limit(username);
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
                        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));
                    let dev_id = claims.device_id;
                    *role = ConnectionRole::Client {
                        username: username.to_string(),
                        device_id: dev_id.clone(),
                    };
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
                // Device was revoked — fall through to full credential auth.
            }
            _ => {
                // Invalid/expired token — fall through to full credential auth.
            }
        }
    }

    // --- Password (required for credential-based client auth) ---
    let password_hash = match password_hash {
        Some(h) => h,
        None => {
            send_auth_error(outbound_tx, "invalid_credentials").await;
            return;
        }
    };

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
                    send_auth_error(outbound_tx, "invalid_totp").await;
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
    let requested_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    state
        .broker
        .add_pending_device(
            username,
            PendingDevice {
                device_id: device_id.clone(),
                device_name: device_name.to_string(),
                ip: ip.to_string(),
                client_tx: outbound_tx.clone(),
                created: std::time::Instant::now(),
                requested_at,
            },
        )
        .await;
    // Reconcile the desktop with the new entry (also reaches desktops that
    // missed the one-shot device_pending push, e.g. a reconnect race).
    state.broker.push_pending_devices_list(username).await;

    // Park the connection as PendingApproval — carrying the account + device_id
    // so a disconnect before approval can garbage-collect this pending entry.
    // The auth_result is sent when the desktop approves/rejects.
    *role = ConnectionRole::PendingApproval {
        username: username.to_string(),
        device_id,
    };
}

async fn handle_binary_message(
    data: &[u8],
    role: &ConnectionRole,
    state: &Arc<AppState>,
    outbound_tx: &ConnTx,
) {
    match protocol::parse_binary_frame(data) {
        Ok((frame_type, upload_id, payload)) => match role {
            ConnectionRole::Client { username, .. } => {
                if frame_type == protocol::PTY_INPUT {
                    let _ = state
                        .broker
                        .send_to_desktop(username, WsMessage::Binary(data.to_vec()))
                        .await;
                } else if frame_type == protocol::PTY_FILE_CHUNK {
                    // Governed forward: only chunks of an active, owned upload
                    // that stays within budget reach the desktop.
                    use crate::broker::ChunkDecision;
                    match state
                        .broker
                        .record_upload_chunk(username, &upload_id, outbound_tx, payload)
                        .await
                    {
                        ChunkDecision::Forward => {
                            let _ = state
                                .broker
                                .send_to_desktop(username, WsMessage::Binary(data.to_vec()))
                                .await;
                        }
                        ChunkDecision::Overrun => {
                            let fail = ControlMessage::FileUploadResult {
                                upload_id: upload_id.clone(),
                                ok: false,
                                path: None,
                                error: Some("size_exceeded".into()),
                            };
                            let _ = outbound_tx.send(WsMessage::Text(
                                serde_json::to_string(&fail).unwrap(),
                            ));
                        }
                        ChunkDecision::Drop => {}
                    }
                }
            }
            ConnectionRole::Desktop { username } => {
                if frame_type == protocol::PTY_FILE_CHUNK {
                    // Chunks of a desktop-originated bug_report upload: buffered
                    // within budget for persistence, never forwarded (the
                    // desktop is the endpoint). Chunks with no governance entry
                    // (e.g. a rejected non-bug_report upload) simply Drop.
                    use crate::broker::ChunkDecision;
                    match state
                        .broker
                        .record_upload_chunk(username, &upload_id, outbound_tx, payload)
                        .await
                    {
                        ChunkDecision::Overrun => {
                            tracing::warn!("desktop bug_report upload overran budget; severed");
                        }
                        ChunkDecision::Forward | ChunkDecision::Drop => {}
                    }
                } else if frame_type == protocol::PTY_FILE_DOWNLOAD_CHUNK {
                    // Chunks of a desktop→client download: routed to the
                    // requesting client connection ONLY, within the download's
                    // byte budget. Unknown/severed download_id → drop; an
                    // overrun severs the download and sends a relay-originated
                    // failure end to the owner.
                    use crate::broker::DownloadChunkDecision;
                    match state
                        .broker
                        .record_download_chunk(username, &upload_id, payload)
                        .await
                    {
                        DownloadChunkDecision::Forward(tx) => {
                            let _ = tx.send(WsMessage::Binary(data.to_vec()));
                        }
                        DownloadChunkDecision::Overrun(tx) => {
                            let fail = ControlMessage::FileDownloadEnd {
                                download_id: upload_id.clone(),
                                ok: false,
                                error: Some("size_exceeded".into()),
                            };
                            let _ = tx.send(WsMessage::Text(
                                serde_json::to_string(&fail).unwrap(),
                            ));
                        }
                        DownloadChunkDecision::Drop => {}
                    }
                } else if frame_type == protocol::PTY_OUTPUT {
                    state
                        .broker
                        .broadcast_to_clients(username, WsMessage::Binary(data.to_vec()))
                        .await;
                } else if frame_type == protocol::PTY_SCROLLBACK {
                    // Replay frames go to the client whose list request
                    // started this burst (replay_begin); broadcast only for
                    // old desktops that don't tag bursts.
                    match state.broker.replay_target(username).await {
                        Some(tx) => {
                            let _ = tx.send(WsMessage::Binary(data.to_vec()));
                        }
                        None => {
                            state
                                .broker
                                .broadcast_to_clients(username, WsMessage::Binary(data.to_vec()))
                                .await;
                        }
                    }
                }
            }
            // Parked-for-approval and unauthenticated connections send no
            // binary traffic; ignore any that arrives.
            ConnectionRole::PendingApproval { .. } | ConnectionRole::Unauthenticated => {}
        },
        Err(e) => {
            tracing::warn!(error = %e, "invalid binary frame");
        }
    }
}

/// Persist a bug report at the relay: write the screenshot (if any) under
/// `<data_dir>/bug-reports/` and insert a DB row attributed to the submitting
/// connection. When `device_name` is `Some`, it is stored verbatim (desktop
/// publish path, which has no devices row); when `None`, the name is resolved
/// from the devices table (client upload path). All errors are logged and
/// swallowed — persistence must never break the upload pass-through.
fn persist_bug_report(
    state: &Arc<AppState>,
    username: &str,
    device_id: &str,
    device_name: Option<&str>,
    text: &str,
    screenshot: &[u8],
) {
    let screenshot_path = if screenshot.is_empty() {
        None
    } else {
        let dir = state.data_dir.join("bug-reports");
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                let path = dir.join(format!("{}.png", uuid::Uuid::new_v4()));
                match std::fs::write(&path, screenshot) {
                    Ok(()) => Some(path.to_string_lossy().into_owned()),
                    Err(e) => {
                        tracing::error!(error = %e, "failed to write bug report screenshot");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to create bug-reports directory");
                None
            }
        }
    };

    // app_version is not carried on the file-upload protocol (the desktop
    // publish path reuses the same FileUploadEnd, which has no such field), so
    // it is stored NULL for both paths. device_name None → resolve from the
    // devices table (client path); Some → store verbatim (desktop path).
    let result = match device_name {
        Some(name) => state.auth.db().insert_bug_report_with_device_name(
            username,
            device_id,
            Some(name),
            text,
            screenshot_path.as_deref(),
            None,
        ),
        None => state.auth.db().insert_bug_report(
            username,
            device_id,
            text,
            screenshot_path.as_deref(),
            None,
        ),
    };
    if let Err(e) = result {
        tracing::error!(error = %e, "failed to persist bug report");
    }
}

async fn send_auth_error(tx: &ConnTx, error: &str) {
    let result = ControlMessage::AuthResult {
        success: false,
        token: None,
        device_id: None,
        error: Some(error.to_string()),
        retry_after: None,
    };
    let _ = tx
        .send(WsMessage::Text(serde_json::to_string(&result).unwrap()));
}

/// TcpListener wrapper that sets TCP_NODELAY on every accepted connection.
/// Keystroke frames are ~38 bytes; Nagle coalescing adds visible typing latency.
struct NoDelayListener(tokio::net::TcpListener);

impl axum::serve::Listener for NoDelayListener {
    type Io = tokio::net::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, addr)) => {
                    let _ = stream.set_nodelay(true);
                    return (stream, addr);
                }
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

/// Peer address pulled from NoDelayListener streams (orphan rules prevent
/// implementing Connected directly for SocketAddr with a custom listener).
#[derive(Clone, Copy, Debug)]
pub struct ClientAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, NoDelayListener>>
    for ClientAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, NoDelayListener>) -> Self {
        ClientAddr(*stream.remote_addr())
    }
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

    // Periodic sweep: expire pending device approvals older than the TTL so a
    // never-approved request can't linger in relay memory or the desktop UI
    // forever. Mirrors the lazy GC used for uploads/downloads/supervisor, but
    // pending entries have no per-message trigger (the waiting client is idle),
    // so the sweep runs on its own interval.
    {
        let gc_state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            // Skip the immediate first tick (nothing is stale at startup).
            tick.tick().await;
            loop {
                tick.tick().await;
                let expired = gc_state.broker.gc_pending_devices().await;
                let mut changed: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for (username, pending) in expired {
                    // Fail the waiting client (mirrors the reject path's
                    // client_tx notification) and roll back its device row.
                    let result = ControlMessage::AuthResult {
                        success: false,
                        token: None,
                        device_id: None,
                        error: Some("approval_timeout".into()),
                        retry_after: None,
                    };
                    let _ = pending.client_tx.send(WsMessage::Text(
                        serde_json::to_string(&result).unwrap(),
                    ));
                    let _ = device::revoke_device(gc_state.auth.db(), &pending.device_id);
                    audit::log_audit(
                        gc_state.auth.db(),
                        AuditEvent::DeviceRejected,
                        Some(&username),
                        Some(&pending.device_id),
                        Some(&pending.ip),
                        Some("approval_timeout"),
                    );
                    changed.insert(username);
                }
                for username in changed {
                    gc_state.broker.push_pending_devices_list(&username).await;
                }
            }
        });
    }

    tracing::info!("relay listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        NoDelayListener(listener),
        app.into_make_service_with_connect_info::<ClientAddr>(),
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

    // --- File upload routing / role-gating ---

    fn test_state() -> Arc<AppState> {
        let db = crate::db::Database::open_in_memory().unwrap();
        let push = PushManager::init(db.clone()).unwrap();
        let auth = AuthManager::new(db).unwrap();
        let data_dir = std::env::temp_dir().join(format!("cc-relay-test-{}", uuid::Uuid::new_v4()));
        Arc::new(AppState::new(Broker::new(), auth, push, data_dir))
    }

    fn test_conn() -> (ConnTx, mpsc::UnboundedReceiver<WsMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            ConnTx::new(tx, Arc::new(std::sync::atomic::AtomicUsize::new(0))),
            rx,
        )
    }

    /// Drain the reconciliation frames the broker pushes to a freshly-registered
    /// desktop (an empty `pending_devices_list`, plus any `connected_devices_list`),
    /// so a test can assert on the message it actually exercises. Called right
    /// after `register_desktop`, before the action under test enqueues anything.
    fn drain_reconcile(rx: &mut mpsc::UnboundedReceiver<WsMessage>) {
        while let Ok(WsMessage::Text(t)) = rx.try_recv() {
            if !(t.contains("pending_devices_list") || t.contains("connected_devices_list")) {
                break;
            }
        }
    }

    fn client_role() -> ConnectionRole {
        ConnectionRole::Client {
            username: "alice".into(),
            device_id: "dev-1".into(),
        }
    }

    fn upload_frame(payload: &[u8]) -> (String, Vec<u8>) {
        let upload_id = "u".repeat(36);
        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, payload);
        (upload_id, frame)
    }

    #[tokio::test]
    async fn test_unauthenticated_file_chunk_dropped() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let (_id, frame) = upload_frame(b"data");
        handle_binary_message(&frame, &ConnectionRole::Unauthenticated, &state, &ctx).await;
        assert!(drx.try_recv().is_err(), "unauthenticated chunk must not forward");
    }

    #[tokio::test]
    async fn test_client_file_chunk_forwarded_after_begin() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let (upload_id, frame) = upload_frame(b"filedata");
        state.broker.begin_upload("alice", &upload_id, 4096, &ctx).await.unwrap();

        handle_binary_message(&frame, &client_role(), &state, &ctx).await;
        match drx.recv().await.unwrap() {
            WsMessage::Binary(b) => assert_eq!(b, frame),
            _ => panic!("expected binary forward to desktop"),
        }
    }

    #[tokio::test]
    async fn test_client_file_chunk_without_begin_not_forwarded() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let (_id, frame) = upload_frame(b"x");
        handle_binary_message(&frame, &client_role(), &state, &ctx).await;
        assert!(drx.try_recv().is_err(), "chunk without begin must not forward");
    }

    #[tokio::test]
    async fn test_client_file_chunk_overrun_sends_failure_and_severs() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, mut crx) = test_conn();
        let (upload_id, frame) = upload_frame(b"way-too-long");
        // Declared size smaller than the payload → overrun on first chunk.
        state.broker.begin_upload("alice", &upload_id, 4, &ctx).await.unwrap();

        handle_binary_message(&frame, &client_role(), &state, &ctx).await;
        // Not forwarded to the desktop.
        assert!(drx.try_recv().is_err());
        // Sender gets a relay-originated failure result.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_upload_result"));
                assert!(t.contains("size_exceeded"));
            }
            _ => panic!("expected failure result"),
        }
    }

    // --- File download routing / role-gating ---

    fn download_frame(payload: &[u8]) -> (String, Vec<u8>) {
        let download_id = "d".repeat(36);
        let frame =
            protocol::build_binary_frame(protocol::PTY_FILE_DOWNLOAD_CHUNK, &download_id, payload);
        (download_id, frame)
    }

    fn info_for(device_id: &str) -> ClientInfo {
        ClientInfo {
            device_id: device_id.into(),
            device_name: "Device".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        }
    }

    #[tokio::test]
    async fn test_client_download_request_registers_and_forwards() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let mut role = client_role();
        let req = ControlMessage::FileDownloadRequest {
            download_id: "d1".into(),
            session_id: "s1".into(),
            path: "/home/sean/a.md".into(),
        };
        handle_control_message(&req, &mut role, &state, &ctx, "1.2.3.4").await;
        // Forwarded verbatim to the desktop.
        match drx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_download_request"));
                assert!(t.contains("\"download_id\":\"d1\""));
            }
            _ => panic!("expected request forwarded to desktop"),
        }
    }

    // Regression: the desktop handshake is strict — after `desktop_register`
    // the very NEXT text frame must be `desktop_registered`, or the client
    // aborts and reconnects in a loop. Queuing the pending-device snapshot
    // before the ack (the old bug) caused a production reconnect storm.
    #[tokio::test]
    async fn test_desktop_register_acks_before_pending_snapshot() {
        let state = test_state();
        // A pending device exists so the snapshot is non-empty and unmistakable.
        state
            .broker
            .add_pending_device(
                "alice",
                PendingDevice {
                    device_id: "pending-1".into(),
                    device_name: "New Phone".into(),
                    ip: "1.2.3.4".into(),
                    client_tx: {
                        let (c, _r) = test_conn();
                        c
                    },
                    created: std::time::Instant::now(),
                    requested_at: 42,
                },
            )
            .await;

        // The registering connection is authenticated as a Client (a desktop-key
        // connection sets the Client role, then upgrades via desktop_register).
        let (dtx, mut drx) = test_conn();
        let mut role = ConnectionRole::Client {
            username: "alice".into(),
            device_id: "desktop".into(),
        };
        let req = ControlMessage::DesktopRegister {
            version: 1,
            capabilities: None,
        };
        handle_control_message(&req, &mut role, &state, &dtx, "1.2.3.4").await;

        // First frame MUST be desktop_registered.
        match drx.try_recv().expect("expected an ack frame") {
            WsMessage::Text(t) => assert!(
                t.contains("desktop_registered"),
                "first frame must be desktop_registered, got: {t}"
            ),
            other => panic!("expected text ack, got {other:?}"),
        }
        // The pending snapshot follows AFTER the ack.
        match drx.try_recv().expect("expected a pending snapshot frame") {
            WsMessage::Text(t) => {
                assert!(t.contains("pending_devices_list"), "got: {t}");
                assert!(t.contains("pending-1"), "snapshot must carry the entry: {t}");
            }
            other => panic!("expected pending snapshot text, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_client_download_request_cap_rejection_replies_to_client_only() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, mut crx) = test_conn();
        let mut role = client_role();
        // Fill the active-download cap (MAX_ACTIVE_DOWNLOADS = 4).
        for i in 0..4 {
            state
                .broker
                .register_download("alice", &format!("pre{i}"), &ctx)
                .await
                .unwrap();
        }
        let req = ControlMessage::FileDownloadRequest {
            download_id: "d-extra".into(),
            session_id: "s1".into(),
            path: "/x".into(),
        };
        handle_control_message(&req, &mut role, &state, &ctx, "1.2.3.4").await;
        // Over the cap: nothing reaches the desktop.
        assert!(drx.try_recv().is_err());
        // The requester gets a relay-originated failure end.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_download_end"));
                assert!(t.contains("\"ok\":false"));
                assert!(t.contains("too many active downloads"));
            }
            _ => panic!("expected failure end"),
        }
    }

    #[tokio::test]
    async fn test_desktop_download_begin_end_route_to_owner_only() {
        let state = test_state();
        let (dtx, _drx) = test_conn();
        let (ctx, mut crx) = test_conn();
        let (other, mut orx) = test_conn();
        state.broker.register_client("alice", ctx.clone(), info_for("dev-1")).await.unwrap();
        state.broker.register_client("alice", other.clone(), info_for("dev-2")).await.unwrap();
        state.broker.register_download("alice", "d1", &ctx).await.unwrap();

        let mut drole = desktop_role();
        let begin = ControlMessage::FileDownloadBegin {
            download_id: "d1".into(),
            name: "a.md".into(),
            size: 16,
            mime: "text/markdown".into(),
        };
        handle_control_message(&begin, &mut drole, &state, &dtx, "1.2.3.4").await;
        // Owner receives the begin; the other client does not.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => assert!(t.contains("file_download_begin")),
            _ => panic!("expected begin to owner"),
        }
        assert!(orx.try_recv().is_err(), "begin must not reach non-owner");

        let end = ControlMessage::FileDownloadEnd {
            download_id: "d1".into(),
            ok: true,
            error: None,
        };
        handle_control_message(&end, &mut drole, &state, &dtx, "1.2.3.4").await;
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => assert!(t.contains("file_download_end")),
            _ => panic!("expected end to owner"),
        }
        assert!(orx.try_recv().is_err(), "end must not reach non-owner");
    }

    #[tokio::test]
    async fn test_desktop_download_begin_unknown_id_dropped() {
        let state = test_state();
        let (dtx, _drx) = test_conn();
        let mut drole = desktop_role();
        let begin = ControlMessage::FileDownloadBegin {
            download_id: "ghost".into(),
            name: "a".into(),
            size: 1,
            mime: "application/octet-stream".into(),
        };
        // No panic, nothing to route — the unknown id is dropped with a warn.
        handle_control_message(&begin, &mut drole, &state, &dtx, "1.2.3.4").await;
    }

    #[tokio::test]
    async fn test_desktop_download_chunk_routes_to_owner() {
        let state = test_state();
        let (dtx, _drx) = test_conn();
        let (ctx, mut crx) = test_conn();
        let (id, frame) = download_frame(b"filedata");
        state.broker.register_download("alice", &id, &ctx).await.unwrap();
        state.broker.note_download_begin("alice", &id, 4096).await.unwrap();

        handle_binary_message(&frame, &desktop_role(), &state, &dtx).await;
        match crx.recv().await.unwrap() {
            WsMessage::Binary(b) => assert_eq!(b, frame),
            _ => panic!("expected chunk routed to owner"),
        }
    }

    #[tokio::test]
    async fn test_desktop_download_chunk_overrun_sends_failure_to_owner() {
        let state = test_state();
        let (dtx, _drx) = test_conn();
        let (ctx, mut crx) = test_conn();
        let (id, frame) = download_frame(b"way-too-long");
        state.broker.register_download("alice", &id, &ctx).await.unwrap();
        // Declared size smaller than the payload → overrun on first chunk.
        state.broker.note_download_begin("alice", &id, 4).await.unwrap();

        handle_binary_message(&frame, &desktop_role(), &state, &dtx).await;
        // Owner gets a relay-originated failure end, not the chunk bytes.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_download_end"));
                assert!(t.contains("size_exceeded"));
            }
            _ => panic!("expected failure end to owner"),
        }
    }

    #[tokio::test]
    async fn test_client_download_chunk_ignored() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);
        let (ctx, _crx) = test_conn();
        let (_id, frame) = download_frame(b"data");
        // A download chunk from a client role is not forwarded anywhere.
        handle_binary_message(&frame, &client_role(), &state, &ctx).await;
        assert!(drx.try_recv().is_err(), "client download chunk must not forward");
    }

    #[tokio::test]
    async fn test_file_upload_begin_oversize_rejected_with_result() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, mut crx) = test_conn();
        let mut role = client_role();
        let begin = ControlMessage::FileUploadBegin {
            upload_id: "u1".into(),
            kind: "file".into(),
            name: "big.bin".into(),
            size: 26 * 1024 * 1024,
            mime: "application/octet-stream".into(),
            session_id: None,
        };
        handle_control_message(&begin, &mut role, &state, &ctx, "1.2.3.4").await;

        // Rejected: nothing reaches the desktop.
        assert!(drx.try_recv().is_err());
        // Sender gets a failure result.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_upload_result"));
                assert!(t.contains("file_too_large"));
            }
            _ => panic!("expected failure result"),
        }
    }

    #[tokio::test]
    async fn test_file_upload_result_routed_to_owner_only() {
        let state = test_state();
        let (owner, mut orx) = test_conn();
        let (other, mut xrx) = test_conn();
        let info = |dev: &str| ClientInfo {
            device_id: dev.into(),
            device_name: "d".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        state.broker.register_client("alice", owner.clone(), info("dev-1")).await.unwrap();
        state.broker.register_client("alice", other.clone(), info("dev-2")).await.unwrap();

        let (dtx, _drx) = test_conn();
        state.broker.register_desktop("alice", dtx.clone(), None).await.unwrap();
        // Drain the desktop-online broadcast both clients received.
        let _ = orx.try_recv();
        let _ = xrx.try_recv();

        let upload_id = "u".repeat(36);
        state.broker.begin_upload("alice", &upload_id, 4096, &owner).await.unwrap();

        let mut role = ConnectionRole::Desktop { username: "alice".into() };
        let result = ControlMessage::FileUploadResult {
            upload_id: upload_id.clone(),
            ok: true,
            path: Some("/tmp/big.bin".into()),
            error: None,
        };
        handle_control_message(&result, &mut role, &state, &dtx, "1.2.3.4").await;

        match orx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_upload_result"));
                assert!(t.contains("\"ok\":true"));
            }
            _ => panic!("expected result on owner"),
        }
        assert!(xrx.try_recv().is_err(), "non-owner must not receive the result");
    }

    // --- Bug report persistence (BR-P1) ---

    /// A bug_report upload persists a DB row + screenshot file with the correct
    /// attribution, and still forwards to the desktop (dual-write).
    #[tokio::test]
    async fn test_bug_report_persists_row_and_file() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        state.auth.db().add_device("dev-1", "alice", "Pixel 9", Some("1.2.3.4")).unwrap();

        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let mut role = client_role();

        let upload_id = "b".repeat(36);
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.clone(),
            kind: "bug_report".into(),
            name: "screenshot.png".into(),
            size: 4,
            mime: "image/png".into(),
            session_id: None,
        };
        handle_control_message(&begin, &mut role, &state, &ctx, "1.2.3.4").await;
        assert!(matches!(drx.recv().await.unwrap(), WsMessage::Text(_)), "begin forwarded");

        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, b"\x89PNG");
        handle_binary_message(&frame, &role, &state, &ctx).await;
        assert!(matches!(drx.recv().await.unwrap(), WsMessage::Binary(_)), "chunk forwarded (dual-write)");

        let end = ControlMessage::FileUploadEnd {
            upload_id: upload_id.clone(),
            text: Some("app crashed".into()),
        };
        handle_control_message(&end, &mut role, &state, &ctx, "1.2.3.4").await;
        assert!(matches!(drx.recv().await.unwrap(), WsMessage::Text(_)), "end forwarded (desktop online)");

        let rows = state.auth.db().list_bug_reports_for_test();
        assert_eq!(rows.len(), 1);
        let (username, device_id, device_name, text, screenshot_path, version) = &rows[0];
        assert_eq!(username, "alice");
        assert_eq!(device_id, "dev-1");
        assert_eq!(device_name.as_deref(), Some("Pixel 9"));
        assert_eq!(text, "app crashed");
        assert!(version.is_none());

        let path = screenshot_path.as_ref().expect("screenshot path recorded");
        assert_eq!(std::fs::read(path).unwrap(), b"\x89PNG");
        let _ = std::fs::remove_file(path);
    }

    /// Non-bug_report uploads are neither buffered nor persisted.
    #[tokio::test]
    async fn test_non_bug_report_upload_not_persisted() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let mut role = client_role();

        let upload_id = "a".repeat(36);
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.clone(),
            kind: "attachment".into(),
            name: "a.png".into(),
            size: 4,
            mime: "image/png".into(),
            session_id: None,
        };
        handle_control_message(&begin, &mut role, &state, &ctx, "1.2.3.4").await;
        let _ = drx.recv().await;

        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, b"\x89PNG");
        handle_binary_message(&frame, &role, &state, &ctx).await;
        let _ = drx.recv().await;

        let end = ControlMessage::FileUploadEnd {
            upload_id: upload_id.clone(),
            text: Some("ignore me".into()),
        };
        handle_control_message(&end, &mut role, &state, &ctx, "1.2.3.4").await;

        assert!(state.auth.db().list_bug_reports_for_test().is_empty());
    }

    /// A bug_report persists and the client receives a synthesized success
    /// result even when no desktop is connected for the account.
    #[tokio::test]
    async fn test_bug_report_succeeds_without_desktop() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        state.auth.db().add_device("dev-1", "alice", "Pixel 9", None).unwrap();

        // No desktop registered.
        let (ctx, mut crx) = test_conn();
        let mut role = client_role();

        let upload_id = "c".repeat(36);
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.clone(),
            kind: "bug_report".into(),
            name: "s.png".into(),
            size: 4,
            mime: "image/png".into(),
            session_id: None,
        };
        handle_control_message(&begin, &mut role, &state, &ctx, "1.2.3.4").await;

        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, b"\x89PNG");
        handle_binary_message(&frame, &role, &state, &ctx).await;

        let end = ControlMessage::FileUploadEnd {
            upload_id: upload_id.clone(),
            text: Some("offline report".into()),
        };
        handle_control_message(&end, &mut role, &state, &ctx, "1.2.3.4").await;

        // Client gets a relay-synthesized success result.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("file_upload_result"));
                assert!(t.contains("\"ok\":true"));
            }
            _ => panic!("expected synthesized success result"),
        }

        let rows = state.auth.db().list_bug_reports_for_test();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3, "offline report");
        assert_eq!(rows[0].1, "dev-1");
        if let Some(p) = &rows[0].4 {
            let _ = std::fs::remove_file(p);
        }
    }

    // --- Bug report publish from the desktop (BR-P2) ---
    //
    // The desktop publishes its OWN reports via the SAME governed upload path
    // clients use: a bug_report file_upload_begin, the screenshot in binary
    // PTY_FILE_CHUNK frames, then file_upload_end. Screenshots therefore never
    // ride an inline JSON text frame (which the 16KB gate would drop).

    fn desktop_role() -> ConnectionRole {
        ConnectionRole::Desktop { username: "alice".into() }
    }

    /// Build the begin/chunk(s)/end frames a desktop sends for one bug report,
    /// as raw WebSocket `Message`s so a test can push them through the REAL
    /// receive-loop gates via `process_ws_message`.
    fn desktop_bug_report_frames(upload_id: &str, text: &str, screenshot: &[u8]) -> Vec<Message> {
        let mut msgs = Vec::new();
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.into(),
            kind: "bug_report".into(),
            name: "screenshot.png".into(),
            size: screenshot.len() as u64,
            mime: "image/png".into(),
            session_id: None,
        };
        msgs.push(Message::Text(serde_json::to_string(&begin).unwrap().into()));
        for chunk in screenshot.chunks(48 * 1024) {
            let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, upload_id, chunk);
            msgs.push(Message::Binary(frame.into()));
        }
        let end = ControlMessage::FileUploadEnd {
            upload_id: upload_id.into(),
            text: Some(text.into()),
        };
        msgs.push(Message::Text(serde_json::to_string(&end).unwrap().into()));
        msgs
    }

    /// End-to-end through the REAL receive-loop gates: a bug-report screenshot
    /// far larger than the 16KB text cap persists (row + file) attributed to the
    /// desktop. Inline JSON would be dropped at the text gate before reaching a
    /// handler; travelling as binary chunks it survives.
    #[tokio::test]
    async fn test_desktop_bug_report_large_screenshot_survives_text_gate() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        let (ctx, _crx) = test_conn();
        let mut role = desktop_role();

        // 200KB screenshot — over 12x the text gate; a base64-in-JSON frame
        // would be dropped at MAX_TEXT_MESSAGE_SIZE.
        let png: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        assert!(png.len() > MAX_TEXT_MESSAGE_SIZE, "screenshot must exceed the text gate");

        let upload_id = "d".repeat(36);
        for msg in desktop_bug_report_frames(&upload_id, "huge screenshot", &png) {
            if let Message::Binary(b) = &msg {
                assert!(b.len() <= MAX_BINARY_MESSAGE_SIZE, "chunk must fit the binary gate");
            }
            process_ws_message(msg, &mut role, &state, &ctx, "1.2.3.4").await;
        }

        let rows = state.auth.db().list_bug_reports_for_test();
        assert_eq!(rows.len(), 1);
        let (username, device_id, device_name, text, screenshot_path, version) = &rows[0];
        assert_eq!(username, "alice");
        assert_eq!(device_id, "desktop");
        assert_eq!(device_name.as_deref(), Some("Desktop"));
        assert_eq!(text, "huge screenshot");
        assert!(version.is_none());
        let path = screenshot_path.as_ref().expect("screenshot persisted");
        assert_eq!(std::fs::read(path).unwrap(), png);
        let _ = std::fs::remove_file(path);
    }

    /// A screenshot-less desktop report persists text with a NULL screenshot.
    #[tokio::test]
    async fn test_desktop_bug_report_text_only_persists() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        let (ctx, _crx) = test_conn();
        let mut role = desktop_role();

        let upload_id = "e".repeat(36);
        for msg in desktop_bug_report_frames(&upload_id, "text only", &[]) {
            process_ws_message(msg, &mut role, &state, &ctx, "1.2.3.4").await;
        }

        let rows = state.auth.db().list_bug_reports_for_test();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "desktop");
        assert_eq!(rows[0].2.as_deref(), Some("Desktop"));
        assert_eq!(rows[0].3, "text only");
        assert!(rows[0].4.is_none(), "no screenshot path for a text-only report");
    }

    /// A non-bug_report upload from a desktop is refused — it must NOT open a
    /// general desktop-upload capability. Nothing persists.
    #[tokio::test]
    async fn test_desktop_non_bug_report_upload_ignored() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        let (ctx, _crx) = test_conn();
        let mut role = desktop_role();

        let upload_id = "f".repeat(36);
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.clone(),
            kind: "attachment".into(),
            name: "a.png".into(),
            size: 4,
            mime: "image/png".into(),
            session_id: None,
        };
        process_ws_message(
            Message::Text(serde_json::to_string(&begin).unwrap().into()),
            &mut role, &state, &ctx, "1.2.3.4",
        ).await;
        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, b"\x89PNG");
        process_ws_message(Message::Binary(frame.into()), &mut role, &state, &ctx, "1.2.3.4").await;
        let end = ControlMessage::FileUploadEnd { upload_id, text: Some("x".into()) };
        process_ws_message(
            Message::Text(serde_json::to_string(&end).unwrap().into()),
            &mut role, &state, &ctx, "1.2.3.4",
        ).await;

        assert!(state.auth.db().list_bug_reports_for_test().is_empty());
    }

    /// A desktop bug_report whose declared size exceeds the 10MB cap is rejected
    /// at begin — no governance entry, so nothing persists.
    #[tokio::test]
    async fn test_desktop_bug_report_oversize_begin_rejected() {
        let state = test_state();
        state.auth.db().create_account("alice", "hash", None, None).unwrap();
        let (ctx, _crx) = test_conn();
        let mut role = desktop_role();

        let upload_id = "g".repeat(36);
        let begin = ControlMessage::FileUploadBegin {
            upload_id: upload_id.clone(),
            kind: "bug_report".into(),
            name: "screenshot.png".into(),
            size: MAX_BUG_REPORT_UPLOAD_SIZE + 1,
            mime: "image/png".into(),
            session_id: None,
        };
        process_ws_message(
            Message::Text(serde_json::to_string(&begin).unwrap().into()),
            &mut role, &state, &ctx, "1.2.3.4",
        ).await;
        // A chunk arrives anyway (attacker ignores the reject) — it must Drop.
        let frame = protocol::build_binary_frame(protocol::PTY_FILE_CHUNK, &upload_id, b"\x89PNG");
        process_ws_message(Message::Binary(frame.into()), &mut role, &state, &ctx, "1.2.3.4").await;
        let end = ControlMessage::FileUploadEnd { upload_id, text: Some("huge".into()) };
        process_ws_message(
            Message::Text(serde_json::to_string(&end).unwrap().into()),
            &mut role, &state, &ctx, "1.2.3.4",
        ).await;

        assert!(state.auth.db().list_bug_reports_for_test().is_empty());
    }

    // --- Supervisor routing invariants ---

    fn supervisor_query(id: &str, kind: &str) -> ControlMessage {
        ControlMessage::SupervisorQuery {
            id: id.into(),
            kind: kind.into(),
            session_id: None,
            text: None,
            last_fingerprint: None,
        }
    }

    /// The relay never inspects `kind`: a query with an unknown kind is
    /// forwarded to the desktop byte-for-byte.
    #[tokio::test]
    async fn test_supervisor_query_forwards_verbatim_ignoring_kind() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, _crx) = test_conn();
        let mut role = client_role();
        let q = supervisor_query("sq-abc123def456", "zzz_unknown");
        handle_control_message(&q, &mut role, &state, &ctx, "1.2.3.4").await;

        match drx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                let got: serde_json::Value = serde_json::from_str(&t).unwrap();
                let want: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
                assert_eq!(got, want, "query forwarded unchanged, kind untouched");
                assert!(t.contains("zzz_unknown"));
            }
            _ => panic!("expected forward to desktop"),
        }
    }

    /// Fanout-negative: two connections share a device_id; only the requesting
    /// CONNECTION receives the result.
    #[tokio::test]
    async fn test_supervisor_result_routed_to_requester_only() {
        let state = test_state();
        let (owner, mut orx) = test_conn();
        let (other, mut xrx) = test_conn();
        let info = |dev: &str| ClientInfo {
            device_id: dev.into(),
            device_name: "d".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        // Same device_id on both connections (two tabs on one device).
        state.broker.register_client("alice", owner.clone(), info("dev-1")).await.unwrap();
        state.broker.register_client("alice", other.clone(), info("dev-1")).await.unwrap();

        let (dtx, _drx) = test_conn();
        state.broker.register_desktop("alice", dtx.clone(), None).await.unwrap();
        let _ = orx.try_recv(); // drain desktop-online broadcast
        let _ = xrx.try_recv();

        let mut role = ConnectionRole::Client {
            username: "alice".into(),
            device_id: "dev-1".into(),
        };
        let q = supervisor_query("sq-fan1", "fleet_status");
        handle_control_message(&q, &mut role, &state, &owner, "1.2.3.4").await;

        let mut drole = ConnectionRole::Desktop { username: "alice".into() };
        let res = ControlMessage::SupervisorResult {
            id: "sq-fan1".into(),
            payload: serde_json::json!({ "fleet": [] }),
        };
        handle_control_message(&res, &mut drole, &state, &dtx, "1.2.3.4").await;

        match orx.recv().await.unwrap() {
            WsMessage::Text(t) => assert!(t.contains("supervisor_result")),
            _ => panic!("expected result on requester"),
        }
        assert!(
            xrx.try_recv().is_err(),
            "second tab on same device must receive nothing"
        );
    }

    /// Suspend-reconnect: query on conn1 → conn1 receiver dropped → desktop
    /// result stored → same id re-issued on conn2 → conn2 gets the stored
    /// result exactly once and the entry is removed.
    #[tokio::test]
    async fn test_supervisor_suspend_reconnect_replays_stored_once() {
        let state = test_state();
        let (dtx, _drx) = test_conn();
        state.broker.register_desktop("alice", dtx.clone(), None).await.unwrap();

        // conn1 issues the query, then its receiver is dropped (tab suspended).
        let (conn1, rx1) = test_conn();
        let mut role1 = ConnectionRole::Client {
            username: "alice".into(),
            device_id: "dev-1".into(),
        };
        let q = supervisor_query("sq-susp", "summary");
        handle_control_message(&q, &mut role1, &state, &conn1, "1.2.3.4").await;
        drop(rx1);

        // Desktop result arrives → owner send fails → stored.
        let mut drole = ConnectionRole::Desktop { username: "alice".into() };
        let res = ControlMessage::SupervisorResult {
            id: "sq-susp".into(),
            payload: serde_json::json!({ "status": "ok" }),
        };
        handle_control_message(&res, &mut drole, &state, &dtx, "1.2.3.4").await;

        // conn2 re-issues the SAME id → the stored result replays to conn2.
        let (conn2, mut rx2) = test_conn();
        let mut role2 = ConnectionRole::Client {
            username: "alice".into(),
            device_id: "dev-2".into(),
        };
        handle_control_message(&q, &mut role2, &state, &conn2, "1.2.3.4").await;
        match rx2.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("supervisor_result"));
                assert!(t.contains("\"status\":\"ok\""));
            }
            _ => panic!("expected stored result replayed"),
        }
        assert!(rx2.try_recv().is_err(), "stored result delivered exactly once");

        // Entry removed: a second desktop result for the id is now unknown and
        // reaches no one.
        handle_control_message(&res, &mut drole, &state, &dtx, "1.2.3.4").await;
        assert!(rx2.try_recv().is_err(), "entry removed after replay; no re-delivery");
    }

    /// Desktop-offline query → immediate relay-synthesized supervisor_error,
    /// byte-shape-identical to a desktop-originated error.
    #[tokio::test]
    async fn test_supervisor_query_desktop_offline_synthesizes_error() {
        let state = test_state();
        // No desktop registered.
        let (ctx, mut crx) = test_conn();
        let mut role = client_role();
        let q = supervisor_query("sq-off", "fleet_status");
        handle_control_message(&q, &mut role, &state, &ctx, "1.2.3.4").await;

        let relay_err = match crx.recv().await.unwrap() {
            WsMessage::Text(t) => t,
            _ => panic!("expected synthesized error"),
        };
        let desktop_err = serde_json::to_string(&ControlMessage::SupervisorError {
            id: "sq-off".into(),
            message: "desktop offline".into(),
        })
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&relay_err).unwrap(),
            serde_json::from_str::<serde_json::Value>(&desktop_err).unwrap(),
            "relay-synthesized error must be wire-identical to a desktop error"
        );
        assert!(relay_err.contains("supervisor_error"));
        assert!(relay_err.contains("desktop offline"));
    }

    /// The 9th pending query for an account is rejected with a capacity error.
    #[tokio::test]
    async fn test_supervisor_query_cap_rejects_ninth() {
        let state = test_state();
        let (dtx, mut drx) = test_conn();
        state.broker.register_desktop("alice", dtx, None).await.unwrap();
        drain_reconcile(&mut drx);

        let (ctx, mut crx) = test_conn();
        let mut role = client_role();
        for i in 0..8 {
            let q = supervisor_query(&format!("sq-{i}"), "fleet_status");
            handle_control_message(&q, &mut role, &state, &ctx, "1.2.3.4").await;
        }
        // All 8 forwarded to the desktop.
        for _ in 0..8 {
            assert!(matches!(drx.recv().await.unwrap(), WsMessage::Text(_)));
        }

        // 9th distinct id → capacity error to requester, nothing to desktop.
        let q9 = supervisor_query("sq-9", "fleet_status");
        handle_control_message(&q9, &mut role, &state, &ctx, "1.2.3.4").await;
        assert!(drx.try_recv().is_err(), "9th query must not forward");
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("supervisor_error"));
                assert!(t.contains("too many pending supervisor queries"));
            }
            _ => panic!("expected capacity error"),
        }
    }

    // --- Bug report read API (BR-P3) ---

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    async fn response_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Write a PNG file under the state's data dir and return its absolute path.
    fn write_screenshot(state: &AppState, bytes: &[u8]) -> String {
        let dir = state.data_dir.join("bug-reports");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.png", uuid::Uuid::new_v4()));
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn test_clamp_limit() {
        assert_eq!(clamp_limit(None), 50);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(1000)), 500);
        assert_eq!(clamp_limit(Some(0)), 1);
    }

    #[tokio::test]
    async fn test_list_bug_reports_requires_auth() {
        let state = test_state();
        // No Authorization header.
        let resp = list_bug_reports_handler(
            State(state.clone()),
            HeaderMap::new(),
            Query(BugReportListQuery { limit: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Malformed token.
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers("not-a-jwt"),
            Query(BugReportListQuery { limit: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_revoked_device_jwt_rejected() {
        let state = test_state();
        let db = state.auth.db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "Pixel 9", None).unwrap();
        db.insert_bug_report("alice", "dev-1", "report", None, None).unwrap();

        // A registered device's JWT works.
        let token = state.auth.create_jwt("alice", "dev-1").unwrap();
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers(&token),
            Query(BugReportListQuery { limit: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Revocation must invalidate the still-unexpired JWT, matching the WS
        // reconnect path.
        device::revoke_device(db, "dev-1").unwrap();
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers(&token),
            Query(BugReportListQuery { limit: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp =
            bug_report_screenshot_handler(State(state.clone()), bearer_headers(&token), Path(1))
                .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_screenshot_requires_auth() {
        let state = test_state();
        let resp =
            bug_report_screenshot_handler(State(state.clone()), HeaderMap::new(), Path(1)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp =
            bug_report_screenshot_handler(State(state.clone()), bearer_headers("bad"), Path(1))
                .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_bug_reports_newest_first_and_scoped() {
        let state = test_state();
        let db = state.auth.db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "Pixel 9", None).unwrap();
        db.create_account("bob", "hash", None, None).unwrap();
        db.add_device("dev-b", "bob", "iPhone", None).unwrap();

        let shot = write_screenshot(&state, b"\x89PNG-list");
        db.insert_bug_report("alice", "dev-1", "first", None, None).unwrap();
        db.insert_bug_report("alice", "dev-1", "second", Some(&shot), Some("1.2.3"))
            .unwrap();
        // A different account's report must never appear.
        db.insert_bug_report("bob", "dev-b", "bob-report", None, None).unwrap();

        let token = state.auth.create_jwt("alice", "dev-1").unwrap();
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers(&token),
            Query(BugReportListQuery { limit: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 2, "only alice's reports, bob excluded");

        // Newest first: "second" precedes "first".
        assert_eq!(arr[0]["text"], "second");
        assert_eq!(arr[0]["has_screenshot"], true);
        assert_eq!(arr[0]["app_version"], "1.2.3");
        assert_eq!(arr[0]["device_name"], "Pixel 9");
        assert!(arr[0].get("username").is_none(), "username must not leak");
        assert!(
            arr[0].get("screenshot_path").is_none(),
            "internal path must not leak"
        );

        assert_eq!(arr[1]["text"], "first");
        assert_eq!(arr[1]["has_screenshot"], false);
        assert!(arr[1]["app_version"].is_null());

        let _ = std::fs::remove_file(&shot);
    }

    #[tokio::test]
    async fn test_list_bug_reports_respects_limit() {
        let state = test_state();
        let db = state.auth.db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "Pixel 9", None).unwrap();
        for i in 0..3 {
            db.insert_bug_report("alice", "dev-1", &format!("r{i}"), None, None)
                .unwrap();
        }
        let token = state.auth.create_jwt("alice", "dev-1").unwrap();

        // limit=1 → only the newest row.
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers(&token),
            Query(BugReportListQuery { limit: Some(1) }),
        )
        .await;
        let body = response_json(resp).await;
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["text"], "r2");

        // An over-cap limit is accepted (clamped), returning all available rows.
        let resp = list_bug_reports_handler(
            State(state.clone()),
            bearer_headers(&token),
            Query(BugReportListQuery { limit: Some(100_000) }),
        )
        .await;
        let body = response_json(resp).await;
        assert_eq!(body.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_screenshot_served_and_missing_cases() {
        let state = test_state();
        let db = state.auth.db();
        db.create_account("alice", "hash", None, None).unwrap();
        db.add_device("dev-1", "alice", "Pixel 9", None).unwrap();
        let token = state.auth.create_jwt("alice", "dev-1").unwrap();

        let png = b"\x89PNG\r\n\x1a\nDATA";
        let shot = write_screenshot(&state, png);
        let with_shot = db
            .insert_bug_report("alice", "dev-1", "has shot", Some(&shot), None)
            .unwrap();
        let no_shot = db
            .insert_bug_report("alice", "dev-1", "no shot", None, None)
            .unwrap();
        let gone_path = state.data_dir.join("bug-reports").join("gone.png");
        let missing_file = db
            .insert_bug_report(
                "alice",
                "dev-1",
                "file gone",
                Some(&gone_path.to_string_lossy()),
                None,
            )
            .unwrap();

        // 200 with PNG bytes + content-type.
        let resp = bug_report_screenshot_handler(
            State(state.clone()),
            bearer_headers(&token),
            Path(with_shot),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], png);

        // Row exists but has no screenshot → 404.
        let resp = bug_report_screenshot_handler(
            State(state.clone()),
            bearer_headers(&token),
            Path(no_shot),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Row records a path but the file is gone → 404.
        let resp = bug_report_screenshot_handler(
            State(state.clone()),
            bearer_headers(&token),
            Path(missing_file),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // No such row → 404.
        let resp = bug_report_screenshot_handler(
            State(state.clone()),
            bearer_headers(&token),
            Path(999_999),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Another account's report id is invisible → 404.
        db.create_account("bob", "hash", None, None).unwrap();
        db.add_device("dev-b", "bob", "iPhone", None).unwrap();
        let bob_shot = write_screenshot(&state, b"\x89PNGbob");
        let bob_id = db
            .insert_bug_report("bob", "dev-b", "bob", Some(&bob_shot), None)
            .unwrap();
        let resp = bug_report_screenshot_handler(
            State(state.clone()),
            bearer_headers(&token),
            Path(bob_id),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_file(&shot);
        let _ = std::fs::remove_file(&bob_shot);
    }
}

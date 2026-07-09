use serde::{Deserialize, Serialize};

/// Binary frame type identifiers
pub const PTY_OUTPUT: u8 = 0x01;
pub const PTY_INPUT: u8 = 0x02;
pub const PTY_SCROLLBACK: u8 = 0x03;
/// A chunk of a client→desktop file upload. The 36-byte session-id slot holds
/// the upload UUID; the payload is a slice of the file bytes.
pub const PTY_FILE_CHUNK: u8 = 0x04;
/// A chunk of a desktop→client file download. The 36-byte session-id slot holds
/// the download UUID; the payload is a slice of the file bytes.
pub const PTY_FILE_DOWNLOAD_CHUNK: u8 = 0x05;

/// Binary frame: [1 byte type][36 bytes session UUID as ASCII][N bytes payload]
pub const BINARY_HEADER_LEN: usize = 1 + 36;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub label: String,
    pub cwd: String,
    pub cols: u16,
    pub rows: u16,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// Account roster entry carried on `session_list`. Opaque to the relay —
/// mirrored across transit so PWA clients can render account chrome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    pub id: String,
    pub color: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
    #[serde(rename = "connectedAt")]
    pub connected_at: String,
}

/// All JSON control messages on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    // --- Handshake ---
    #[serde(rename = "hello")]
    Hello {
        version: u32,
        #[serde(rename = "clientVersion", skip_serializing_if = "Option::is_none")]
        client_version: Option<String>,
        #[serde(rename = "serverVersion", skip_serializing_if = "Option::is_none")]
        server_version: Option<String>,
    },

    // --- Auth ---
    #[serde(rename = "auth")]
    Auth {
        version: u32,
        username: String,
        #[serde(rename = "passwordHash", skip_serializing_if = "Option::is_none")]
        password_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
        #[serde(rename = "deviceToken", skip_serializing_if = "Option::is_none")]
        device_token: Option<String>,
        /// Provisioned desktop key — present only when a desktop (host) authenticates.
        /// Bypasses password/TOTP/approval and authorizes desktop registration.
        #[serde(rename = "desktopKey", skip_serializing_if = "Option::is_none")]
        desktop_key: Option<String>,
    },
    #[serde(rename = "auth_result")]
    AuthResult {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(rename = "deviceId", skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(rename = "retryAfter", skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
    },

    // --- Desktop registration ---
    #[serde(rename = "desktop_register")]
    DesktopRegister {
        version: u32,
        /// Features this desktop supports (e.g. "file_upload"). Absent for old
        /// desktops that predate capability advertisement.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capabilities: Option<Vec<String>>,
    },
    #[serde(rename = "desktop_registered")]
    DesktopRegistered,

    // --- Device approval ---
    #[serde(rename = "device_pending")]
    DevicePending {
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "deviceName")]
        device_name: String,
        ip: String,
    },
    #[serde(rename = "device_approved")]
    DeviceApproved {
        #[serde(rename = "deviceId")]
        device_id: String,
    },
    #[serde(rename = "device_rejected")]
    DeviceRejected {
        #[serde(rename = "deviceId")]
        device_id: String,
    },

    // --- Sessions ---
    #[serde(rename = "session_spawn_request")]
    SessionSpawnRequest {
        cols: u16,
        rows: u16,
        #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
    },
    #[serde(rename = "session_list_request")]
    SessionListRequest,
    #[serde(rename = "session_list")]
    SessionList {
        sessions: Vec<SessionInfo>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accounts: Option<Vec<AccountMeta>>,
    },
    #[serde(rename = "session_created")]
    SessionCreated {
        #[serde(rename = "sessionId")]
        session_id: String,
        label: String,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
        created_at: Option<u64>,
        // PTY dims so clients render the authoritative grid immediately
        // (otherwise unknown until the next session_list). Optional: old
        // desktops don't send them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cols: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rows: Option<u16>,
        #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
    },
    #[serde(rename = "session_renamed")]
    SessionRenamed {
        #[serde(rename = "sessionId")]
        session_id: String,
        label: String,
    },
    #[serde(rename = "session_closed")]
    SessionClosed {
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    /// Client asks the desktop to kill a session's PTY. The desktop's normal
    /// exit path then broadcasts `session_closed` to every client.
    #[serde(rename = "session_close_request")]
    SessionCloseRequest {
        #[serde(rename = "sessionId")]
        session_id: String,
    },

    // --- Session events (desktop → clients) ---
    /// A long-running session finished working; fan out to clients (and web
    /// push subscribers when configured).
    #[serde(rename = "session_notification")]
    SessionNotification {
        #[serde(rename = "sessionId")]
        session_id: String,
        title: String,
        body: String,
    },
    /// Claude Code context-window usage for a session, sourced from the
    /// desktop's statusline bridge.
    #[serde(rename = "context_update")]
    ContextUpdate {
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "usedPct")]
        used_pct: f64,
        #[serde(rename = "usedTokens", default, skip_serializing_if = "Option::is_none")]
        used_tokens: Option<u64>,
        #[serde(rename = "maxTokens", default, skip_serializing_if = "Option::is_none")]
        max_tokens: Option<u64>,
    },

    // --- Web push ---
    #[serde(rename = "push_subscribe")]
    PushSubscribe { subscription: serde_json::Value },
    #[serde(rename = "push_unsubscribe")]
    PushUnsubscribe,
    #[serde(rename = "vapid_key_request")]
    VapidKeyRequest,
    #[serde(rename = "vapid_public_key")]
    VapidPublicKey { key: String },

    // --- Resize ---
    #[serde(rename = "pty_resize")]
    PtyResize {
        #[serde(rename = "sessionId")]
        session_id: String,
        cols: u16,
        rows: u16,
    },
    #[serde(rename = "pty_resized")]
    PtyResized {
        #[serde(rename = "sessionId")]
        session_id: String,
        cols: u16,
        rows: u16,
    },

    // --- Replay routing / recovery ---
    /// Desktop → relay: the scrollback replay for the oldest queued
    /// session_list_request follows. Lets the relay route the replay burst
    /// (binary scrollback + trailing session_list) to the requesting client
    /// only instead of broadcasting it. Never forwarded to clients.
    #[serde(rename = "replay_begin")]
    ReplayBegin,
    /// Relay → client: live output was dropped for this connection under
    /// backpressure — request a session list (which triggers a scrollback
    /// replay) to converge back to the current screen.
    #[serde(rename = "resync_required")]
    ResyncRequired,

    // --- File upload (client → desktop, chunked over binary PTY_FILE_CHUNK) ---
    /// Client announces an upload; the relay governs it and forwards to the
    /// desktop. `upload_id` keys the binary chunk stream and the result.
    #[serde(rename = "file_upload_begin")]
    FileUploadBegin {
        upload_id: String,
        kind: String,
        name: String,
        size: u64,
        mime: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Client signals all chunks sent; forwarded to the desktop to finalize.
    #[serde(rename = "file_upload_end")]
    FileUploadEnd {
        upload_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    },
    /// Desktop (or the relay, on rejection) reports the outcome; routed to the
    /// requesting client connection only.
    #[serde(rename = "file_upload_result")]
    FileUploadResult {
        upload_id: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    // --- File download (desktop → client, chunked over binary PTY_FILE_DOWNLOAD_CHUNK) ---
    /// Client asks the desktop to send a file it rendered in terminal output.
    /// The relay governs it and forwards to the desktop. `download_id` keys the
    /// binary chunk stream and the begin/end results.
    #[serde(rename = "file_download_request")]
    FileDownloadRequest {
        download_id: String,
        session_id: String,
        path: String,
    },
    /// Desktop announces the file it is about to stream; routed to the
    /// requesting client connection only.
    #[serde(rename = "file_download_begin")]
    FileDownloadBegin {
        download_id: String,
        name: String,
        size: u64,
        mime: String,
    },
    /// Desktop (or the relay, on rejection/overrun) reports the download
    /// outcome; routed to the requesting client connection only. Sent for both
    /// success (after the last chunk) and failure (may arrive with no begin).
    #[serde(rename = "file_download_end")]
    FileDownloadEnd {
        download_id: String,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    // --- Supervisor (client → relay → desktop; result/error → requester only) ---
    /// Client asks the desktop a supervisor question. Forwarded VERBATIM to the
    /// desktop by the relay — `kind` is OPAQUE and never matched relay-side.
    #[serde(rename = "supervisor_query")]
    SupervisorQuery {
        /// Client-minted, high-entropy correlation id.
        id: String,
        /// Query kind — opaque to the relay.
        kind: String,
        #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(rename = "lastFingerprint", skip_serializing_if = "Option::is_none")]
        last_fingerprint: Option<String>,
    },
    /// Desktop answers a supervisor query; routed to the requesting client only.
    #[serde(rename = "supervisor_result")]
    SupervisorResult {
        id: String,
        payload: serde_json::Value,
    },
    /// Supervisor failure (desktop-originated OR relay-synthesized); routed to
    /// the requesting client only. Both origins are wire-identical.
    #[serde(rename = "supervisor_error")]
    SupervisorError {
        id: String,
        message: String,
    },

    // --- Health ---
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "desktop_status")]
    DesktopStatus {
        online: bool,
        /// Features the online desktop advertised at registration. None when
        /// offline or when an old desktop registered without capabilities.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capabilities: Option<Vec<String>>,
    },
    #[serde(rename = "relay_shutting_down")]
    RelayShuttingDown,

    // --- Device management ---
    #[serde(rename = "connected_devices_request")]
    ConnectedDevicesRequest,
    #[serde(rename = "connected_devices_list")]
    ConnectedDevicesList { devices: Vec<DeviceInfo> },
    #[serde(rename = "device_revoke")]
    DeviceRevoke {
        #[serde(rename = "deviceId")]
        device_id: String,
    },
    #[serde(rename = "device_revoked")]
    DeviceRevoked {
        #[serde(rename = "deviceId")]
        device_id: String,
    },
}

/// Parse a binary WebSocket frame into (type, session_id_str, payload).
pub fn parse_binary_frame(data: &[u8]) -> Result<(u8, String, &[u8]), ProtocolError> {
    if data.len() < BINARY_HEADER_LEN {
        return Err(ProtocolError::FrameTooShort {
            got: data.len(),
            expected: BINARY_HEADER_LEN,
        });
    }
    let frame_type = data[0];
    if !matches!(
        frame_type,
        PTY_OUTPUT | PTY_INPUT | PTY_SCROLLBACK | PTY_FILE_CHUNK | PTY_FILE_DOWNLOAD_CHUNK
    ) {
        return Err(ProtocolError::UnknownFrameType(frame_type));
    }
    let id_bytes = &data[1..37];
    let session_id = std::str::from_utf8(id_bytes)
        .map_err(|e| ProtocolError::InvalidUuid(e.to_string()))?
        .to_string();
    Ok((frame_type, session_id, &data[BINARY_HEADER_LEN..]))
}

/// Build a binary WebSocket frame from parts.
pub fn build_binary_frame(frame_type: u8, session_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BINARY_HEADER_LEN + payload.len());
    buf.push(frame_type);
    let id_bytes = session_id.as_bytes();
    let mut padded = [b' '; 36];
    let copy_len = id_bytes.len().min(36);
    padded[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
    buf.extend_from_slice(&padded);
    buf.extend_from_slice(payload);
    buf
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("binary frame too short: got {got}, expected at least {expected}")]
    FrameTooShort { got: usize, expected: usize },
    #[error("unknown binary frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    #[error("invalid UUID in binary frame: {0}")]
    InvalidUuid(String),
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_serialize_hello() {
        let msg = ControlMessage::Hello {
            version: 1,
            client_version: Some("0.1.0".into()),
            server_version: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"clientVersion\":\"0.1.0\""));
        assert!(!json.contains("serverVersion"));
    }

    #[test]
    fn test_control_message_deserialize_auth() {
        let json = r#"{"type":"auth","version":1,"username":"sean","passwordHash":"abc123","totp":"654321","deviceToken":"jwt..."}"#;
        let msg: ControlMessage = serde_json::from_str(json).unwrap();
        match msg {
            ControlMessage::Auth {
                version,
                username,
                password_hash,
                totp,
                device_token,
                ..
            } => {
                assert_eq!(version, 1);
                assert_eq!(username, "sean");
                assert_eq!(password_hash.unwrap(), "abc123");
                assert_eq!(totp.unwrap(), "654321");
                assert_eq!(device_token.unwrap(), "jwt...");
            }
            _ => panic!("expected Auth variant"),
        }
    }

    #[test]
    fn test_control_message_roundtrip_auth_result() {
        let msg = ControlMessage::AuthResult {
            success: false,
            token: None,
            device_id: None,
            error: Some("rate_limited".into()),
            retry_after: Some(900),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::AuthResult {
                success,
                error,
                retry_after,
                ..
            } => {
                assert!(!success);
                assert_eq!(error.unwrap(), "rate_limited");
                assert_eq!(retry_after.unwrap(), 900);
            }
            _ => panic!("expected AuthResult"),
        }
    }

    #[test]
    fn test_binary_frame_roundtrip() {
        let session_id = uuid::Uuid::new_v4().to_string();
        let payload = b"hello terminal";
        let frame = build_binary_frame(PTY_OUTPUT, &session_id, payload);
        let (ftype, sid, data) = parse_binary_frame(&frame).unwrap();
        assert_eq!(ftype, PTY_OUTPUT);
        assert_eq!(sid, session_id);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_binary_frame_too_short() {
        let result = parse_binary_frame(&[0x01, 0x02]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_binary_frame_unknown_type() {
        let mut frame = vec![0xFF];
        frame.extend_from_slice(&[0u8; 36]);
        let result = parse_binary_frame(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown"));
    }

    #[test]
    fn test_session_list_roundtrip() {
        let msg = ControlMessage::SessionList {
            sessions: vec![SessionInfo {
                id: "abc".into(),
                label: "Session 1".into(),
                cwd: "/home/sean".into(),
                cols: 120,
                rows: 40,
                created_at: Some(1719700000000),
                account_id: None,
            }],
            accounts: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::SessionList { sessions, .. } => {
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].label, "Session 1");
            }
            _ => panic!("expected SessionList"),
        }
    }

    #[test]
    fn test_session_spawn_request_account_id_roundtrips() {
        // Present accountId survives parse → re-serialize.
        let json = r#"{"type":"session_spawn_request","cols":80,"rows":24,"accountId":"acct-7"}"#;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        match &parsed {
            ControlMessage::SessionSpawnRequest { cols, rows, account_id } => {
                assert_eq!(*cols, 80);
                assert_eq!(*rows, 24);
                assert_eq!(account_id.as_deref(), Some("acct-7"));
            }
            _ => panic!("expected SessionSpawnRequest"),
        }
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_session_spawn_request_without_account_id_backcompat() {
        // Old clients omit accountId — parses, and re-serializes identically.
        let json = r#"{"type":"session_spawn_request","cols":80,"rows":24}"#;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(
            parsed,
            ControlMessage::SessionSpawnRequest { account_id: None, .. }
        ));
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_session_created_account_id_roundtrips() {
        let json = r#"{"type":"session_created","sessionId":"s1","label":"L","accountId":"acct-3"}"#;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        match &parsed {
            ControlMessage::SessionCreated { account_id, .. } => {
                assert_eq!(account_id.as_deref(), Some("acct-3"));
            }
            _ => panic!("expected SessionCreated"),
        }
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_session_created_without_account_id_backcompat() {
        // Old desktops send neither accountId nor dims.
        let json = r#"{"type":"session_created","sessionId":"s1","label":"L"}"#;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(
            parsed,
            ControlMessage::SessionCreated { account_id: None, .. }
        ));
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_session_list_per_entry_account_id_and_roster_roundtrips() {
        // Per-entry accountId + a multi-entry accounts roster survive transit.
        let json = r##"{"type":"session_list","sessions":[{"id":"a","label":"L1","cwd":"/","cols":80,"rows":24,"accountId":"acct-1"}],"accounts":[{"id":"acct-1","color":"#ff0000","status":"active"},{"id":"acct-2","color":"#00ff00","status":"idle"}]}"##;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        match &parsed {
            ControlMessage::SessionList { sessions, accounts } => {
                assert_eq!(sessions[0].account_id.as_deref(), Some("acct-1"));
                let roster = accounts.as_ref().expect("accounts present");
                assert_eq!(roster.len(), 2);
                assert_eq!(roster[0].id, "acct-1");
                assert_eq!(roster[0].color, "#ff0000");
                assert_eq!(roster[0].status, "active");
                assert_eq!(roster[1].id, "acct-2");
            }
            _ => panic!("expected SessionList"),
        }
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_session_list_without_new_fields_backcompat() {
        // Old desktop: no per-entry accountId, no accounts roster. Re-serializes
        // byte-identically to the input shape.
        let json = r#"{"type":"session_list","sessions":[{"id":"a","label":"L1","cwd":"/","cols":80,"rows":24}]}"#;
        let parsed: ControlMessage = serde_json::from_str(json).unwrap();
        match &parsed {
            ControlMessage::SessionList { sessions, accounts } => {
                assert!(sessions[0].account_id.is_none());
                assert!(accounts.is_none());
            }
            _ => panic!("expected SessionList"),
        }
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_file_chunk_frame_roundtrips() {
        let upload_id = uuid::Uuid::new_v4().to_string();
        let payload = b"file bytes";
        let frame = build_binary_frame(PTY_FILE_CHUNK, &upload_id, payload);
        let (ftype, id, data) = parse_binary_frame(&frame).unwrap();
        assert_eq!(ftype, PTY_FILE_CHUNK);
        assert_eq!(id, upload_id);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_file_download_chunk_frame_roundtrips() {
        let download_id = uuid::Uuid::new_v4().to_string();
        let payload = b"download bytes";
        let frame = build_binary_frame(PTY_FILE_DOWNLOAD_CHUNK, &download_id, payload);
        let (ftype, id, data) = parse_binary_frame(&frame).unwrap();
        assert_eq!(ftype, PTY_FILE_DOWNLOAD_CHUNK);
        assert_eq!(id, download_id);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_file_download_request_wire_shape() {
        let json = r#"{"type":"file_download_request","download_id":"d1","session_id":"s1","path":"/home/sean/a.md"}"#;
        let msg: ControlMessage = serde_json::from_str(json).unwrap();
        match &msg {
            ControlMessage::FileDownloadRequest {
                download_id,
                session_id,
                path,
            } => {
                assert_eq!(download_id, "d1");
                assert_eq!(session_id, "s1");
                assert_eq!(path, "/home/sean/a.md");
            }
            _ => panic!("expected FileDownloadRequest"),
        }
        let reser: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(reser, serde_json::from_str::<serde_json::Value>(json).unwrap());
    }

    #[test]
    fn test_file_download_begin_roundtrips() {
        let msg = ControlMessage::FileDownloadBegin {
            download_id: "d1".into(),
            name: "report.md".into(),
            size: 2048,
            mime: "text/markdown".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"file_download_begin\""));
        assert!(json.contains("\"size\":2048"));
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::FileDownloadBegin { download_id, name, size, mime } => {
                assert_eq!(download_id, "d1");
                assert_eq!(name, "report.md");
                assert_eq!(size, 2048);
                assert_eq!(mime, "text/markdown");
            }
            _ => panic!("expected FileDownloadBegin"),
        }
    }

    #[test]
    fn test_file_download_end_omits_error_on_success() {
        // Success: error is omitted entirely.
        let ok = ControlMessage::FileDownloadEnd {
            download_id: "d1".into(),
            ok: true,
            error: None,
        };
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(!json.contains("error"));

        // Failure: error is present and round-trips.
        let fail = ControlMessage::FileDownloadEnd {
            download_id: "d1".into(),
            ok: false,
            error: Some("not found".into()),
        };
        let json = serde_json::to_string(&fail).unwrap();
        assert!(json.contains("\"ok\":false"));
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::FileDownloadEnd { download_id, ok, error } => {
                assert_eq!(download_id, "d1");
                assert!(!ok);
                assert_eq!(error.unwrap(), "not found");
            }
            _ => panic!("expected FileDownloadEnd"),
        }
    }

    #[test]
    fn test_desktop_register_with_capabilities_roundtrips() {
        let msg = ControlMessage::DesktopRegister {
            version: 1,
            capabilities: Some(vec!["file_upload".into()]),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"capabilities\":[\"file_upload\"]"));
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::DesktopRegister { capabilities, .. } => {
                assert_eq!(capabilities.unwrap(), vec!["file_upload".to_string()]);
            }
            _ => panic!("expected DesktopRegister"),
        }
    }

    #[test]
    fn test_old_desktop_register_without_capabilities_parses() {
        // Old desktops omit the field entirely — serde default fills None.
        let json = r#"{"type":"desktop_register","version":1}"#;
        let msg: ControlMessage = serde_json::from_str(json).unwrap();
        match msg {
            ControlMessage::DesktopRegister { version, capabilities } => {
                assert_eq!(version, 1);
                assert!(capabilities.is_none());
            }
            _ => panic!("expected DesktopRegister"),
        }
    }

    #[test]
    fn test_file_upload_begin_wire_shape() {
        let json = r#"{"type":"file_upload_begin","upload_id":"u1","kind":"image","name":"a.png","size":1024,"mime":"image/png","session_id":"s1"}"#;
        let msg: ControlMessage = serde_json::from_str(json).unwrap();
        match msg {
            ControlMessage::FileUploadBegin {
                upload_id,
                kind,
                name,
                size,
                mime,
                session_id,
            } => {
                assert_eq!(upload_id, "u1");
                assert_eq!(kind, "image");
                assert_eq!(name, "a.png");
                assert_eq!(size, 1024);
                assert_eq!(mime, "image/png");
                assert_eq!(session_id.unwrap(), "s1");
            }
            _ => panic!("expected FileUploadBegin"),
        }
        // session_id is optional.
        let no_sid = r#"{"type":"file_upload_begin","upload_id":"u2","kind":"file","name":"b","size":1,"mime":"text/plain"}"#;
        let parsed: ControlMessage = serde_json::from_str(no_sid).unwrap();
        assert!(matches!(
            parsed,
            ControlMessage::FileUploadBegin { session_id: None, .. }
        ));
    }

    #[test]
    fn test_file_upload_result_roundtrips() {
        let msg = ControlMessage::FileUploadResult {
            upload_id: "u1".into(),
            ok: false,
            path: None,
            error: Some("file_too_large".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"file_upload_result\""));
        assert!(json.contains("\"upload_id\":\"u1\""));
        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::FileUploadResult { ok, error, .. } => {
                assert!(!ok);
                assert_eq!(error.unwrap(), "file_too_large");
            }
            _ => panic!("expected FileUploadResult"),
        }
    }

    #[test]
    fn test_desktop_status_carries_capabilities() {
        let msg = ControlMessage::DesktopStatus {
            online: true,
            capabilities: Some(vec!["file_upload".into()]),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"capabilities\":[\"file_upload\"]"));
        // Offline omits capabilities entirely (skip_serializing_if None).
        let offline = ControlMessage::DesktopStatus {
            online: false,
            capabilities: None,
        };
        let json = serde_json::to_string(&offline).unwrap();
        assert!(!json.contains("capabilities"));
    }

    #[test]
    fn test_supervisor_query_golden_fixtures() {
        // Fixture 1: minimal query (no optional fields → omitted on the wire).
        let fix1 = r#"{"type":"supervisor_query","id":"sq-fixture01","kind":"fleet_status"}"#;
        let msg1 = ControlMessage::SupervisorQuery {
            id: "sq-fixture01".into(),
            kind: "fleet_status".into(),
            session_id: None,
            text: None,
            last_fingerprint: None,
        };
        let got1: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg1).unwrap()).unwrap();
        let want1: serde_json::Value = serde_json::from_str(fix1).unwrap();
        assert_eq!(got1, want1);
        match serde_json::from_str::<ControlMessage>(fix1).unwrap() {
            ControlMessage::SupervisorQuery { id, kind, session_id, text, last_fingerprint } => {
                assert_eq!(id, "sq-fixture01");
                assert_eq!(kind, "fleet_status");
                assert!(session_id.is_none() && text.is_none() && last_fingerprint.is_none());
            }
            _ => panic!("expected SupervisorQuery"),
        }

        // Fixture 2: sessionId + lastFingerprint camelCase renames present.
        let fix2 = r#"{"type":"supervisor_query","id":"sq-fixture02","kind":"summary","sessionId":"sess-1","lastFingerprint":"fp-1"}"#;
        let msg2 = ControlMessage::SupervisorQuery {
            id: "sq-fixture02".into(),
            kind: "summary".into(),
            session_id: Some("sess-1".into()),
            text: None,
            last_fingerprint: Some("fp-1".into()),
        };
        let got2: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg2).unwrap()).unwrap();
        let want2: serde_json::Value = serde_json::from_str(fix2).unwrap();
        assert_eq!(got2, want2);
        match serde_json::from_str::<ControlMessage>(fix2).unwrap() {
            ControlMessage::SupervisorQuery { session_id, last_fingerprint, .. } => {
                assert_eq!(session_id.unwrap(), "sess-1");
                assert_eq!(last_fingerprint.unwrap(), "fp-1");
            }
            _ => panic!("expected SupervisorQuery"),
        }
    }

    #[test]
    fn test_supervisor_result_golden_fixture() {
        let fix = r#"{"type":"supervisor_result","id":"sq-fixture01","payload":{"fleet":[]}}"#;
        let msg = ControlMessage::SupervisorResult {
            id: "sq-fixture01".into(),
            payload: serde_json::json!({ "fleet": [] }),
        };
        let got: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        let want: serde_json::Value = serde_json::from_str(fix).unwrap();
        assert_eq!(got, want);
        match serde_json::from_str::<ControlMessage>(fix).unwrap() {
            ControlMessage::SupervisorResult { id, payload } => {
                assert_eq!(id, "sq-fixture01");
                assert_eq!(payload, serde_json::json!({ "fleet": [] }));
            }
            _ => panic!("expected SupervisorResult"),
        }
    }

    #[test]
    fn test_supervisor_error_golden_fixture() {
        let fix = r#"{"type":"supervisor_error","id":"sq-fixture01","message":"desktop offline"}"#;
        let msg = ControlMessage::SupervisorError {
            id: "sq-fixture01".into(),
            message: "desktop offline".into(),
        };
        let got: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        let want: serde_json::Value = serde_json::from_str(fix).unwrap();
        assert_eq!(got, want);
        match serde_json::from_str::<ControlMessage>(fix).unwrap() {
            ControlMessage::SupervisorError { id, message } => {
                assert_eq!(id, "sq-fixture01");
                assert_eq!(message, "desktop offline");
            }
            _ => panic!("expected SupervisorError"),
        }
    }

    #[test]
    fn test_ping_pong() {
        let ping_json = serde_json::to_string(&ControlMessage::Ping).unwrap();
        assert!(ping_json.contains("\"type\":\"ping\""));
        let pong_json = serde_json::to_string(&ControlMessage::Pong).unwrap();
        assert!(pong_json.contains("\"type\":\"pong\""));
    }
}

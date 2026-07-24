use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Instant;
use tokio::sync::{mpsc, Mutex as TokioMutex, RwLock};

use crate::protocol::PTY_OUTPUT;

/// A message that can be sent over a WebSocket connection.
#[derive(Debug, Clone)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close,
}

impl WsMessage {
    fn byte_len(&self) -> usize {
        match self {
            WsMessage::Text(t) => t.len(),
            WsMessage::Binary(b) => b.len(),
            WsMessage::Close => 0,
        }
    }

    fn is_pty_output(&self) -> bool {
        matches!(self, WsMessage::Binary(b) if b.first() == Some(&PTY_OUTPUT))
    }

    /// Session id slot of a PTY_OUTPUT frame: bytes 1..37, space-padded
    /// (mirrors the desktop's `build_binary_frame`). None for non-output
    /// frames or malformed headers.
    fn pty_output_session(&self) -> Option<&str> {
        match self {
            WsMessage::Binary(b) if b.first() == Some(&PTY_OUTPUT) && b.len() >= 37 => {
                std::str::from_utf8(&b[1..37]).ok().map(str::trim)
            }
            _ => None,
        }
    }
}

/// Outbound handle for one connection. Messages flow through an unbounded
/// channel with explicit byte accounting: `queued` is incremented here and
/// decremented by the connection's writer task as frames drain to the socket.
///
/// When a client can't keep up (queued bytes past the budget), dropping
/// arbitrary frames silently corrupts its terminal — instead the connection
/// is marked dirty: live PTY output stops, one `resync_required` is sent
/// (rate-limited), and the client converges via a scrollback replay, which
/// clears the flag on its next session_list_request.
#[derive(Debug, Clone)]
pub struct ConnTx {
    tx: mpsc::UnboundedSender<WsMessage>,
    queued: Arc<AtomicUsize>,
    dirty: Arc<AtomicBool>,
    last_resync: Arc<TokioMutex<Option<Instant>>>,
    /// Sessions this client is actively viewing (`session_focus` message).
    /// None = the client never scoped itself (old clients) — it receives every
    /// session's live output, the pre-focus behavior. A phone viewing one
    /// session out of six otherwise gets the full firehose, blows the output
    /// budget in minutes, and lives inside the pause→resync cycle.
    focus: Arc<StdRwLock<Option<HashSet<String>>>>,
}

/// Live output queued beyond this marks the connection dirty. The scrollback
/// ring is 100KB — a client this far behind converges faster via replay than
/// by draining a multi-megabyte backlog.
const CLIENT_OUTPUT_BUDGET_BYTES: usize = 2 * 1024 * 1024;
/// Minimum spacing between resync_required nudges to the same client, so a
/// persistently slow client doesn't loop drop → resync → drop.
const RESYNC_MIN_INTERVAL_SECS: u64 = 10;

impl ConnTx {
    pub fn new(tx: mpsc::UnboundedSender<WsMessage>, queued: Arc<AtomicUsize>) -> Self {
        Self {
            tx,
            queued,
            dirty: Arc::new(AtomicBool::new(false)),
            last_resync: Arc::new(TokioMutex::new(None)),
            focus: Arc::new(StdRwLock::new(None)),
        }
    }

    /// Update the focused-session set. An empty list clears scoping (receive
    /// everything) — the safe reading of "nothing focused".
    pub fn set_focus(&self, ids: Vec<String>) {
        let new = if ids.is_empty() {
            None
        } else {
            Some(ids.into_iter().collect())
        };
        *self.focus.write().unwrap() = new;
    }

    /// Whether live output for `session_id` should reach this connection.
    fn wants_session(&self, session_id: &str) -> bool {
        match &*self.focus.read().unwrap() {
            None => true,
            Some(set) => set.contains(session_id),
        }
    }

    /// Enqueue unconditionally (control traffic, replay, desktop-bound).
    pub fn send(&self, msg: WsMessage) -> Result<(), ()> {
        self.queued.fetch_add(msg.byte_len(), Ordering::Relaxed);
        self.tx.send(msg).map_err(|_| ())
    }

    /// Enqueue live PTY output, applying the dirty/budget policy.
    /// Returns true when a resync_required nudge should be sent.
    fn send_output(&self, msg: WsMessage) -> bool {
        if self.dirty.load(Ordering::Relaxed) {
            // Already resyncing — this output is contained in the replay.
            return false;
        }
        if self.queued.load(Ordering::Relaxed) + msg.byte_len() > CLIENT_OUTPUT_BUDGET_BYTES {
            self.dirty.store(true, Ordering::Relaxed);
            return true;
        }
        let _ = self.send(msg);
        false
    }

    /// The client asked for a session list — the replay that follows makes
    /// its terminal converge, so live output can flow again.
    pub fn clear_dirty(&self) {
        self.dirty.store(false, Ordering::Relaxed);
    }

    /// Same underlying connection (the queued counter is per-connection).
    pub fn same_conn(&self, other: &ConnTx) -> bool {
        Arc::ptr_eq(&self.queued, &other.queued)
    }
}

/// Info about a connected client.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub device_id: String,
    pub device_name: String,
    pub ip: String,
    pub connected_at: String,
}

/// A connected client with its sender channel and info.
struct ClientConnection {
    tx: ConnTx,
    info: ClientInfo,
}

/// Pending device approval request.
#[derive(Debug, Clone)]
pub struct PendingDevice {
    pub device_id: String,
    pub device_name: String,
    pub ip: String,
    pub client_tx: ConnTx,
    /// When this request was created (for the TTL sweep).
    pub created: Instant,
    /// Same instant as epoch-ms, sent to the desktop so it can render a stable
    /// auto-reject countdown that survives list replacements.
    pub requested_at: u64,
}

/// A queued replay request: the exact connection that asked for the session
/// list. Routing by connection (not device) matters — two tabs can share a
/// device_id, and delivering a burst to the non-requesting twin would feed
/// its open scrollback gate a replay whose terminating session_list it never
/// consumes, deadlocking its live output.
#[derive(Clone)]
struct ReplayRequest {
    device_id: String,
    tx: ConnTx,
}

/// One in-flight client→desktop file upload, governed at the relay so a
/// misbehaving client can't stream unbounded bytes or leak upload slots.
struct UploadEntry {
    /// The exact client CONNECTION that owns this upload. Chunks are only
    /// forwarded from this connection and the result is routed back to it.
    owner: ConnTx,
    /// Size the client declared in `file_upload_begin`.
    declared_size: u64,
    /// Payload bytes forwarded to the desktop so far.
    bytes_forwarded: u64,
    /// Last time any message touched this upload (for idle GC).
    last_activity: Instant,
    /// Set by `file_upload_end`; further chunks are ignored.
    finished: bool,
    /// For `bug_report` uploads only: forwarded chunk payloads accumulated for
    /// relay-side persistence. `None` for every other kind (pass-through only).
    buffer: Option<Vec<u8>>,
}

/// One in-flight desktop→client file download, governed at the relay so a
/// misbehaving desktop can't stream unbounded bytes or leak download slots.
/// The mirror image of `UploadEntry`: here the OWNER is the requesting client
/// connection and the byte stream flows the other way.
struct DownloadEntry {
    /// The exact client CONNECTION that requested this download. `begin`, `end`
    /// and chunk traffic are routed ONLY to this connection.
    owner: ConnTx,
    /// Size the desktop declared in `file_download_begin`; `None` until begin
    /// passes through (a failure `end` can arrive with no preceding begin).
    declared_size: Option<u64>,
    /// Payload bytes forwarded to the client so far.
    bytes_forwarded: u64,
    /// Last time any message touched this download (for idle GC).
    last_activity: Instant,
}

/// One pending supervisor query, keyed by the client-minted query id. The
/// result/error is routed back to the exact owning CONNECTION; if that
/// connection is gone when the desktop answers, the serialized reply is parked
/// in `stored` for redelivery when the same id is re-issued after reconnect.
struct SupervisorEntry {
    /// The exact client connection that owns this query (result target).
    owner: ConnTx,
    /// A desktop reply that arrived while the owner was gone, held for the
    /// redelivery window until the same id is re-queried (or GC).
    stored: Option<String>,
    /// Creation time (for the 300s GC — tool-loops can exceed 60s).
    created: Instant,
}

/// Relay routing decision for a `supervisor_query` from a client.
#[derive(Debug, PartialEq, Eq)]
pub enum SupervisorQueryDecision {
    /// A stored reply exists for this id — the caller replays it to the
    /// requester and does NOT forward to the desktop.
    Replay(String),
    /// The id is in-flight and was re-owned to the requesting connection — do
    /// not forward.
    Reowned,
    /// The account is at the pending cap — the caller synthesizes an error.
    Capacity,
    /// A fresh entry was inserted — the caller forwards the query VERBATIM.
    Forward,
}

/// Outcome of resolving a desktop supervisor reply.
#[derive(Debug, PartialEq, Eq)]
pub enum SupervisorResolveOutcome {
    /// Delivered to the owning connection; entry removed.
    Delivered,
    /// Owner connection gone — reply parked for redelivery.
    Stored,
    /// No pending entry for this id — caller drops the reply.
    Unknown,
}

/// Outcome of governing a single `PTY_FILE_CHUNK`.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkDecision {
    /// Owned by an active upload and within budget — forward to the desktop.
    Forward,
    /// No active begin, not owned by this connection, or already finished.
    Drop,
    /// Byte budget exceeded — the upload was severed; the caller sends a
    /// relay-originated failure result to the owner (which is this connection).
    Overrun,
}

/// Outcome of governing a single `PTY_FILE_DOWNLOAD_CHUNK` from the desktop.
/// Each variant carries the owning client connection to route to (except
/// `Drop`, where no owner is known).
#[derive(Debug)]
pub enum DownloadChunkDecision {
    /// Owned by an active download and within budget — forward to the owner.
    Forward(ConnTx),
    /// No active download for this id (unknown/finished/severed) — drop.
    Drop,
    /// Byte budget exceeded — the download was severed; the caller sends a
    /// relay-originated failure `file_download_end` to the owner.
    Overrun(ConnTx),
}

/// Per-account state tracked by the broker.
struct AccountState {
    desktop_tx: Option<ConnTx>,
    /// Features the online desktop advertised at registration.
    desktop_capabilities: Option<Vec<String>>,
    /// Active file uploads keyed by upload_id.
    uploads: HashMap<String, UploadEntry>,
    /// Active file downloads keyed by download_id.
    downloads: HashMap<String, DownloadEntry>,
    /// Pending supervisor queries keyed by query id.
    supervisor_pending: HashMap<String, SupervisorEntry>,
    clients: Vec<ClientConnection>,
    pending_devices: Vec<PendingDevice>,
    /// Connections whose session_list_request has been forwarded to the
    /// desktop, in order. The desktop answers requests sequentially and
    /// prefixes each reply burst with replay_begin, so the front of this
    /// queue is the connection the next burst belongs to.
    replay_queue: VecDeque<ReplayRequest>,
    /// Connection currently receiving a replay burst (scrollback frames up
    /// to the trailing session_list). None = broadcast (old desktop fallback).
    replay_target: Option<ReplayRequest>,
}

impl AccountState {
    fn new() -> Self {
        Self {
            desktop_tx: None,
            desktop_capabilities: None,
            uploads: HashMap::new(),
            downloads: HashMap::new(),
            supervisor_pending: HashMap::new(),
            clients: Vec::new(),
            pending_devices: Vec::new(),
            replay_queue: VecDeque::new(),
            replay_target: None,
        }
    }
}

const MAX_CLIENTS: usize = 10;
const MAX_TOTAL_CONNECTIONS: usize = 50;
const MAX_REPLAY_QUEUE: usize = 64;
/// Hard cap on a single upload's forwarded bytes (also the max declared size).
const MAX_UPLOAD_SIZE: u64 = 25 * 1024 * 1024;
/// Max concurrent uploads per account.
const MAX_ACTIVE_UPLOADS: usize = 8;
/// Hard cap on a single download's forwarded bytes (also caps the declared size).
const MAX_DOWNLOAD_SIZE: u64 = 25 * 1024 * 1024;
/// Max concurrent downloads per account.
const MAX_ACTIVE_DOWNLOADS: usize = 4;
/// Uploads (and downloads) with no activity for this long are garbage-collected.
const UPLOAD_IDLE_TIMEOUT_SECS: u64 = 60;
/// Max concurrent pending supervisor queries per account.
const MAX_PENDING_SUPERVISOR: usize = 8;
/// Supervisor entries older than this (created-based) are garbage-collected.
/// 300s (not 60s): P3 chat tool-loops can exceed 60s.
const SUPERVISOR_GC_SECS: u64 = 300;
/// Pending device approvals older than this (created-based) are expired by the
/// periodic sweep — the waiting client is failed and the desktop's pending list
/// is refreshed, so a never-approved request can't linger in memory or UI.
const PENDING_DEVICE_TTL_SECS: u64 = 600;

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[allow(dead_code)] // retained for API stability; register_desktop is now last-writer-wins
    #[error("desktop already connected for this account")]
    DesktopAlreadyConnected,
    #[error("too many client connections (max {MAX_CLIENTS})")]
    TooManyClients,
    #[error("server at capacity (max {MAX_TOTAL_CONNECTIONS} total connections)")]
    ServerAtCapacity,
    #[error("desktop is offline")]
    DesktopOffline,
    #[error("send failed")]
    SendFailed,
}

/// The central connection broker.
#[derive(Clone)]
pub struct Broker {
    accounts: Arc<RwLock<HashMap<String, AccountState>>>,
    total_connections: Arc<AtomicUsize>,
}

impl Broker {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            total_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Check if the server can accept another connection.
    pub fn try_acquire_connection(&self) -> Result<(), BrokerError> {
        let current = self.total_connections.load(Ordering::Relaxed);
        if current >= MAX_TOTAL_CONNECTIONS {
            return Err(BrokerError::ServerAtCapacity);
        }
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Release a connection slot.
    pub fn release_connection(&self) {
        self.total_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current total connection count.
    pub fn total_connection_count(&self) -> usize {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Register a desktop connection for an account (last-writer-wins).
    ///
    /// If a desktop socket is already registered it is evicted (sent a Close)
    /// and replaced by the new one. This prevents a reconnect deadlock: when a
    /// desktop's TCP socket drops uncleanly it can linger as "online" while the
    /// desktop's backoff loop opens a fresh connection — without eviction the
    /// new connection would be refused until the stale socket times out.
    pub async fn register_desktop(
        &self,
        username: &str,
        tx: ConnTx,
        capabilities: Option<Vec<String>>,
    ) -> Result<(), BrokerError> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        if let Some(old) = state.desktop_tx.take() {
            let _ = old.send(WsMessage::Close);
            tracing::info!(
                username = %username,
                "evicting stale desktop connection (last-writer-wins)"
            );
        }
        state.desktop_tx = Some(tx);
        state.desktop_capabilities = capabilities.clone();
        // Replay bookkeeping belongs to the previous desktop connection.
        state.replay_queue.clear();
        state.replay_target = None;
        // NOTE: the pending-device reconciliation snapshot is deliberately NOT
        // sent here. The desktop handshake is strict — the very next text frame
        // after `desktop_register` must be `desktop_registered`, or the client
        // aborts. Queuing a `pending_devices_list` before the ack caused a
        // reconnect storm. The caller (server.rs) sends the ack FIRST, then
        // calls `push_pending_devices_list` to replay the pending set (even when
        // empty — an empty list clears stale local state).
        // Notify all clients that desktop came online, advertising its features.
        // The desktop being registered is NOT in `state.clients` (a desktop-key
        // connection never calls register_client), so this loop cannot enqueue
        // to the registering desktop's own outbound_tx and race the ack.
        let online_msg = WsMessage::Text(
            serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                online: true,
                capabilities,
            })
            .unwrap_or_default(),
        );
        for client in &state.clients {
            let _ = client.tx.send(online_msg.clone());
        }
        Ok(())
    }

    /// Unregister a desktop connection.
    ///
    /// `conn` is the disconnecting connection: when a stale desktop socket
    /// (evicted by last-writer-wins) finally dies, its cleanup must NOT wipe
    /// the registration of the desktop that replaced it.
    pub async fn unregister_desktop(&self, username: &str, conn: &ConnTx) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            // Free uploads owned by the dying connection (desktop bug-report
            // publishes) before the stale-desktop early return, mirroring the
            // client cleanup in unregister_client — a crashed publish must not
            // hold its buffer and upload slot until the idle sweep.
            state.uploads.retain(|_, e| !e.owner.same_conn(conn));
            match &state.desktop_tx {
                Some(current) if !current.same_conn(conn) => {
                    tracing::info!(
                        username = %username,
                        "stale desktop disconnect ignored (already replaced)"
                    );
                    return;
                }
                _ => {}
            }
            state.desktop_tx = None;
            state.desktop_capabilities = None;
            state.replay_queue.clear();
            state.replay_target = None;
            // Notify all clients that desktop went offline
            let offline_msg = WsMessage::Text(
                serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                    online: false,
                    capabilities: None,
                })
                .unwrap_or_default(),
            );
            for client in &state.clients {
                if client.tx.send(offline_msg.clone()).is_err() {
                    tracing::warn!(
                        username = %username,
                        device_id = %client.info.device_id,
                        "failed to send desktop-offline notification (client gone)"
                    );
                }
            }
        }
    }

    /// Register a client connection, keyed by the CONNECTION, not device_id.
    ///
    /// Re-registering the same socket (re-auth after approval) updates in
    /// place. A second connection from the same device (two PWA tabs, browser
    /// tab + installed PWA) coexists — device-keyed replacement silently
    /// evicted the older tab from the output fan-out while its socket stayed
    /// open: input kept working, output went permanently dead.
    pub async fn register_client(
        &self,
        username: &str,
        tx: ConnTx,
        info: ClientInfo,
    ) -> Result<(), BrokerError> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        if let Some(existing) = state.clients.iter_mut().find(|c| c.tx.same_conn(&tx)) {
            existing.tx = tx.clone();
            existing.info = info;
            Self::replay_desktop_status(state, &tx);
            // In-place re-register (re-auth after approval) can change the
            // device name/ip — keep the desktop's connected list current.
            Self::send_connected_devices(state);
            return Ok(());
        }
        if state.clients.len() >= MAX_CLIENTS {
            return Err(BrokerError::TooManyClients);
        }
        state.clients.push(ClientConnection {
            tx: tx.clone(),
            info,
        });
        // A client that connects AFTER the desktop registered would otherwise
        // never hear its capabilities (DesktopStatus is only emitted on change),
        // leaving upload/bug-report UI hidden against a capable desktop.
        Self::replay_desktop_status(state, &tx);
        // Push the updated connected-device roster to the desktop so its
        // sidebar reflects the new device without a manual refresh.
        Self::send_connected_devices(state);
        Ok(())
    }

    /// Send the current desktop online/capability state to one just-joined
    /// client. No-op when no desktop is registered — the client's optimistic
    /// default covers that until a real status change arrives.
    fn replay_desktop_status(state: &AccountState, tx: &ConnTx) {
        if state.desktop_tx.is_none() {
            return;
        }
        let msg = WsMessage::Text(
            serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                online: true,
                capabilities: state.desktop_capabilities.clone(),
            })
            .unwrap_or_default(),
        );
        let _ = tx.send(msg);
    }

    /// Unregister ONE client connection (socket close). Other connections
    /// from the same device stay registered.
    pub async fn unregister_client(&self, username: &str, _device_id: &str, conn: &ConnTx) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            state.clients.retain(|c| !c.tx.same_conn(conn));
            state.replay_queue.retain(|r| !r.tx.same_conn(conn));
            // Drop any uploads this connection owned so their slots free up.
            state.uploads.retain(|_, e| !e.owner.same_conn(conn));
            // Same for downloads it requested — a client that closes mid-stream
            // must not hold its download slot until the idle sweep.
            state.downloads.retain(|_, e| !e.owner.same_conn(conn));
            // A mid-burst disconnect leaves replay_target pointing at the
            // gone connection on purpose: the remaining frames of that burst
            // drop harmlessly instead of broadcasting to everyone, and the
            // trailing session_list clears the target.
            Self::send_connected_devices(state);
        }
    }

    /// Remove EVERY connection of a device (revocation) — unlike socket
    /// cleanup, this is device-scoped by design.
    pub async fn unregister_device(&self, username: &str, device_id: &str) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            state.clients.retain(|c| c.info.device_id != device_id);
            state.replay_queue.retain(|r| r.device_id != device_id);
            Self::send_connected_devices(state);
        }
    }

    /// A client requested the session list: queue its CONNECTION for targeted
    /// replay routing and let its live output flow again (the replay it just
    /// asked for is the convergence point).
    pub async fn note_session_list_request(
        &self,
        username: &str,
        device_id: &str,
        conn: &ConnTx,
    ) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            if state.replay_queue.len() < MAX_REPLAY_QUEUE {
                state.replay_queue.push_back(ReplayRequest {
                    device_id: device_id.to_string(),
                    tx: conn.clone(),
                });
            }
            conn.clear_dirty();
        }
    }

    /// Desktop announced a replay burst: route it to the oldest queued
    /// requester. None (empty queue / old desktop) falls back to broadcast.
    pub async fn begin_replay(&self, username: &str) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            state.replay_target = state.replay_queue.pop_front();
        }
    }

    /// The session_list that terminates a replay burst: returns the exact
    /// connection to route it to (clearing the target), or None to broadcast.
    pub async fn end_replay(&self, username: &str) -> Option<ConnTx> {
        let mut accounts = self.accounts.write().await;
        Some(accounts.get_mut(username)?.replay_target.take()?.tx)
    }

    /// Connection currently receiving a replay burst, if any.
    pub async fn replay_target(&self, username: &str) -> Option<ConnTx> {
        let accounts = self.accounts.read().await;
        Some(accounts.get(username)?.replay_target.as_ref()?.tx.clone())
    }

    /// Device id of the current replay target (diagnostics/tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn replay_target_device(&self, username: &str) -> Option<String> {
        let accounts = self.accounts.read().await;
        Some(accounts.get(username)?.replay_target.as_ref()?.device_id.clone())
    }

    /// Check if a desktop is connected for a given account.
    pub async fn is_desktop_online(&self, username: &str) -> bool {
        let accounts = self.accounts.read().await;
        accounts
            .get(username)
            .map(|s| s.desktop_tx.is_some())
            .unwrap_or(false)
    }

    /// Send a message from a client to the desktop.
    pub async fn send_to_desktop(
        &self,
        username: &str,
        msg: WsMessage,
    ) -> Result<(), BrokerError> {
        let accounts = self.accounts.read().await;
        let state = accounts.get(username).ok_or(BrokerError::DesktopOffline)?;
        let tx = state.desktop_tx.as_ref().ok_or(BrokerError::DesktopOffline)?;
        tx.send(msg).map_err(|_| BrokerError::SendFailed)
    }

    /// Drop uploads idle past the timeout. Called lazily on every upload
    /// message for the account (there is no periodic sweep task).
    fn gc_uploads(state: &mut AccountState) {
        let now = Instant::now();
        state
            .uploads
            .retain(|_, e| now.duration_since(e.last_activity).as_secs() < UPLOAD_IDLE_TIMEOUT_SECS);
    }

    /// Govern a `file_upload_begin`. Returns Ok to forward to the desktop, or
    /// Err(reason) — the caller then sends a relay-originated failure result to
    /// the sender and does NOT forward.
    pub async fn begin_upload(
        &self,
        username: &str,
        upload_id: &str,
        size: u64,
        conn: &ConnTx,
    ) -> Result<(), &'static str> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        Self::gc_uploads(state);
        if size > MAX_UPLOAD_SIZE {
            return Err("file_too_large");
        }
        if state.uploads.len() >= MAX_ACTIVE_UPLOADS {
            return Err("too_many_uploads");
        }
        if state.uploads.contains_key(upload_id) {
            return Err("duplicate_upload_id");
        }
        state.uploads.insert(
            upload_id.to_string(),
            UploadEntry {
                owner: conn.clone(),
                declared_size: size,
                bytes_forwarded: 0,
                last_activity: Instant::now(),
                finished: false,
                buffer: None,
            },
        );
        Ok(())
    }

    /// Mark an in-flight upload as a `bug_report` so its forwarded chunks are
    /// buffered at the relay for persistence. Only the owning connection can
    /// mark its own upload; a no-op if the upload/owner is gone.
    pub async fn mark_bug_report_upload(&self, username: &str, upload_id: &str, conn: &ConnTx) {
        let mut accounts = self.accounts.write().await;
        let Some(state) = accounts.get_mut(username) else {
            return;
        };
        if let Some(entry) = state.uploads.get_mut(upload_id) {
            if entry.owner.same_conn(conn) {
                entry.buffer = Some(Vec::new());
            }
        }
    }

    /// Take a finished bug report's buffered bytes for persistence. Returns
    /// `Some(bytes)` only when the upload is a `bug_report` owned by `conn`
    /// (bytes may be empty = no screenshot); `None` for any other upload. The
    /// governance entry is left in place for the normal result-routing path.
    pub async fn take_bug_report_buffer(
        &self,
        username: &str,
        upload_id: &str,
        conn: &ConnTx,
    ) -> Option<Vec<u8>> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        let entry = state.uploads.get_mut(upload_id)?;
        if !entry.owner.same_conn(conn) {
            return None;
        }
        entry.buffer.take()
    }

    /// Govern one `PTY_FILE_CHUNK`. See `ChunkDecision`.
    pub async fn record_upload_chunk(
        &self,
        username: &str,
        upload_id: &str,
        conn: &ConnTx,
        payload: &[u8],
    ) -> ChunkDecision {
        let mut accounts = self.accounts.write().await;
        let Some(state) = accounts.get_mut(username) else {
            return ChunkDecision::Drop;
        };
        Self::gc_uploads(state);
        let Some(entry) = state.uploads.get_mut(upload_id) else {
            return ChunkDecision::Drop;
        };
        if entry.finished || !entry.owner.same_conn(conn) {
            return ChunkDecision::Drop;
        }
        entry.bytes_forwarded += payload.len() as u64;
        entry.last_activity = Instant::now();
        let budget = entry.declared_size.min(MAX_UPLOAD_SIZE);
        if entry.bytes_forwarded > budget {
            state.uploads.remove(upload_id);
            return ChunkDecision::Overrun;
        }
        // Buffer bug-report payloads for persistence (within budget by the
        // check above); no-op for every other kind.
        if let Some(buf) = entry.buffer.as_mut() {
            buf.extend_from_slice(payload);
        }
        ChunkDecision::Forward
    }

    /// Mark an upload finished (from `file_upload_end`). Only the owning
    /// connection can finish its own upload; the entry lingers until the
    /// desktop's result arrives so the result can be routed back.
    pub async fn finish_upload(&self, username: &str, upload_id: &str, conn: &ConnTx) {
        let mut accounts = self.accounts.write().await;
        let Some(state) = accounts.get_mut(username) else {
            return;
        };
        Self::gc_uploads(state);
        if let Some(entry) = state.uploads.get_mut(upload_id) {
            if entry.owner.same_conn(conn) {
                entry.finished = true;
                entry.last_activity = Instant::now();
            }
        }
    }

    /// Resolve a `file_upload_result` from the desktop: remove the upload's
    /// governance entry and return the owning connection to route the result
    /// to. None means the owner is gone/unknown — the caller drops the result.
    pub async fn resolve_upload(&self, username: &str, upload_id: &str) -> Option<ConnTx> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        Self::gc_uploads(state);
        state.uploads.remove(upload_id).map(|e| e.owner)
    }

    /// Drop downloads idle past the timeout. Called lazily on every download
    /// message for the account (mirrors `gc_uploads`; no periodic sweep task).
    fn gc_downloads(state: &mut AccountState) {
        let now = Instant::now();
        state
            .downloads
            .retain(|_, e| now.duration_since(e.last_activity).as_secs() < UPLOAD_IDLE_TIMEOUT_SECS);
    }

    /// Govern a `file_download_request` from a client. Registers
    /// `download_id → requesting connection` so begin/end/chunk traffic can be
    /// routed back. Returns Ok to forward the request to the desktop, or
    /// Err(reason) — the caller then synthesizes a failure `file_download_end`
    /// to the requesting client and does NOT forward.
    pub async fn register_download(
        &self,
        username: &str,
        download_id: &str,
        conn: &ConnTx,
    ) -> Result<(), &'static str> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        Self::gc_downloads(state);
        if state.downloads.len() >= MAX_ACTIVE_DOWNLOADS {
            return Err("too many active downloads");
        }
        state.downloads.insert(
            download_id.to_string(),
            DownloadEntry {
                owner: conn.clone(),
                declared_size: None,
                bytes_forwarded: 0,
                last_activity: Instant::now(),
            },
        );
        Ok(())
    }

    /// Route a `file_download_begin` from the desktop: record the declared size
    /// for byte budgeting and return the owning client connection. None means
    /// the download_id is unknown — the caller drops the begin.
    pub async fn note_download_begin(
        &self,
        username: &str,
        download_id: &str,
        size: u64,
    ) -> Option<ConnTx> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        Self::gc_downloads(state);
        let entry = state.downloads.get_mut(download_id)?;
        entry.declared_size = Some(size);
        entry.last_activity = Instant::now();
        Some(entry.owner.clone())
    }

    /// Govern one `PTY_FILE_DOWNLOAD_CHUNK` from the desktop. Accounts the bytes
    /// against the declared size / `MAX_DOWNLOAD_SIZE` and severs the download
    /// on overrun. See `DownloadChunkDecision`.
    pub async fn record_download_chunk(
        &self,
        username: &str,
        download_id: &str,
        payload: &[u8],
    ) -> DownloadChunkDecision {
        let mut accounts = self.accounts.write().await;
        let Some(state) = accounts.get_mut(username) else {
            return DownloadChunkDecision::Drop;
        };
        Self::gc_downloads(state);
        let Some(entry) = state.downloads.get_mut(download_id) else {
            return DownloadChunkDecision::Drop;
        };
        entry.bytes_forwarded += payload.len() as u64;
        entry.last_activity = Instant::now();
        let budget = entry.declared_size.unwrap_or(MAX_DOWNLOAD_SIZE).min(MAX_DOWNLOAD_SIZE);
        if entry.bytes_forwarded > budget {
            let owner = entry.owner.clone();
            state.downloads.remove(download_id);
            return DownloadChunkDecision::Overrun(owner);
        }
        DownloadChunkDecision::Forward(entry.owner.clone())
    }

    /// Resolve a `file_download_end` from the desktop: remove the download's
    /// governance entry and return the owning connection to route the end to.
    /// None means the owner is gone/unknown — the caller drops the end.
    pub async fn resolve_download(&self, username: &str, download_id: &str) -> Option<ConnTx> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        Self::gc_downloads(state);
        state.downloads.remove(download_id).map(|e| e.owner)
    }

    /// Drop supervisor entries older than the GC window (created-based). Called
    /// opportunistically on every supervisor message (no periodic sweep task,
    /// mirroring `gc_uploads`).
    fn gc_supervisor(state: &mut AccountState) {
        let now = Instant::now();
        state
            .supervisor_pending
            .retain(|_, e| now.duration_since(e.created).as_secs() < SUPERVISOR_GC_SECS);
    }

    /// Route a `supervisor_query` from a client. Implements steps 2–5 of the
    /// wire contract (step 1, desktop-offline, is handled by the caller):
    /// stored-result replay, in-flight re-own, cap reject, else insert. The
    /// `kind` is never inspected here — routing is purely by `id`.
    pub async fn begin_supervisor_query(
        &self,
        username: &str,
        id: &str,
        conn: &ConnTx,
    ) -> SupervisorQueryDecision {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        Self::gc_supervisor(state);
        if let Some(entry) = state.supervisor_pending.get_mut(id) {
            // Step 2: a reply is parked → replay to this connection, remove entry.
            if let Some(stored) = entry.stored.take() {
                state.supervisor_pending.remove(id);
                return SupervisorQueryDecision::Replay(stored);
            }
            // Step 3: in-flight → re-own to the (re)issuing connection.
            entry.owner = conn.clone();
            return SupervisorQueryDecision::Reowned;
        }
        // Step 4: cap.
        if state.supervisor_pending.len() >= MAX_PENDING_SUPERVISOR {
            return SupervisorQueryDecision::Capacity;
        }
        // Step 5: insert.
        state.supervisor_pending.insert(
            id.to_string(),
            SupervisorEntry {
                owner: conn.clone(),
                stored: None,
                created: Instant::now(),
            },
        );
        SupervisorQueryDecision::Forward
    }

    /// Resolve a desktop `supervisor_result` / `supervisor_error` by id. Tries
    /// to deliver to the owning connection; on success removes the entry, on
    /// send failure parks the serialized reply for redelivery. Unknown id →
    /// caller drops. NEVER broadcasts.
    pub async fn resolve_supervisor(
        &self,
        username: &str,
        id: &str,
        msg: WsMessage,
    ) -> SupervisorResolveOutcome {
        let mut accounts = self.accounts.write().await;
        let Some(state) = accounts.get_mut(username) else {
            return SupervisorResolveOutcome::Unknown;
        };
        Self::gc_supervisor(state);
        let Some(entry) = state.supervisor_pending.get_mut(id) else {
            return SupervisorResolveOutcome::Unknown;
        };
        let serialized = match &msg {
            WsMessage::Text(t) => t.clone(),
            _ => String::new(),
        };
        if entry.owner.send(msg).is_ok() {
            state.supervisor_pending.remove(id);
            SupervisorResolveOutcome::Delivered
        } else {
            entry.stored = Some(serialized);
            SupervisorResolveOutcome::Stored
        }
    }

    /// Broadcast a message from the desktop to all connected clients.
    ///
    /// Live PTY output goes through the per-client budget/dirty policy:
    /// a client that can't drain fast enough stops receiving output and is
    /// nudged (rate-limited) to resync, instead of silently losing frames
    /// and rendering a corrupted screen until the next full reconnect.
    pub async fn broadcast_to_clients(&self, username: &str, msg: WsMessage) {
        let accounts = self.accounts.read().await;
        let Some(state) = accounts.get(username) else { return };

        if !msg.is_pty_output() {
            for client in &state.clients {
                let _ = client.tx.send(msg.clone());
            }
            return;
        }

        // Focus scoping: skipped frames are never queued, so they don't count
        // toward the client's budget or trip the dirty/resync cycle.
        let session_id = msg.pty_output_session().map(str::to_owned);
        for client in &state.clients {
            if let Some(sid) = session_id.as_deref() {
                if !client.tx.wants_session(sid) {
                    continue;
                }
            }
            if client.tx.send_output(msg.clone()) {
                tracing::warn!(
                    username = %username,
                    device_id = %client.info.device_id,
                    "backpressure: pausing live output for slow client, requesting resync"
                );
                self.nudge_resync(client);
            }
        }
    }

    /// Send resync_required to a freshly-dirty client, at most once per
    /// RESYNC_MIN_INTERVAL_SECS. Spawned off the caller's lock scope-free
    /// clone so the broadcast path never blocks on the rate-limit mutex.
    fn nudge_resync(&self, client: &ClientConnection) {
        let tx = client.tx.clone();
        let device_id = client.info.device_id.clone();
        tokio::spawn(async move {
            let mut last = tx.last_resync.lock().await;
            let now = Instant::now();
            if let Some(prev) = *last {
                if now.duration_since(prev).as_secs() < RESYNC_MIN_INTERVAL_SECS {
                    return;
                }
            }
            *last = Some(now);
            drop(last);
            tracing::info!(device_id = %device_id, "sending resync_required");
            let _ = tx.send(WsMessage::Text(
                serde_json::to_string(&crate::protocol::ControlMessage::ResyncRequired)
                    .unwrap_or_default(),
            ));
        });
    }

    /// Send a message to every connection of a device. Multiple connections
    /// can share a device_id (two tabs on one device); each gates or handles
    /// the message itself. Ok when at least one delivery succeeded.
    pub async fn send_to_client(
        &self,
        username: &str,
        device_id: &str,
        msg: WsMessage,
    ) -> Result<(), BrokerError> {
        let accounts = self.accounts.read().await;
        let state = accounts.get(username).ok_or(BrokerError::SendFailed)?;
        let mut delivered = false;
        for client in state.clients.iter().filter(|c| c.info.device_id == device_id) {
            if client.tx.send(msg.clone()).is_ok() {
                delivered = true;
            }
        }
        if delivered {
            Ok(())
        } else {
            Err(BrokerError::SendFailed)
        }
    }

    /// Add a pending device approval request.
    pub async fn add_pending_device(&self, username: &str, pending: PendingDevice) {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        state.pending_devices.push(pending);
    }

    /// Take a pending device by device_id (removes it from pending list).
    pub async fn take_pending_device(
        &self,
        username: &str,
        device_id: &str,
    ) -> Option<PendingDevice> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        let idx = state
            .pending_devices
            .iter()
            .position(|p| p.device_id == device_id)?;
        Some(state.pending_devices.remove(idx))
    }

    /// Remove a pending device by the CONNECTION that is waiting on it — the
    /// ghost-cleanup path when an unapproved client's socket closes before the
    /// desktop acts. Returns the removed entry (if any) so the caller can
    /// refresh the desktop's pending list.
    pub async fn remove_pending_by_conn(
        &self,
        username: &str,
        conn: &ConnTx,
    ) -> Option<PendingDevice> {
        let mut accounts = self.accounts.write().await;
        let state = accounts.get_mut(username)?;
        let idx = state
            .pending_devices
            .iter()
            .position(|p| p.client_tx.same_conn(conn))?;
        Some(state.pending_devices.remove(idx))
    }

    /// Expire pending device approvals older than the TTL across every account.
    /// Returns `(username, entry)` for each expired request so the caller can
    /// fail the waiting client and refresh the affected desktops.
    pub async fn gc_pending_devices(&self) -> Vec<(String, PendingDevice)> {
        let mut accounts = self.accounts.write().await;
        let now = Instant::now();
        let mut expired = Vec::new();
        for (username, state) in accounts.iter_mut() {
            let mut i = 0;
            while i < state.pending_devices.len() {
                if now.duration_since(state.pending_devices[i].created).as_secs()
                    >= PENDING_DEVICE_TTL_SECS
                {
                    let p = state.pending_devices.remove(i);
                    expired.push((username.clone(), p));
                } else {
                    i += 1;
                }
            }
        }
        expired
    }

    /// Push the current pending-device set to `username`'s desktop connection.
    /// No-op when no desktop is registered. Safe to call after the pending set
    /// changes (add/take/remove/expire) — it re-locks, so callers must not hold
    /// the accounts lock.
    pub async fn push_pending_devices_list(&self, username: &str) {
        let accounts = self.accounts.read().await;
        if let Some(state) = accounts.get(username) {
            Self::send_pending_devices(state);
        }
    }

    /// Serialize the account's pending devices and send them to its desktop.
    /// Sent even when empty — an empty list is what clears stale desktop UI.
    /// Assumes the caller holds the accounts lock (no re-lock).
    fn send_pending_devices(state: &AccountState) {
        let Some(desktop) = state.desktop_tx.as_ref() else {
            return;
        };
        let devices: Vec<_> = state
            .pending_devices
            .iter()
            .map(|p| crate::protocol::PendingDeviceInfo {
                device_id: p.device_id.clone(),
                device_name: p.device_name.clone(),
                ip: p.ip.clone(),
                requested_at: Some(p.requested_at),
            })
            .collect();
        let msg = crate::protocol::ControlMessage::PendingDevicesList { devices };
        let _ = desktop.send(WsMessage::Text(
            serde_json::to_string(&msg).unwrap_or_default(),
        ));
    }

    /// Serialize the account's connected devices (deduped by device_id) and send
    /// them to its desktop. Assumes the caller holds the accounts lock.
    fn send_connected_devices(state: &AccountState) {
        let Some(desktop) = state.desktop_tx.as_ref() else {
            return;
        };
        let mut seen = std::collections::HashSet::new();
        let devices: Vec<_> = state
            .clients
            .iter()
            .filter(|c| seen.insert(c.info.device_id.clone()))
            .map(|c| crate::protocol::DeviceInfo {
                id: c.info.device_id.clone(),
                name: c.info.device_name.clone(),
                ip: c.info.ip.clone(),
                connected_at: c.info.connected_at.clone(),
            })
            .collect();
        let msg = crate::protocol::ControlMessage::ConnectedDevicesList { devices };
        let _ = desktop.send(WsMessage::Text(
            serde_json::to_string(&msg).unwrap_or_default(),
        ));
    }

    /// Get info about all connected clients for an account, deduped by
    /// device_id (two tabs on one device are still one device to the user).
    pub async fn get_connected_clients(&self, username: &str) -> Vec<ClientInfo> {
        let accounts = self.accounts.read().await;
        let Some(state) = accounts.get(username) else {
            return Vec::new();
        };
        let mut seen = std::collections::HashSet::new();
        state
            .clients
            .iter()
            .filter(|c| seen.insert(c.info.device_id.clone()))
            .map(|c| c.info.clone())
            .collect()
    }

    /// Send a shutdown message to all connections.
    pub async fn broadcast_shutdown(&self) {
        let accounts = self.accounts.read().await;
        let shutdown_msg = WsMessage::Text(
            serde_json::to_string(&crate::protocol::ControlMessage::RelayShuttingDown)
                .unwrap_or_default(),
        );
        for state in accounts.values() {
            if let Some(ref tx) = state.desktop_tx {
                let _ = tx.send(shutdown_msg.clone());
            }
            for client in &state.clients {
                let _ = client.tx.send(shutdown_msg.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: a ConnTx with its own counter plus the raw receiver.
    fn test_conn() -> (ConnTx, mpsc::UnboundedReceiver<WsMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (ConnTx::new(tx, Arc::new(AtomicUsize::new(0))), rx)
    }

    #[tokio::test]
    async fn test_replay_routing_targets_requester() {
        let broker = Broker::new();
        let (dtx, _drx) = test_conn();
        broker.register_desktop("alice", dtx, None).await.unwrap();

        let mut txs = Vec::new();
        for (dev, name) in [("dev-1", "Phone"), ("dev-2", "Laptop")] {
            let (tx, _rx) = test_conn();
            let info = ClientInfo {
                device_id: dev.into(),
                device_name: name.into(),
                ip: "1.2.3.4".into(),
                connected_at: "now".into(),
            };
            broker.register_client("alice", tx.clone(), info).await.unwrap();
            txs.push(tx);
        }

        // No request queued: replay falls back to broadcast (None target).
        broker.begin_replay("alice").await;
        assert!(broker.replay_target("alice").await.is_none());

        // dev-2 asks for the list; the next burst belongs to its CONNECTION.
        broker.note_session_list_request("alice", "dev-2", &txs[1]).await;
        broker.begin_replay("alice").await;
        assert_eq!(
            broker.replay_target_device("alice").await.as_deref(),
            Some("dev-2")
        );
        assert!(broker
            .replay_target("alice")
            .await
            .unwrap()
            .same_conn(&txs[1]));

        // The trailing session_list consumes the target.
        assert!(broker.end_replay("alice").await.unwrap().same_conn(&txs[1]));
        assert!(broker.replay_target("alice").await.is_none());

        // Two queued requests resolve in FIFO order.
        broker.note_session_list_request("alice", "dev-1", &txs[0]).await;
        broker.note_session_list_request("alice", "dev-2", &txs[1]).await;
        broker.begin_replay("alice").await;
        assert!(broker.end_replay("alice").await.unwrap().same_conn(&txs[0]));
        broker.begin_replay("alice").await;
        assert!(broker.end_replay("alice").await.unwrap().same_conn(&txs[1]));
    }

    /// Build a PTY_OUTPUT frame with the desktop's header layout (type byte +
    /// 36-byte space-padded session id + payload).
    fn output_frame(session_id: &str, payload: &[u8]) -> WsMessage {
        let mut buf = vec![PTY_OUTPUT];
        let mut padded = [b' '; 36];
        let id = session_id.as_bytes();
        padded[..id.len().min(36)].copy_from_slice(&id[..id.len().min(36)]);
        buf.extend_from_slice(&padded);
        buf.extend_from_slice(payload);
        WsMessage::Binary(buf)
    }

    #[tokio::test]
    async fn test_focus_scopes_live_output() {
        let broker = Broker::new();
        let (dtx, _drx) = test_conn();
        broker.register_desktop("alice", dtx, None).await.unwrap();

        let (focused, mut focused_rx) = test_conn();
        let (unscoped, mut unscoped_rx) = test_conn();
        for (dev, tx) in [("dev-f", &focused), ("dev-u", &unscoped)] {
            let info = ClientInfo {
                device_id: dev.into(),
                device_name: dev.into(),
                ip: "1.2.3.4".into(),
                connected_at: "now".into(),
            };
            broker.register_client("alice", tx.clone(), info).await.unwrap();
        }
        focused.set_focus(vec!["sess-a".into()]);

        // Drain the roster/device broadcasts registration pushed to both
        // clients so the assertions below see only PTY output frames.
        while focused_rx.try_recv().is_ok() {}
        while unscoped_rx.try_recv().is_ok() {}

        // Output for an unfocused session: only the unscoped client gets it.
        broker.broadcast_to_clients("alice", output_frame("sess-b", b"x")).await;
        assert!(focused_rx.try_recv().is_err());
        assert!(unscoped_rx.try_recv().is_ok());

        // Output for the focused session: both get it.
        broker.broadcast_to_clients("alice", output_frame("sess-a", b"y")).await;
        assert!(focused_rx.try_recv().is_ok());
        assert!(unscoped_rx.try_recv().is_ok());

        // Empty focus clears scoping.
        focused.set_focus(Vec::new());
        broker.broadcast_to_clients("alice", output_frame("sess-b", b"z")).await;
        assert!(focused_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_backpressure_marks_dirty_and_recovers() {
        let (tx, mut rx) = test_conn();

        // Under budget: output flows.
        let small = WsMessage::Binary(vec![PTY_OUTPUT, 0, 0]);
        assert!(!tx.send_output(small.clone()));
        assert!(rx.try_recv().is_ok());

        // Blow the budget without draining: marked dirty, nudge requested,
        // frame NOT delivered.
        let huge = WsMessage::Binary({
            let mut v = vec![PTY_OUTPUT];
            v.resize(CLIENT_OUTPUT_BUDGET_BYTES + 1, 0);
            v
        });
        assert!(tx.send_output(huge.clone()));
        assert!(rx.try_recv().is_err());

        // While dirty, further output is skipped silently (no second nudge).
        assert!(!tx.send_output(small.clone()));
        assert!(rx.try_recv().is_err());

        // A session_list_request clears the flag; output flows again.
        tx.clear_dirty();
        assert!(!tx.send_output(small));
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_desktop_registration() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.register_desktop("alice", tx.clone(), None).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // Second registration wins (last-writer-wins): the stale socket is
        // evicted and the new one takes over — still online, no error.
        let (tx2, _rx2) = test_conn();
        broker.register_desktop("alice", tx2.clone(), None).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // The evicted stale connection's disconnect cleanup must NOT wipe
        // the replacement's registration.
        broker.unregister_desktop("alice", &tx).await;
        assert!(broker.is_desktop_online("alice").await);

        // Unregister by the current connection works, then re-register.
        broker.unregister_desktop("alice", &tx2).await;
        assert!(!broker.is_desktop_online("alice").await);
        broker.register_desktop("alice", tx, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_client_registration_and_limit() {
        let broker = Broker::new();
        for i in 0..MAX_CLIENTS {
            let (tx, _rx) = test_conn();
            let info = ClientInfo {
                device_id: format!("dev-{i}"),
                device_name: format!("Device {i}"),
                ip: "1.2.3.4".into(),
                connected_at: "2026-01-01T00:00:00Z".into(),
            };
            broker.register_client("alice", tx, info).await.unwrap();
        }

        // 11th should fail
        let (tx, _rx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-extra".into(),
            device_name: "Extra".into(),
            ip: "1.2.3.4".into(),
            connected_at: "2026-01-01T00:00:00Z".into(),
        };
        let err = broker.register_client("alice", tx, info).await.unwrap_err();
        assert!(matches!(err, BrokerError::TooManyClients));
    }

    #[tokio::test]
    async fn test_message_routing_to_desktop() {
        let broker = Broker::new();
        let (tx, mut rx) = test_conn();
        broker.register_desktop("alice", tx, None).await.unwrap();
        // register_desktop no longer queues any frame — the pending snapshot is
        // pushed by the server AFTER the desktop_registered ack.
        assert!(rx.try_recv().is_err());

        broker
            .send_to_desktop("alice", WsMessage::Text("hello".into()))
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            WsMessage::Text(t) => assert_eq!(t, "hello"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn test_broadcast_to_clients() {
        let broker = Broker::new();
        let (tx1, mut rx1) = test_conn();
        let (tx2, mut rx2) = test_conn();

        let info1 = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        let info2 = ClientInfo {
            device_id: "dev-2".into(),
            device_name: "Laptop".into(),
            ip: "5.6.7.8".into(),
            connected_at: "now".into(),
        };

        broker.register_client("alice", tx1, info1).await.unwrap();
        broker.register_client("alice", tx2, info2).await.unwrap();

        broker
            .broadcast_to_clients("alice", WsMessage::Text("update".into()))
            .await;

        match rx1.recv().await.unwrap() {
            WsMessage::Text(t) => assert_eq!(t, "update"),
            _ => panic!("expected text"),
        }
        match rx2.recv().await.unwrap() {
            WsMessage::Text(t) => assert_eq!(t, "update"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn test_send_to_specific_client() {
        let broker = Broker::new();
        let (tx1, mut rx1) = test_conn();
        let (tx2, mut rx2) = test_conn();

        let info1 = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        let info2 = ClientInfo {
            device_id: "dev-2".into(),
            device_name: "Laptop".into(),
            ip: "5.6.7.8".into(),
            connected_at: "now".into(),
        };

        broker.register_client("alice", tx1, info1).await.unwrap();
        broker.register_client("alice", tx2, info2).await.unwrap();

        broker
            .send_to_client("alice", "dev-2", WsMessage::Text("for laptop".into()))
            .await
            .unwrap();

        // rx2 should have the message
        match rx2.recv().await.unwrap() {
            WsMessage::Text(t) => assert_eq!(t, "for laptop"),
            _ => panic!("expected text"),
        }
        // rx1 should be empty
        assert!(rx1.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_pending_device() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let pending = PendingDevice {
            device_id: "pending-1".into(),
            device_name: "New Phone".into(),
            ip: "1.2.3.4".into(),
            client_tx: tx,
            created: Instant::now(),
            requested_at: 0,
        };
        broker.add_pending_device("alice", pending).await;

        let taken = broker.take_pending_device("alice", "pending-1").await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().device_name, "New Phone");

        // Second take should return None
        assert!(broker.take_pending_device("alice", "pending-1").await.is_none());
    }

    #[tokio::test]
    async fn test_remove_pending_by_conn() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let (other, _orx) = test_conn();
        broker
            .add_pending_device(
                "alice",
                PendingDevice {
                    device_id: "pending-1".into(),
                    device_name: "New Phone".into(),
                    ip: "1.2.3.4".into(),
                    client_tx: tx.clone(),
                    created: Instant::now(),
                    requested_at: 0,
                },
            )
            .await;

        // A different connection removes nothing.
        assert!(broker.remove_pending_by_conn("alice", &other).await.is_none());
        // The owning connection removes its own entry.
        let removed = broker.remove_pending_by_conn("alice", &tx).await;
        assert_eq!(removed.unwrap().device_id, "pending-1");
        assert!(broker.remove_pending_by_conn("alice", &tx).await.is_none());
    }

    #[tokio::test]
    async fn test_gc_pending_devices_expires_old_entries() {
        let broker = Broker::new();
        let (fresh_tx, _f) = test_conn();
        let (old_tx, _o) = test_conn();
        // A fresh entry (created now) must survive.
        broker
            .add_pending_device(
                "alice",
                PendingDevice {
                    device_id: "fresh".into(),
                    device_name: "Fresh".into(),
                    ip: "1.1.1.1".into(),
                    client_tx: fresh_tx,
                    created: Instant::now(),
                    requested_at: 0,
                },
            )
            .await;
        // An entry created well past the TTL must be expired.
        broker
            .add_pending_device(
                "alice",
                PendingDevice {
                    device_id: "stale".into(),
                    device_name: "Stale".into(),
                    ip: "2.2.2.2".into(),
                    client_tx: old_tx,
                    created: Instant::now()
                        - std::time::Duration::from_secs(PENDING_DEVICE_TTL_SECS + 1),
                    requested_at: 0,
                },
            )
            .await;

        let expired = broker.gc_pending_devices().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, "alice");
        assert_eq!(expired[0].1.device_id, "stale");
        // The fresh one is still pending; the stale one is gone.
        assert!(broker.take_pending_device("alice", "fresh").await.is_some());
        assert!(broker.take_pending_device("alice", "stale").await.is_none());
    }

    #[tokio::test]
    async fn test_pending_devices_list_pushed_to_desktop() {
        let broker = Broker::new();
        let (dtx, mut drx) = test_conn();
        broker.register_desktop("alice", dtx, None).await.unwrap();
        // register_desktop no longer queues a snapshot; nothing to drain.
        assert!(drx.try_recv().is_err());

        let (ctx, _crx) = test_conn();
        broker
            .add_pending_device(
                "alice",
                PendingDevice {
                    device_id: "pending-1".into(),
                    device_name: "New Phone".into(),
                    ip: "1.2.3.4".into(),
                    client_tx: ctx,
                    created: Instant::now(),
                    requested_at: 42,
                },
            )
            .await;
        broker.push_pending_devices_list("alice").await;

        // The desktop received a pending_devices_list carrying the entry.
        let mut saw_list = false;
        while let Ok(msg) = drx.try_recv() {
            if let WsMessage::Text(t) = msg {
                if t.contains("pending_devices_list") && t.contains("pending-1") {
                    saw_list = true;
                }
            }
        }
        assert!(saw_list, "desktop must receive pending_devices_list");
    }

    #[tokio::test]
    async fn test_unregister_client() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", tx.clone(), info).await.unwrap();
        assert_eq!(broker.get_connected_clients("alice").await.len(), 1);

        broker.unregister_client("alice", "dev-1", &tx).await;
        assert_eq!(broker.get_connected_clients("alice").await.len(), 0);
    }

    /// Two connections from the SAME device (two PWA tabs) must coexist:
    /// device-keyed replacement used to evict the older tab from the output
    /// fan-out (input kept working, output went permanently dead) and the
    /// newer tab's disconnect then wiped the survivor's registration.
    #[tokio::test]
    async fn test_same_device_twin_connections() {
        let broker = Broker::new();
        let (tx1, mut rx1) = test_conn();
        let (tx2, mut rx2) = test_conn();
        let info = |name: &str| ClientInfo {
            device_id: "dev-1".into(),
            device_name: name.into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };

        broker.register_client("alice", tx1.clone(), info("Tab A")).await.unwrap();
        broker.register_client("alice", tx2.clone(), info("Tab B")).await.unwrap();

        // Both connections receive broadcasts.
        broker
            .broadcast_to_clients("alice", WsMessage::Text("update".into()))
            .await;
        assert!(rx1.try_recv().is_ok(), "tab A must still receive output");
        assert!(rx2.try_recv().is_ok(), "tab B must receive output");

        // Device-targeted sends reach both tabs.
        broker
            .send_to_client("alice", "dev-1", WsMessage::Text("targeted".into()))
            .await
            .unwrap();
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());

        // The device list shows ONE device, not two.
        assert_eq!(broker.get_connected_clients("alice").await.len(), 1);

        // Tab B closing must not deregister Tab A.
        broker.unregister_client("alice", "dev-1", &tx2).await;
        broker
            .broadcast_to_clients("alice", WsMessage::Text("after-close".into()))
            .await;
        assert!(rx1.try_recv().is_ok(), "tab A must survive tab B's close");

        // Revocation is device-scoped: removes every remaining connection.
        broker.unregister_device("alice", "dev-1").await;
        assert_eq!(broker.get_connected_clients("alice").await.len(), 0);
    }

    /// Re-registering the SAME connection (re-auth after device approval)
    /// must update in place, not create a duplicate entry.
    #[tokio::test]
    async fn test_same_conn_reregistration_updates_in_place() {
        let broker = Broker::new();
        let (tx, mut rx) = test_conn();
        let info = |name: &str| ClientInfo {
            device_id: "dev-1".into(),
            device_name: name.into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", tx.clone(), info("Pending")).await.unwrap();
        broker.register_client("alice", tx.clone(), info("Approved")).await.unwrap();

        let clients = broker.get_connected_clients("alice").await;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].device_name, "Approved");

        // One broadcast → exactly one delivery.
        broker
            .broadcast_to_clients("alice", WsMessage::Text("once".into()))
            .await;
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "duplicate registration would double-send");
    }

    #[tokio::test]
    async fn test_upload_begin_rejects_oversize() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let err = broker
            .begin_upload("alice", "u1", MAX_UPLOAD_SIZE + 1, &tx)
            .await
            .unwrap_err();
        assert_eq!(err, "file_too_large");
    }

    #[tokio::test]
    async fn test_upload_begin_rejects_ninth_concurrent() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        for i in 0..MAX_ACTIVE_UPLOADS {
            broker
                .begin_upload("alice", &format!("u{i}"), 1024, &tx)
                .await
                .unwrap();
        }
        let err = broker
            .begin_upload("alice", "u-extra", 1024, &tx)
            .await
            .unwrap_err();
        assert_eq!(err, "too_many_uploads");
    }

    #[tokio::test]
    async fn test_upload_begin_rejects_duplicate_id() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.begin_upload("alice", "u1", 1024, &tx).await.unwrap();
        let err = broker
            .begin_upload("alice", "u1", 1024, &tx)
            .await
            .unwrap_err();
        assert_eq!(err, "duplicate_upload_id");
    }

    #[tokio::test]
    async fn test_chunk_without_begin_is_dropped() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        assert_eq!(
            broker.record_upload_chunk("alice", "ghost", &tx, &[0u8; 512]).await,
            ChunkDecision::Drop
        );
    }

    #[tokio::test]
    async fn test_chunk_from_non_owner_is_dropped() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        let (other, _xrx) = test_conn();
        broker.begin_upload("alice", "u1", 4096, &owner).await.unwrap();
        // A different connection cannot push chunks into someone else's upload.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &other, &[0u8; 512]).await,
            ChunkDecision::Drop
        );
        // The owner's chunk is forwarded.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &owner, &[0u8; 512]).await,
            ChunkDecision::Forward
        );
    }

    #[tokio::test]
    async fn test_chunk_overrun_severs_upload() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.begin_upload("alice", "u1", 1000, &tx).await.unwrap();
        // Within budget.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, &[0u8; 800]).await,
            ChunkDecision::Forward
        );
        // Exceeds declared size → overrun; upload state is dropped.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, &[0u8; 300]).await,
            ChunkDecision::Overrun
        );
        // Now there's no active begin — subsequent chunks are dropped.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, &[0u8; 10]).await,
            ChunkDecision::Drop
        );
    }

    #[tokio::test]
    async fn test_finished_upload_ignores_further_chunks() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.begin_upload("alice", "u1", 4096, &tx).await.unwrap();
        broker.finish_upload("alice", "u1", &tx).await;
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, &[0u8; 512]).await,
            ChunkDecision::Drop
        );
    }

    #[tokio::test]
    async fn test_bug_report_buffers_chunks_and_takes_them() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.begin_upload("alice", "u1", 4096, &tx).await.unwrap();
        broker.mark_bug_report_upload("alice", "u1", &tx).await;
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, b"\x89PNG").await,
            ChunkDecision::Forward
        );
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, b"more").await,
            ChunkDecision::Forward
        );
        // Buffer holds the concatenated payloads.
        let bytes = broker.take_bug_report_buffer("alice", "u1", &tx).await.unwrap();
        assert_eq!(bytes, b"\x89PNGmore");
        // A second take yields nothing (buffer already consumed).
        assert!(broker.take_bug_report_buffer("alice", "u1", &tx).await.is_none());
    }

    #[tokio::test]
    async fn test_unmarked_upload_is_not_buffered() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        broker.begin_upload("alice", "u1", 4096, &tx).await.unwrap();
        // Never marked as a bug report.
        assert_eq!(
            broker.record_upload_chunk("alice", "u1", &tx, b"data").await,
            ChunkDecision::Forward
        );
        // Not a bug report → take returns None.
        assert!(broker.take_bug_report_buffer("alice", "u1", &tx).await.is_none());
    }

    #[tokio::test]
    async fn test_upload_result_routes_to_owner_only() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        let (other, _xrx) = test_conn();
        broker.begin_upload("alice", "u1", 4096, &owner).await.unwrap();

        let routed = broker.resolve_upload("alice", "u1").await.unwrap();
        assert!(routed.same_conn(&owner));
        assert!(!routed.same_conn(&other));
        // Entry is cleared: a second resolve finds nothing.
        assert!(broker.resolve_upload("alice", "u1").await.is_none());
    }

    #[tokio::test]
    async fn test_upload_cleared_when_owner_disconnects() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", tx.clone(), info).await.unwrap();
        broker.begin_upload("alice", "u1", 4096, &tx).await.unwrap();
        broker.unregister_client("alice", "dev-1", &tx).await;
        // The upload slot is freed — the id is no longer active.
        assert!(broker.resolve_upload("alice", "u1").await.is_none());
    }

    #[tokio::test]
    async fn test_download_register_rejects_fifth_concurrent() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        for i in 0..MAX_ACTIVE_DOWNLOADS {
            broker
                .register_download("alice", &format!("d{i}"), &tx)
                .await
                .unwrap();
        }
        let err = broker
            .register_download("alice", "d-extra", &tx)
            .await
            .unwrap_err();
        assert_eq!(err, "too many active downloads");
    }

    #[tokio::test]
    async fn test_download_begin_and_end_route_to_owner_only() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        let (other, _xrx) = test_conn();
        broker.register_download("alice", "d1", &owner).await.unwrap();

        // begin records the declared size and returns the owner.
        let begin_owner = broker.note_download_begin("alice", "d1", 4096).await.unwrap();
        assert!(begin_owner.same_conn(&owner));
        assert!(!begin_owner.same_conn(&other));

        // end removes the entry and returns the owner.
        let end_owner = broker.resolve_download("alice", "d1").await.unwrap();
        assert!(end_owner.same_conn(&owner));
        // Entry is cleared: a second resolve finds nothing.
        assert!(broker.resolve_download("alice", "d1").await.is_none());
    }

    #[tokio::test]
    async fn test_download_chunk_routes_to_owner_and_forwards() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        broker.register_download("alice", "d1", &owner).await.unwrap();
        broker.note_download_begin("alice", "d1", 4096).await.unwrap();

        match broker.record_download_chunk("alice", "d1", &[0u8; 512]).await {
            DownloadChunkDecision::Forward(tx) => assert!(tx.same_conn(&owner)),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_download_chunk_without_download_is_dropped() {
        let broker = Broker::new();
        assert!(matches!(
            broker.record_download_chunk("alice", "ghost", &[0u8; 512]).await,
            DownloadChunkDecision::Drop
        ));
    }

    #[tokio::test]
    async fn test_download_chunk_overrun_severs_download() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        broker.register_download("alice", "d1", &owner).await.unwrap();
        broker.note_download_begin("alice", "d1", 1000).await.unwrap();
        // Within budget.
        assert!(matches!(
            broker.record_download_chunk("alice", "d1", &[0u8; 800]).await,
            DownloadChunkDecision::Forward(_)
        ));
        // Exceeds declared size → overrun; download state is dropped, owner returned.
        match broker.record_download_chunk("alice", "d1", &[0u8; 300]).await {
            DownloadChunkDecision::Overrun(tx) => assert!(tx.same_conn(&owner)),
            other => panic!("expected Overrun, got {other:?}"),
        }
        // Now there's no active download — subsequent chunks are dropped.
        assert!(matches!(
            broker.record_download_chunk("alice", "d1", &[0u8; 10]).await,
            DownloadChunkDecision::Drop
        ));
    }

    #[tokio::test]
    async fn test_download_cleared_when_owner_disconnects() {
        let broker = Broker::new();
        let (tx, _rx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", tx.clone(), info).await.unwrap();
        broker.register_download("alice", "d1", &tx).await.unwrap();
        broker.unregister_client("alice", "dev-1", &tx).await;
        // The download slot is freed — the id is no longer active.
        assert!(broker.resolve_download("alice", "d1").await.is_none());
    }

    #[tokio::test]
    async fn test_desktop_capabilities_reach_client_status() {
        let broker = Broker::new();
        let (ctx, mut crx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", ctx, info).await.unwrap();

        let (dtx, _drx) = test_conn();
        broker
            .register_desktop("alice", dtx, Some(vec!["file_upload".into()]))
            .await
            .unwrap();

        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("desktop_status"));
                assert!(t.contains("\"online\":true"));
                assert!(t.contains("file_upload"));
            }
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn test_desktop_offline_notification() {
        let broker = Broker::new();
        let (dtx, _drx) = test_conn();
        broker.register_desktop("alice", dtx.clone(), None).await.unwrap();

        let (ctx, mut crx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", ctx, info).await.unwrap();

        // Registering while the desktop is online replays an online status first.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("desktop_status"));
                assert!(t.contains("true"));
            }
            _ => panic!("expected text"),
        }

        broker.unregister_desktop("alice", &dtx).await;

        // Then the offline notification when the desktop drops.
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("desktop_status"));
                assert!(t.contains("false"));
            }
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn test_client_join_replays_desktop_capabilities() {
        let broker = Broker::new();
        let (dtx, _drx) = test_conn();
        let caps = Some(vec!["file_upload_v1".to_string()]);
        broker.register_desktop("alice", dtx, caps).await.unwrap();

        // A client connecting AFTER the desktop must still learn its caps.
        let (ctx, mut crx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", ctx, info).await.unwrap();

        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("desktop_status"));
                assert!(t.contains("true"));
                assert!(t.contains("file_upload_v1"));
            }
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn test_supervisor_query_decision_lifecycle() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();

        // First query for an id → inserted, forward to desktop.
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-1", &owner).await,
            SupervisorQueryDecision::Forward
        );
        // Same id in-flight, re-issued from another connection → re-owned.
        let (owner2, mut orx2) = test_conn();
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-1", &owner2).await,
            SupervisorQueryDecision::Reowned
        );
        // Desktop reply is delivered to the current owner (owner2), entry cleared.
        assert_eq!(
            broker
                .resolve_supervisor("alice", "sq-1", WsMessage::Text("r".into()))
                .await,
            SupervisorResolveOutcome::Delivered
        );
        assert!(matches!(orx2.try_recv().unwrap(), WsMessage::Text(t) if t == "r"));
        // Entry gone → a second resolve is unknown.
        assert_eq!(
            broker
                .resolve_supervisor("alice", "sq-1", WsMessage::Text("r".into()))
                .await,
            SupervisorResolveOutcome::Unknown
        );
    }

    #[tokio::test]
    async fn test_supervisor_store_then_replay_on_reconnect() {
        let broker = Broker::new();
        let (conn1, rx1) = test_conn();
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-x", &conn1).await,
            SupervisorQueryDecision::Forward
        );
        // Owner's receiver is gone → desktop reply is parked, not delivered.
        drop(rx1);
        assert_eq!(
            broker
                .resolve_supervisor("alice", "sq-x", WsMessage::Text("payload".into()))
                .await,
            SupervisorResolveOutcome::Stored
        );
        // Same id re-issued from a new connection → the parked reply replays.
        let (conn2, _rx2) = test_conn();
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-x", &conn2).await,
            SupervisorQueryDecision::Replay("payload".into())
        );
        // Entry removed after replay: re-issuing again inserts fresh (Forward).
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-x", &conn2).await,
            SupervisorQueryDecision::Forward
        );
    }

    #[tokio::test]
    async fn test_supervisor_cap_rejects_ninth() {
        let broker = Broker::new();
        let (owner, _orx) = test_conn();
        for i in 0..MAX_PENDING_SUPERVISOR {
            assert_eq!(
                broker.begin_supervisor_query("alice", &format!("sq-{i}"), &owner).await,
                SupervisorQueryDecision::Forward
            );
        }
        assert_eq!(
            broker.begin_supervisor_query("alice", "sq-extra", &owner).await,
            SupervisorQueryDecision::Capacity
        );
    }
}

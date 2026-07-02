use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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
}

/// Per-account state tracked by the broker.
struct AccountState {
    desktop_tx: Option<ConnTx>,
    clients: Vec<ClientConnection>,
    pending_devices: Vec<PendingDevice>,
    /// device_ids whose session_list_request has been forwarded to the
    /// desktop, in order. The desktop answers requests sequentially and
    /// prefixes each reply burst with replay_begin, so the front of this
    /// queue is the client the next burst belongs to.
    replay_queue: VecDeque<String>,
    /// Client currently receiving a replay burst (scrollback frames up to
    /// the trailing session_list). None = broadcast (old desktop fallback).
    replay_target: Option<String>,
}

impl AccountState {
    fn new() -> Self {
        Self {
            desktop_tx: None,
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
        // Replay bookkeeping belongs to the previous desktop connection.
        state.replay_queue.clear();
        state.replay_target = None;
        // Notify all clients that desktop came online
        let online_msg = WsMessage::Text(
            serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                online: true,
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
            state.replay_queue.clear();
            state.replay_target = None;
            // Notify all clients that desktop went offline
            let offline_msg = WsMessage::Text(
                serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                    online: false,
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

    /// Register a client connection. If a client with the same device_id
    /// already exists (e.g. re-auth after approval), update its sender.
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
        if let Some(existing) = state.clients.iter_mut().find(|c| c.info.device_id == info.device_id) {
            existing.tx = tx;
            existing.info = info;
            return Ok(());
        }
        if state.clients.len() >= MAX_CLIENTS {
            return Err(BrokerError::TooManyClients);
        }
        state.clients.push(ClientConnection { tx, info });
        Ok(())
    }

    /// Unregister a client connection by device_id.
    pub async fn unregister_client(&self, username: &str, device_id: &str) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            state.clients.retain(|c| c.info.device_id != device_id);
            state.replay_queue.retain(|d| d != device_id);
            // A mid-burst disconnect leaves replay_target pointing at the
            // gone device on purpose: the remaining frames of that burst
            // drop harmlessly instead of broadcasting to everyone, and the
            // trailing session_list clears the target.
        }
    }

    /// A client requested the session list: queue it for targeted replay
    /// routing and let its live output flow again (the replay it just asked
    /// for is the convergence point).
    pub async fn note_session_list_request(&self, username: &str, device_id: &str) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            if state.replay_queue.len() < MAX_REPLAY_QUEUE {
                state.replay_queue.push_back(device_id.to_string());
            }
            if let Some(client) = state.clients.iter().find(|c| c.info.device_id == device_id) {
                client.tx.clear_dirty();
            }
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

    /// The session_list that terminates a replay burst: returns the device to
    /// route it to (clearing the target), or None to broadcast.
    pub async fn end_replay(&self, username: &str) -> Option<String> {
        let mut accounts = self.accounts.write().await;
        accounts.get_mut(username)?.replay_target.take()
    }

    /// Current replay-burst recipient, if any.
    pub async fn replay_target(&self, username: &str) -> Option<String> {
        let accounts = self.accounts.read().await;
        accounts.get(username)?.replay_target.clone()
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

        for client in &state.clients {
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

    /// Send a message to a specific client by device_id.
    pub async fn send_to_client(
        &self,
        username: &str,
        device_id: &str,
        msg: WsMessage,
    ) -> Result<(), BrokerError> {
        let accounts = self.accounts.read().await;
        let state = accounts.get(username).ok_or(BrokerError::SendFailed)?;
        let client = state
            .clients
            .iter()
            .find(|c| c.info.device_id == device_id)
            .ok_or(BrokerError::SendFailed)?;
        client.tx.send(msg).map_err(|_| BrokerError::SendFailed)
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

    /// Get info about all connected clients for an account.
    pub async fn get_connected_clients(&self, username: &str) -> Vec<ClientInfo> {
        let accounts = self.accounts.read().await;
        accounts
            .get(username)
            .map(|s| s.clients.iter().map(|c| c.info.clone()).collect())
            .unwrap_or_default()
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
        broker.register_desktop("alice", dtx).await.unwrap();

        for (dev, name) in [("dev-1", "Phone"), ("dev-2", "Laptop")] {
            let (tx, _rx) = test_conn();
            let info = ClientInfo {
                device_id: dev.into(),
                device_name: name.into(),
                ip: "1.2.3.4".into(),
                connected_at: "now".into(),
            };
            broker.register_client("alice", tx, info).await.unwrap();
        }

        // No request queued: replay falls back to broadcast (None target).
        broker.begin_replay("alice").await;
        assert_eq!(broker.replay_target("alice").await, None);

        // dev-2 asks for the list; the next burst belongs to it.
        broker.note_session_list_request("alice", "dev-2").await;
        broker.begin_replay("alice").await;
        assert_eq!(broker.replay_target("alice").await.as_deref(), Some("dev-2"));

        // The trailing session_list consumes the target.
        assert_eq!(broker.end_replay("alice").await.as_deref(), Some("dev-2"));
        assert_eq!(broker.replay_target("alice").await, None);

        // Two queued requests resolve in FIFO order.
        broker.note_session_list_request("alice", "dev-1").await;
        broker.note_session_list_request("alice", "dev-2").await;
        broker.begin_replay("alice").await;
        assert_eq!(broker.end_replay("alice").await.as_deref(), Some("dev-1"));
        broker.begin_replay("alice").await;
        assert_eq!(broker.end_replay("alice").await.as_deref(), Some("dev-2"));
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
        broker.register_desktop("alice", tx.clone()).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // Second registration wins (last-writer-wins): the stale socket is
        // evicted and the new one takes over — still online, no error.
        let (tx2, _rx2) = test_conn();
        broker.register_desktop("alice", tx2.clone()).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // The evicted stale connection's disconnect cleanup must NOT wipe
        // the replacement's registration.
        broker.unregister_desktop("alice", &tx).await;
        assert!(broker.is_desktop_online("alice").await);

        // Unregister by the current connection works, then re-register.
        broker.unregister_desktop("alice", &tx2).await;
        assert!(!broker.is_desktop_online("alice").await);
        broker.register_desktop("alice", tx).await.unwrap();
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
        broker.register_desktop("alice", tx).await.unwrap();

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
        };
        broker.add_pending_device("alice", pending).await;

        let taken = broker.take_pending_device("alice", "pending-1").await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().device_name, "New Phone");

        // Second take should return None
        assert!(broker.take_pending_device("alice", "pending-1").await.is_none());
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
        broker.register_client("alice", tx, info).await.unwrap();
        assert_eq!(broker.get_connected_clients("alice").await.len(), 1);

        broker.unregister_client("alice", "dev-1").await;
        assert_eq!(broker.get_connected_clients("alice").await.len(), 0);
    }

    #[tokio::test]
    async fn test_desktop_offline_notification() {
        let broker = Broker::new();
        let (dtx, _drx) = test_conn();
        broker.register_desktop("alice", dtx.clone()).await.unwrap();

        let (ctx, mut crx) = test_conn();
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", ctx, info).await.unwrap();

        broker.unregister_desktop("alice", &dtx).await;

        // Client should receive desktop_status offline
        match crx.recv().await.unwrap() {
            WsMessage::Text(t) => {
                assert!(t.contains("desktop_status"));
                assert!(t.contains("false"));
            }
            _ => panic!("expected text"),
        }
    }
}

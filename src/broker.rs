use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A message that can be sent over a WebSocket connection.
#[derive(Debug, Clone)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close,
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
    tx: mpsc::Sender<WsMessage>,
    info: ClientInfo,
}

/// Pending device approval request.
#[derive(Debug, Clone)]
pub struct PendingDevice {
    pub device_id: String,
    pub device_name: String,
    pub ip: String,
    pub client_tx: mpsc::Sender<WsMessage>,
}

/// Per-account state tracked by the broker.
struct AccountState {
    desktop_tx: Option<mpsc::Sender<WsMessage>>,
    clients: Vec<ClientConnection>,
    pending_devices: Vec<PendingDevice>,
}

impl AccountState {
    fn new() -> Self {
        Self {
            desktop_tx: None,
            clients: Vec::new(),
            pending_devices: Vec::new(),
        }
    }
}

const MAX_CLIENTS: usize = 10;
const MAX_TOTAL_CONNECTIONS: usize = 50;

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
        tx: mpsc::Sender<WsMessage>,
    ) -> Result<(), BrokerError> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
        if let Some(old) = state.desktop_tx.take() {
            let _ = old.try_send(WsMessage::Close);
            tracing::info!(
                username = %username,
                "evicting stale desktop connection (last-writer-wins)"
            );
        }
        state.desktop_tx = Some(tx);
        Ok(())
    }

    /// Unregister a desktop connection.
    pub async fn unregister_desktop(&self, username: &str) {
        let mut accounts = self.accounts.write().await;
        if let Some(state) = accounts.get_mut(username) {
            state.desktop_tx = None;
            // Notify all clients that desktop went offline
            let offline_msg = WsMessage::Text(
                serde_json::to_string(&crate::protocol::ControlMessage::DesktopStatus {
                    online: false,
                })
                .unwrap_or_default(),
            );
            for client in &state.clients {
                if client.tx.try_send(offline_msg.clone()).is_err() {
                    tracing::warn!(
                        username = %username,
                        device_id = %client.info.device_id,
                        "backpressure: failed to send desktop-offline notification"
                    );
                }
            }
        }
    }

    /// Register a client connection.
    pub async fn register_client(
        &self,
        username: &str,
        tx: mpsc::Sender<WsMessage>,
        info: ClientInfo,
    ) -> Result<(), BrokerError> {
        let mut accounts = self.accounts.write().await;
        let state = accounts
            .entry(username.to_string())
            .or_insert_with(AccountState::new);
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
        }
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
        tx.try_send(msg).map_err(|_| BrokerError::SendFailed)
    }

    /// Broadcast a message from the desktop to all connected clients.
    pub async fn broadcast_to_clients(&self, username: &str, msg: WsMessage) {
        let accounts = self.accounts.read().await;
        if let Some(state) = accounts.get(username) {
            for client in &state.clients {
                if client.tx.try_send(msg.clone()).is_err() {
                    tracing::warn!(
                        username = %username,
                        device_id = %client.info.device_id,
                        "backpressure: dropping message to client (channel full or closed)"
                    );
                }
            }
        }
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
        client.tx.try_send(msg).map_err(|_| BrokerError::SendFailed)
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
                let _ = tx.try_send(shutdown_msg.clone());
            }
            for client in &state.clients {
                let _ = client.tx.try_send(shutdown_msg.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_desktop_registration() {
        let broker = Broker::new();
        let (tx, _rx) = mpsc::channel(16);
        broker.register_desktop("alice", tx.clone()).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // Second registration wins (last-writer-wins): the stale socket is
        // evicted and the new one takes over — still online, no error.
        let (tx2, _rx2) = mpsc::channel(16);
        broker.register_desktop("alice", tx2).await.unwrap();
        assert!(broker.is_desktop_online("alice").await);

        // Unregister and re-register should work
        broker.unregister_desktop("alice").await;
        assert!(!broker.is_desktop_online("alice").await);
        broker.register_desktop("alice", tx).await.unwrap();
    }

    #[tokio::test]
    async fn test_client_registration_and_limit() {
        let broker = Broker::new();
        for i in 0..MAX_CLIENTS {
            let (tx, _rx) = mpsc::channel(16);
            let info = ClientInfo {
                device_id: format!("dev-{i}"),
                device_name: format!("Device {i}"),
                ip: "1.2.3.4".into(),
                connected_at: "2026-01-01T00:00:00Z".into(),
            };
            broker.register_client("alice", tx, info).await.unwrap();
        }

        // 11th should fail
        let (tx, _rx) = mpsc::channel(16);
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
        let (tx, mut rx) = mpsc::channel(16);
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
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);

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
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);

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
        let (tx, _rx) = mpsc::channel(16);
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
        let (tx, _rx) = mpsc::channel(16);
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
        let (dtx, _drx) = mpsc::channel(16);
        broker.register_desktop("alice", dtx).await.unwrap();

        let (ctx, mut crx) = mpsc::channel(16);
        let info = ClientInfo {
            device_id: "dev-1".into(),
            device_name: "Phone".into(),
            ip: "1.2.3.4".into(),
            connected_at: "now".into(),
        };
        broker.register_client("alice", ctx, info).await.unwrap();

        broker.unregister_desktop("alice").await;

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

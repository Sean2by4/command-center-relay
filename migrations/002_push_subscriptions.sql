CREATE TABLE IF NOT EXISTS push_subscriptions (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES accounts(username) ON DELETE CASCADE,
    subscription_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

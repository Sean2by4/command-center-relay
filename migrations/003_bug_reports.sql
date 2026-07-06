CREATE TABLE IF NOT EXISTS bug_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT,
    text TEXT NOT NULL,
    screenshot_path TEXT,
    app_version TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

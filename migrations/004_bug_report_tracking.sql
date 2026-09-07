ALTER TABLE bug_reports ADD COLUMN status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed'));
ALTER TABLE bug_reports ADD COLUMN resolution TEXT;
ALTER TABLE bug_reports ADD COLUMN closed_at TEXT;

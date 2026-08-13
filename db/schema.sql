-- One row per TCP connection the honeypot accepts.
-- session_id ties everything else together for "what did this one
-- attacker do, in order" reconstruction.
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,   -- UUID, generated when connection opens
    source_ip       TEXT NOT NULL,
    source_port     INTEGER NOT NULL,
    started_at      TEXT NOT NULL,      -- ISO 8601 UTC timestamp
    ended_at        TEXT,               -- NULL until the connection closes
    event_count     INTEGER NOT NULL DEFAULT 0,
    closed_reason    TEXT                -- 'client_disconnect' | 'timeout' | 'max_attempts' | 'error'
);

-- One row per meaningful thing that happened within a session:
-- a connection being opened, an auth attempt, a "command" typed after
-- a fake login, etc. This is the append-only ground truth log.
CREATE TABLE IF NOT EXISTS events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,       -- ISO 8601 UTC
    source_ip       TEXT NOT NULL,
    source_port     INTEGER NOT NULL,
    event_type      TEXT NOT NULL,       -- 'connection' | 'auth_attempt' | 'command_attempt' | 'disconnect'
    username        TEXT,                -- NULL unless event_type = 'auth_attempt'
    password        TEXT,                -- NULL unless event_type = 'auth_attempt'
    command_text    TEXT,                -- NULL unless event_type = 'command_attempt'; stored as inert string, NEVER executed
    metadata        TEXT,                -- JSON-encoded string for anything extra (e.g. raw banner negotiation)
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- One row per detection-engine finding.
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    session_id      TEXT,
    rule_name       TEXT NOT NULL,        -- e.g. 'repeated_auth_failure'
    severity        TEXT NOT NULL,        -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    reason          TEXT NOT NULL,        -- human-readable explanation
    event_ids       TEXT,                 -- JSON list of event_id's this alert is based on
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Indexes for the query patterns the dashboard and detection engine
-- actually use: "recent events by IP", "events in a session", "recent alerts".
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

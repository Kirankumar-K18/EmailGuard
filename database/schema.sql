-- EmailGuard SQLite schema. Executed automatically at start-up (idempotent).

CREATE TABLE IF NOT EXISTS email_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    source          TEXT    NOT NULL DEFAULT 'analyzer',      -- analyzer | spoofing_detector | demo_scenario | demo_seed
    is_demo         INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    scenario        TEXT,
    sender          TEXT,
    from_domain     TEXT,
    recipient       TEXT,
    subject         TEXT,
    email_date      TEXT,
    message_id      TEXT,
    risk_score      INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT    NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    classification  TEXT    NOT NULL DEFAULT 'UNVERIFIED',
    report_json     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS authentication_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    mechanism   TEXT    NOT NULL CHECK (mechanism IN ('SPF', 'DKIM', 'DMARC')),
    status      TEXT    NOT NULL,
    method      TEXT    NOT NULL,                             -- DNS | CRYPTOGRAPHIC | NOT PERFORMED
    domain      TEXT,
    details     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER REFERENCES email_analysis(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    severity    TEXT    NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    event_type  TEXT    NOT NULL,                             -- indicator category
    title       TEXT    NOT NULL,
    message     TEXT,
    is_demo     INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1))
);

CREATE TABLE IF NOT EXISTS application_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_analysis_created ON email_analysis(created_at);
CREATE INDEX IF NOT EXISTS idx_analysis_class   ON email_analysis(classification);
CREATE INDEX IF NOT EXISTS idx_auth_analysis    ON authentication_results(analysis_id);
CREATE INDEX IF NOT EXISTS idx_events_analysis  ON security_events(analysis_id);
CREATE INDEX IF NOT EXISTS idx_events_created   ON security_events(created_at);

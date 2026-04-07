"""
Datenbank-Schema für SentinelClaw.

Zentrale Schema-Definition die von beiden Backends (SQLite, PostgreSQL)
genutzt wird. Die Konvertierungsfunktion passt SQLite-spezifische
Syntax an PostgreSQL an.
"""

# Schema-SQL — SQLite-kompatibel, wird für PostgreSQL konvertiert
SCHEMA_SQL = """
-- Scan-Aufträge
CREATE TABLE IF NOT EXISTS scan_jobs (
    id              TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    scan_type       TEXT NOT NULL DEFAULT 'recon',
    status          TEXT NOT NULL DEFAULT 'pending',
    config          TEXT DEFAULT '{}',
    max_escalation_level INTEGER DEFAULT 2,
    token_budget    INTEGER DEFAULT 50000,
    tokens_used     INTEGER DEFAULT 0,
    started_at      TEXT,
    completed_at    TEXT,
    created_at      TEXT NOT NULL
);

-- Findings (einzelne Schwachstellen-Funde)
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    tool_name       TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      REAL DEFAULT 0.0,
    cve_id          TEXT,
    target_host     TEXT NOT NULL,
    target_port     INTEGER,
    service         TEXT,
    description     TEXT DEFAULT '',
    evidence        TEXT DEFAULT '',
    recommendation  TEXT DEFAULT '',
    raw_output      TEXT,
    created_at      TEXT NOT NULL
);

-- Scan-Ergebnisse (Zusammenfassung pro Tool-Aufruf)
CREATE TABLE IF NOT EXISTS scan_results (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    tool_name       TEXT NOT NULL,
    result_type     TEXT NOT NULL,
    findings_json   TEXT DEFAULT '[]',
    raw_output      TEXT,
    severity_counts TEXT DEFAULT '{}',
    duration_seconds REAL DEFAULT 0.0,
    created_at      TEXT NOT NULL
);

-- Scan-Phasen (Fortschritt pro Phase eines Scans)
CREATE TABLE IF NOT EXISTS scan_phases (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    phase_number    INTEGER NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    tool_used       TEXT,
    command_executed TEXT,
    raw_output      TEXT,
    parsed_result   TEXT DEFAULT '{}',
    hosts_found     INTEGER DEFAULT 0,
    ports_found     INTEGER DEFAULT 0,
    findings_found  INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0.0,
    started_at      TEXT,
    completed_at    TEXT,
    error_message   TEXT,
    created_at      TEXT NOT NULL
);

-- Entdeckte Hosts (pro Scan)
CREATE TABLE IF NOT EXISTS discovered_hosts (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    phase_id        TEXT REFERENCES scan_phases(id),
    address         TEXT NOT NULL,
    hostname        TEXT DEFAULT '',
    os_guess        TEXT DEFAULT '',
    state           TEXT DEFAULT 'up',
    created_at      TEXT NOT NULL
);

-- Offene Ports (pro Host)
CREATE TABLE IF NOT EXISTS open_ports (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    phase_id        TEXT REFERENCES scan_phases(id),
    host_address    TEXT NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT DEFAULT 'tcp',
    state           TEXT DEFAULT 'open',
    service         TEXT DEFAULT '',
    version         TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_phases_job ON scan_phases(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_discovered_hosts_job ON discovered_hosts(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_open_ports_job ON open_ports(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_open_ports_host ON open_ports(host_address);

-- Audit-Logs (UNVERÄNDERBAR — kein UPDATE, kein DELETE)
CREATE TABLE IF NOT EXISTS audit_logs (
    id              TEXT PRIMARY KEY,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    details         TEXT DEFAULT '{}',
    triggered_by    TEXT DEFAULT 'system',
    created_at      TEXT NOT NULL
);

-- Agent-Logs (Tool-Aufrufe und Agent-Entscheidungen)
CREATE TABLE IF NOT EXISTS agent_logs (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id),
    agent_name      TEXT NOT NULL,
    step_description TEXT NOT NULL,
    tool_name       TEXT,
    input_params    TEXT DEFAULT '{}',
    output_summary  TEXT DEFAULT '',
    duration_ms     INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_target ON scan_jobs(target);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_agent_logs_scan ON agent_logs(scan_job_id);

-- Chat-Nachrichten (Agent-Chat-System)
CREATE TABLE IF NOT EXISTS chat_messages (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT,
    role            TEXT NOT NULL,
    content         TEXT NOT NULL,
    message_type    TEXT DEFAULT 'text',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_scan ON chat_messages(scan_id);

-- Benutzer-Verwaltung (RBAC)
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN DEFAULT 1,
    mfa_enabled     BOOLEAN DEFAULT 0,
    mfa_secret      TEXT DEFAULT '',
    must_change_password BOOLEAN DEFAULT 0,
    last_login_at   TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Autorisierte Scan-Ziele (Whitelist mit Bestätigung)
CREATE TABLE IF NOT EXISTS authorized_targets (
    id              TEXT PRIMARY KEY,
    target          TEXT UNIQUE NOT NULL,
    confirmed_by    TEXT NOT NULL,
    confirmation    TEXT NOT NULL DEFAULT 'owner',
    notes           TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_targets_target ON authorized_targets(target);

-- Systemweite Einstellungen (Key-Value mit Kategorien)
CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    category    TEXT NOT NULL,
    value_type  TEXT NOT NULL,
    label       TEXT NOT NULL,
    description TEXT DEFAULT '',
    updated_by  TEXT DEFAULT '',
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_settings_category ON system_settings(category);

-- Approval-Requests (Genehmigungsanfragen für Eskalationsstufe 3+)
CREATE TABLE IF NOT EXISTS approval_requests (
    id                  TEXT PRIMARY KEY,
    scan_job_id         TEXT NOT NULL REFERENCES scan_jobs(id),
    requested_by        TEXT NOT NULL,
    action_type         TEXT NOT NULL,
    escalation_level    INTEGER NOT NULL,
    target              TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    description         TEXT NOT NULL,
    risk_assessment     TEXT DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'pending',
    decided_by          TEXT,
    decided_at          TEXT,
    expires_at          TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approvals_scan ON approval_requests(scan_job_id);

-- Benutzerdefinierte Scan-Profile
CREATE TABLE IF NOT EXISTS custom_scan_profiles (
    id                          TEXT PRIMARY KEY,
    name                        TEXT NOT NULL UNIQUE,
    description                 TEXT DEFAULT '',
    ports                       TEXT NOT NULL,
    max_escalation_level        INTEGER DEFAULT 2,
    skip_host_discovery         INTEGER DEFAULT 0,
    skip_vuln_scan              INTEGER DEFAULT 0,
    nmap_extra_flags            TEXT DEFAULT '[]',
    estimated_duration_minutes  INTEGER DEFAULT 5,
    is_builtin                  INTEGER DEFAULT 0,
    created_by                  TEXT DEFAULT '',
    updated_at                  TEXT NOT NULL
);
"""


def convert_schema_for_postgresql(sql: str) -> str:
    """Konvertiert SQLite-spezifische Typen zu PostgreSQL-kompatiblen Typen.

    Ersetzt BOOLEAN DEFAULT 0/1 durch true/false und konvertiert
    Integer-Felder die konzeptionell Booleans sind.
    """
    replacements = [
        ("BOOLEAN DEFAULT 1", "BOOLEAN DEFAULT true"),
        ("BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT false"),
        ("BOOLEAN NOT NULL DEFAULT 1", "BOOLEAN NOT NULL DEFAULT true"),
        # Felder in custom_scan_profiles die als INTEGER gespeichert aber Booleans sind
        ("skip_host_discovery         INTEGER DEFAULT 0",
         "skip_host_discovery         BOOLEAN DEFAULT false"),
        ("skip_vuln_scan              INTEGER DEFAULT 0",
         "skip_vuln_scan              BOOLEAN DEFAULT false"),
        ("is_builtin                  INTEGER DEFAULT 0",
         "is_builtin                  BOOLEAN DEFAULT false"),
    ]
    for old, new in replacements:
        sql = sql.replace(old, new)
    return sql

"""
Datenbank-Manager für SentinelClaw (SQLite im PoC).

Erstellt und verwaltet die SQLite-Datenbank. Das Schema orientiert
sich an ADR-002, nutzt aber SQLite statt PostgreSQL für den PoC.
Migration zu PostgreSQL ist über das Repository-Pattern möglich.
"""

import json
from pathlib import Path
from uuid import UUID

import aiosqlite

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# SQL-Statements für die Schema-Erstellung
_SCHEMA_SQL = """
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

-- Indizes für die neuen Tabellen
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

-- Indizes für häufige Abfragen
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
"""


def _uuid_to_str(value: UUID | str) -> str:
    """Konvertiert UUID zu String für SQLite-Speicherung."""
    return str(value) if isinstance(value, UUID) else value


class DatabaseManager:
    """Verwaltet die SQLite-Datenbankverbindung und Schema-Erstellung."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._connection: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Erstellt die Datenbank und alle Tabellen."""
        # Verzeichnis erstellen falls nötig
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(
            str(self._db_path),
            timeout=30.0,  # 30 Sekunden warten bei "database is locked"
        )

        # WAL-Modus: Erlaubt gleichzeitige Lese- und Schreibzugriffe
        await self._connection.execute("PRAGMA journal_mode=WAL")
        # Busy-Timeout: SQLite wartet bis zu 30s wenn DB gesperrt ist
        await self._connection.execute("PRAGMA busy_timeout=30000")
        # Foreign Keys aktivieren (SQLite hat sie standardmäßig aus)
        await self._connection.execute("PRAGMA foreign_keys=ON")

        # Schema erstellen
        await self._connection.executescript(_SCHEMA_SQL)
        await self._connection.commit()

        logger.info("Datenbank initialisiert", path=str(self._db_path))

    async def get_connection(self) -> aiosqlite.Connection:
        """Gibt die aktive Datenbankverbindung zurück."""
        if self._connection is None:
            await self.initialize()
        assert self._connection is not None, "DB-Verbindung konnte nicht hergestellt werden"
        return self._connection

    async def close(self) -> None:
        """Schließt die Datenbankverbindung."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            logger.info("Datenbankverbindung geschlossen")


def serialize_json(data: dict | list) -> str:
    """Serialisiert Python-Dicts/Listen als JSON-String für SQLite."""
    return json.dumps(data, default=str, ensure_ascii=False)


def deserialize_json(raw: str | None) -> dict | list:
    """Deserialisiert einen JSON-String aus SQLite."""
    if raw is None or raw == "":
        return {}
    return json.loads(raw)

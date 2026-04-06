"""
Schema-Migrationssystem für SentinelClaw.

Verwaltet Datenbankänderungen über versionierte Migrationen.
Jede Migration läuft genau einmal. Die aktuelle Version wird
in der schema_version-Tabelle gespeichert.
"""

from datetime import UTC, datetime

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Alle Migrationen in Reihenfolge. Jede hat eine Version und SQL-Statements.
MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (1, "Basis-Schema", [
        # Leer — das Basis-Schema wird über _SCHEMA_SQL in database.py erstellt
        # Migration 1 markiert nur dass das Basis-Schema vorhanden ist
    ]),
    (2, "MFA-Secret Feld", [
        "ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT ''",
    ]),
    (3, "Approval-Requests Tabelle", [
        """CREATE TABLE IF NOT EXISTS approval_requests (
            id TEXT PRIMARY KEY,
            scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id),
            requested_by TEXT NOT NULL,
            action_type TEXT NOT NULL,
            escalation_level INTEGER NOT NULL,
            target TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_assessment TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            decided_by TEXT,
            decided_at TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status)",
    ]),
    (4, "System-Settings Tabelle", [
        """CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            category TEXT NOT NULL,
            value_type TEXT NOT NULL,
            label TEXT NOT NULL,
            description TEXT DEFAULT '',
            updated_by TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        )""",
    ]),
    (5, "Custom Scan-Profile Tabelle", [
        """CREATE TABLE IF NOT EXISTS custom_scan_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            ports TEXT NOT NULL,
            max_escalation_level INTEGER DEFAULT 2,
            skip_host_discovery INTEGER DEFAULT 0,
            skip_vuln_scan INTEGER DEFAULT 0,
            nmap_extra_flags TEXT DEFAULT '[]',
            estimated_duration_minutes INTEGER DEFAULT 5,
            is_builtin INTEGER DEFAULT 0,
            created_by TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        )""",
    ]),
    (6, "Must-Change-Password Feld", [
        "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0",
    ]),
    (7, "Agent-Reports Tabelle", [
        """CREATE TABLE IF NOT EXISTS agent_reports (
            id              TEXT PRIMARY KEY,
            scan_job_id     TEXT,
            title           TEXT NOT NULL,
            report_type     TEXT NOT NULL DEFAULT 'osint',
            content         TEXT NOT NULL,
            target          TEXT DEFAULT '',
            created_by      TEXT DEFAULT 'agent',
            created_at      TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_agent_reports_type ON agent_reports(report_type)",
    ]),
]


async def run_migrations(db) -> int:
    """Führt alle ausstehenden Migrationen aus.

    Returns:
        Anzahl der ausgeführten Migrationen.
    """
    conn = await db.get_connection()

    # Schema-Version-Tabelle erstellen
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)"
    )
    await conn.commit()

    # Aktuelle Version herausfinden
    cursor = await conn.execute("SELECT MAX(version) FROM schema_version")
    row = await cursor.fetchone()
    current_version = row[0] if row[0] is not None else 0

    applied = 0
    for version, description, statements in MIGRATIONS:
        if version <= current_version:
            continue

        logger.info(f"Migration {version}: {description}")
        for sql in statements:
            try:
                await conn.execute(sql)
            except Exception as error:
                # Ignoriere "duplicate column" Fehler (Migration war teilweise gelaufen)
                if "duplicate" in str(error).lower():
                    logger.debug(f"Migration {version}: Spalte existiert bereits")
                    continue
                raise

        await conn.execute(
            "INSERT INTO schema_version (version, description, applied_at) "
            "VALUES (?, ?, ?)",
            (version, description, datetime.now(UTC).isoformat()),
        )
        await conn.commit()
        applied += 1
        logger.info(f"Migration {version} angewendet: {description}")

    if applied:
        logger.info(
            f"{applied} Migration(en) ausgeführt, "
            f"aktuelle Version: {current_version + applied}"
        )

    return applied

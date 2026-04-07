"""
Schema-Migrationssystem für SentinelClaw.

Verwaltet Datenbankänderungen über versionierte Migrationen.
Jede Migration läuft genau einmal. Die aktuelle Version wird
in der schema_version-Tabelle gespeichert.

Unterstützt sowohl SQLite als auch PostgreSQL — dialektspezifische
SQL-Statements werden über das db_type-Attribut gesteuert.
"""

from datetime import UTC, datetime

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


def _sql_insert_or_ignore(db_type: str, table: str, columns: str, values: str) -> str:
    """Erzeugt INSERT OR IGNORE (SQLite) bzw. ON CONFLICT DO NOTHING (PostgreSQL)."""
    if db_type == "postgresql":
        return f"INSERT INTO {table} ({columns}) VALUES ({values}) ON CONFLICT DO NOTHING"
    return f"INSERT OR IGNORE INTO {table} ({columns}) VALUES ({values})"


def _get_migrations(db_type: str) -> list[tuple[int, str, list[str]]]:
    """Gibt alle Migrationen zurück, angepasst an den Datenbank-Dialekt."""
    return [
        (1, "Basis-Schema", []),
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
            f"""CREATE TABLE IF NOT EXISTS custom_scan_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                ports TEXT NOT NULL,
                max_escalation_level INTEGER DEFAULT 2,
                skip_host_discovery {"BOOLEAN DEFAULT false" if db_type == "postgresql" else "INTEGER DEFAULT 0"},
                skip_vuln_scan {"BOOLEAN DEFAULT false" if db_type == "postgresql" else "INTEGER DEFAULT 0"},
                nmap_extra_flags TEXT DEFAULT '[]',
                estimated_duration_minutes INTEGER DEFAULT 5,
                is_builtin {"BOOLEAN DEFAULT false" if db_type == "postgresql" else "INTEGER DEFAULT 0"},
                created_by TEXT DEFAULT '',
                updated_at TEXT NOT NULL
            )""",
        ]),
        (6, "Must-Change-Password Feld", [
            f"ALTER TABLE users ADD COLUMN must_change_password "
            f"{'BOOLEAN DEFAULT false' if db_type == 'postgresql' else 'BOOLEAN DEFAULT 0'}",
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
        (8, "Chat-Metadata Feld", [
            "ALTER TABLE chat_messages ADD COLUMN metadata TEXT DEFAULT '{}'",
        ]),
        (9, "Revozierte Tokens für serverseitiges Logout", [
            """CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti         TEXT PRIMARY KEY,
                expires_at  TEXT NOT NULL,
                revoked_at  TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at)",
        ]),
        (10, "DSGVO: Einwilligungstracking", [
            f"""CREATE TABLE IF NOT EXISTS consent_records (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                consent_type TEXT NOT NULL,
                granted      {"BOOLEAN NOT NULL DEFAULT true" if db_type == "postgresql" else "BOOLEAN NOT NULL DEFAULT 1"},
                ip_address   TEXT DEFAULT '',
                created_at   TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_consent_user ON consent_records(user_id)",
        ]),
        (11, "DSGVO: Aufbewahrungsfristen-Setting", [
            _sql_insert_or_ignore(
                db_type, "system_settings",
                "key, value, category, value_type, label, description, updated_at",
                "'retention_scan_days', '90', 'dsgvo', 'integer', "
                "'Scan-Aufbewahrung (Tage)', "
                "'Scans älter als N Tage werden automatisch gelöscht (0 = deaktiviert)', "
                f"'{datetime.now(UTC).isoformat()}'",
            ),
            _sql_insert_or_ignore(
                db_type, "system_settings",
                "key, value, category, value_type, label, description, updated_at",
                "'avv_warning_enabled', 'true', 'dsgvo', 'boolean', "
                "'AVV-Warnung bei Cloud-LLM', "
                "'Zeigt Warnung wenn Daten an US-Provider gesendet werden', "
                f"'{datetime.now(UTC).isoformat()}'",
            ),
        ]),
        (12, "Multi-Tenancy: Organizations-Tabelle", [
            """CREATE TABLE IF NOT EXISTS organizations (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL UNIQUE,
                slug        TEXT NOT NULL UNIQUE,
                max_users   INTEGER DEFAULT 10,
                created_at  TEXT NOT NULL
            )""",
            _sql_insert_or_ignore(
                db_type, "organizations",
                "id, name, slug, max_users, created_at",
                f"'default-org', 'Standard', 'standard', 100, "
                f"'{datetime.now(UTC).isoformat()}'",
            ),
        ]),
        (13, "Multi-Tenancy: organization_id auf allen Tabellen", [
            "ALTER TABLE users ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE scan_jobs ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE findings ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE chat_messages ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE approval_requests ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE authorized_targets ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE custom_scan_profiles ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "ALTER TABLE agent_reports ADD COLUMN organization_id TEXT DEFAULT 'default-org'",
            "CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id)",
            "CREATE INDEX IF NOT EXISTS idx_scans_org ON scan_jobs(organization_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id)",
        ]),
    ]


async def run_migrations(db) -> int:
    """Führt alle ausstehenden Migrationen aus.

    Returns:
        Anzahl der ausgeführten Migrationen.
    """
    conn = await db.get_connection()
    db_type = getattr(db, "db_type", "sqlite")
    migrations = _get_migrations(db_type)

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
    for version, description, statements in migrations:
        if version <= current_version:
            continue

        logger.info(f"Migration {version}: {description}")
        for sql in statements:
            try:
                await conn.execute(sql)
            except Exception as error:
                # Ignoriere "duplicate column/table" Fehler (teilweise gelaufene Migration)
                error_str = str(error).lower()
                if "duplicate" in error_str or "already exists" in error_str:
                    logger.debug(f"Migration {version}: Objekt existiert bereits")
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

"""Unit-Tests für den Retention-Service.

Testet automatische Löschung alter Scan-Daten basierend auf
konfigurierbarer Aufbewahrungsfrist (DSGVO).
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from src.shared.database import DatabaseManager
from src.shared.retention_service import run_retention_cleanup


@pytest.fixture
async def db(tmp_path: Path):
    """Frische Test-Datenbank mit Migrationen."""
    manager = DatabaseManager(tmp_path / "test_retention.db")
    await manager.initialize()
    from src.shared.migrations import run_migrations
    await run_migrations(manager)
    yield manager
    await manager.close()


async def _set_retention_days(db: DatabaseManager, days: int) -> None:
    """Setzt die Aufbewahrungsfrist in den System-Settings."""
    conn = await db.get_connection()
    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "INSERT OR REPLACE INTO system_settings "
        "(key, value, category, value_type, label, updated_at) "
        "VALUES (?, ?, 'dsgvo', 'integer', 'Retention', ?)",
        ("retention_scan_days", str(days), now),
    )
    await conn.commit()


async def _create_scan(db: DatabaseManager, days_old: int, status: str = "completed") -> str:
    """Erstellt einen Scan der N Tage alt ist."""
    conn = await db.get_connection()
    scan_id = str(uuid4())
    created_at = (datetime.now(UTC) - timedelta(days=days_old)).isoformat()
    await conn.execute(
        "INSERT INTO scan_jobs (id, target, status, created_at) VALUES (?, ?, ?, ?)",
        (scan_id, "10.10.10.1", status, created_at),
    )
    # Finding hinzufügen
    await conn.execute(
        "INSERT INTO findings (id, scan_job_id, tool_name, title, severity, "
        "target_host, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (str(uuid4()), scan_id, "nmap", "Port offen", "info", "10.10.10.1", created_at),
    )
    await conn.commit()
    return scan_id


class TestRetentionCleanup:
    """Tests für automatische Daten-Retention."""

    async def test_cleanup_disabled_when_zero(self, db):
        """Cleanup ist deaktiviert wenn retention_scan_days=0."""
        await _set_retention_days(db, 0)
        await _create_scan(db, days_old=365)
        deleted = await run_retention_cleanup(db)
        assert deleted == 0

    async def test_cleanup_uses_default_from_migration(self, db):
        """Migration 11 sät retention_scan_days=90 als Default — alte Scans werden gelöscht."""
        await _create_scan(db, days_old=365, status="completed")
        deleted = await run_retention_cleanup(db)
        assert deleted == 1  # 365 Tage > 90 Tage Default

    async def test_old_completed_scans_deleted(self, db):
        """Abgeschlossene Scans älter als Frist werden gelöscht."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=60, status="completed")
        deleted = await run_retention_cleanup(db)
        assert deleted == 1

    async def test_recent_scans_preserved(self, db):
        """Neuere Scans werden nicht gelöscht."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=10, status="completed")
        deleted = await run_retention_cleanup(db)
        assert deleted == 0

    async def test_running_scans_preserved(self, db):
        """Laufende Scans werden nie gelöscht, auch wenn alt."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=60, status="running")
        deleted = await run_retention_cleanup(db)
        assert deleted == 0

    async def test_cascade_deletes_findings(self, db):
        """Löschung kaskadiert zu Findings."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=60, status="completed")
        await run_retention_cleanup(db)
        conn = await db.get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM findings")
        row = await cursor.fetchone()
        assert row[0] == 0

    async def test_mixed_old_and_new_scans(self, db):
        """Nur alte Scans werden gelöscht, neue bleiben."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=60, status="completed")  # Alt → löschen
        await _create_scan(db, days_old=60, status="failed")  # Alt → löschen
        await _create_scan(db, days_old=5, status="completed")  # Neu → behalten
        deleted = await run_retention_cleanup(db)
        assert deleted == 2
        conn = await db.get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM scan_jobs")
        row = await cursor.fetchone()
        assert row[0] == 1

    async def test_multiple_runs_idempotent(self, db):
        """Mehrfaches Ausführen löscht nicht doppelt."""
        await _set_retention_days(db, 30)
        await _create_scan(db, days_old=60, status="completed")
        first = await run_retention_cleanup(db)
        second = await run_retention_cleanup(db)
        assert first == 1
        assert second == 0

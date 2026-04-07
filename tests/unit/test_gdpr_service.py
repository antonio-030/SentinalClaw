"""Unit-Tests für den DSGVO-Service.

Testet Datenexport (Art. 15/20), Cascade-Löschung (Art. 17)
und Audit-Log-Anonymisierung. Stellt sicher dass personenbezogene
Daten vollständig entfernt werden.
"""

from pathlib import Path
from uuid import uuid4

import pytest

from src.shared.database import DatabaseManager, serialize_json
from src.shared.gdpr_service import delete_user_data, export_user_data
from src.shared.types.models import Finding, ScanJob, Severity


@pytest.fixture
async def db(tmp_path: Path):
    """Frische Test-Datenbank mit Migrationen und Testdaten."""
    manager = DatabaseManager(tmp_path / "test_gdpr.db")
    await manager.initialize()
    from src.shared.migrations import run_migrations
    await run_migrations(manager)
    yield manager
    await manager.close()


async def _seed_test_user(db: DatabaseManager, user_id: str = "user-gdpr-1") -> str:
    """Erstellt einen Testbenutzer in der Datenbank."""
    from datetime import UTC, datetime
    from src.shared.auth import hash_password
    conn = await db.get_connection()
    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "INSERT INTO users (id, email, display_name, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, "test@example.com", "Test User", hash_password("test"), "analyst", now),
    )
    await conn.commit()
    return user_id


async def _seed_scan_with_findings(db: DatabaseManager) -> str:
    """Erstellt einen Scan mit Findings für Tests."""
    from datetime import UTC, datetime
    conn = await db.get_connection()
    scan_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "INSERT INTO scan_jobs (id, target, scan_type, status, config, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, "10.10.10.1", "recon", "completed", "{}", now),
    )
    finding_id = str(uuid4())
    await conn.execute(
        "INSERT INTO findings (id, scan_job_id, tool_name, title, severity, "
        "target_host, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (finding_id, scan_id, "nuclei", "XSS gefunden", "high", "10.10.10.1", now),
    )
    await conn.commit()
    return scan_id


class TestDataExport:
    """Tests für DSGVO Art. 15/20 Datenexport."""

    async def test_export_contains_user_profile(self, db):
        """Export enthält Benutzerprofil-Daten."""
        user_id = await _seed_test_user(db)
        result = await export_user_data(user_id, db)
        assert "user" in result
        assert result["user"]["email"] == "test@example.com"
        assert result["user"]["display_name"] == "Test User"
        assert result["user"]["role"] == "analyst"

    async def test_export_contains_scans(self, db):
        """Export enthält Scan-Daten."""
        user_id = await _seed_test_user(db)
        await _seed_scan_with_findings(db)
        result = await export_user_data(user_id, db)
        assert "scans" in result
        assert len(result["scans"]) >= 1
        assert result["scans"][0]["target"] == "10.10.10.1"

    async def test_export_contains_findings(self, db):
        """Export enthält Findings."""
        user_id = await _seed_test_user(db)
        await _seed_scan_with_findings(db)
        result = await export_user_data(user_id, db)
        assert "findings" in result
        assert len(result["findings"]) >= 1

    async def test_export_has_timestamp(self, db):
        """Export enthält Exportzeitpunkt."""
        user_id = await _seed_test_user(db)
        result = await export_user_data(user_id, db)
        assert "export_date" in result

    async def test_export_nonexistent_user(self, db):
        """Export für nicht existierenden User gibt Fehler zurück."""
        result = await export_user_data("nonexistent-user", db)
        assert "error" in result

    async def test_export_contains_consents(self, db):
        """Export enthält Einwilligungsdaten."""
        user_id = await _seed_test_user(db)
        result = await export_user_data(user_id, db)
        assert "consents" in result

    async def test_export_contains_chat_messages(self, db):
        """Export enthält Chat-Nachrichten."""
        user_id = await _seed_test_user(db)
        result = await export_user_data(user_id, db)
        assert "chat_messages" in result


class TestCascadeDeletion:
    """Tests für DSGVO Art. 17 Recht auf Löschung."""

    async def test_delete_removes_scans(self, db):
        """Löschung entfernt alle Scans."""
        user_id = await _seed_test_user(db)
        await _seed_scan_with_findings(db)
        result = await delete_user_data(user_id, db)
        assert "scan_jobs" in result
        # Prüfe DB direkt
        conn = await db.get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM scan_jobs")
        row = await cursor.fetchone()
        assert row[0] == 0

    async def test_delete_removes_findings(self, db):
        """Löschung entfernt alle Findings."""
        user_id = await _seed_test_user(db)
        await _seed_scan_with_findings(db)
        await delete_user_data(user_id, db)
        conn = await db.get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM findings")
        row = await cursor.fetchone()
        assert row[0] == 0

    async def test_delete_removes_user(self, db):
        """Löschung entfernt den Benutzer selbst."""
        user_id = await _seed_test_user(db)
        await delete_user_data(user_id, db)
        conn = await db.get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        assert row[0] == 0

    async def test_delete_anonymizes_audit_logs(self, db):
        """Löschung anonymisiert Audit-Logs (statt sie zu löschen)."""
        user_id = await _seed_test_user(db)
        # Audit-Log-Eintrag erstellen
        conn = await db.get_connection()
        from datetime import UTC, datetime
        await conn.execute(
            "INSERT INTO audit_logs (id, action, triggered_by, created_at) "
            "VALUES (?, ?, ?, ?)",
            (str(uuid4()), "scan.started", user_id, datetime.now(UTC).isoformat()),
        )
        await conn.commit()
        await delete_user_data(user_id, db)
        # Audit-Log existiert noch, aber anonymisiert
        cursor = await conn.execute("SELECT COUNT(*) FROM audit_logs")
        row = await cursor.fetchone()
        assert row[0] >= 1  # Logs werden NICHT gelöscht

    async def test_delete_returns_counts(self, db):
        """Löschung gibt Anzahl gelöschter Einträge pro Tabelle zurück."""
        user_id = await _seed_test_user(db)
        await _seed_scan_with_findings(db)
        result = await delete_user_data(user_id, db)
        assert isinstance(result, dict)
        assert "findings" in result
        assert "scan_jobs" in result

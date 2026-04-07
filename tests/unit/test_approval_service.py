"""Unit-Tests für den Approval-Service.

Testet die Genehmigungslogik für Eskalationsstufe 3+ Tools:
Request-Erstellung, Status-Prüfung und Timeout-Verhalten.
"""

from pathlib import Path

import aiosqlite
import pytest

from src.shared.approval_service import create_approval_request
from src.shared.database import DatabaseManager


@pytest.fixture
async def db(tmp_path: Path):
    """Frische Test-Datenbank mit Migrationen."""
    manager = DatabaseManager(tmp_path / "test_approval.db")
    await manager.initialize()
    from src.shared.migrations import run_migrations
    await run_migrations(manager)
    yield manager
    await manager.close()


async def _ensure_scan_job(db: DatabaseManager, scan_id: str) -> None:
    """Erstellt einen Scan-Job damit FK-Constraints erfüllt sind."""
    from datetime import UTC, datetime
    conn = await db.get_connection()
    await conn.execute(
        "INSERT OR IGNORE INTO scan_jobs (id, target, status, created_at) VALUES (?, ?, ?, ?)",
        (scan_id, "10.10.10.1", "running", datetime.now(UTC).isoformat()),
    )
    await conn.commit()


class TestApprovalRequestCreation:
    """Tests für Approval-Request-Erstellung."""

    async def test_create_request_returns_uuid(self, db):
        """Erstellter Request gibt eine gültige UUID zurück."""
        await _ensure_scan_job(db, "scan-123")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-123", tool_name="metasploit",
            target="10.10.10.1", escalation_level=3,
            description="Exploit-Versuch auf SSH",
        )
        assert isinstance(request_id, str)
        assert len(request_id) == 36

    async def test_request_stored_with_correct_data(self, db):
        """Request wird mit korrekten Daten in der DB gespeichert."""
        await _ensure_scan_job(db, "scan-456")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-456", tool_name="hydra",
            target="10.10.10.2", escalation_level=4,
            description="Brute-Force SSH",
        )
        conn = await db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (request_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row["tool_name"] == "hydra"
        assert row["escalation_level"] == 4
        assert row["status"] == "pending"

    async def test_request_has_expiry(self, db):
        """Request hat ein Ablaufdatum."""
        await _ensure_scan_job(db, "scan-789")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-789", tool_name="sqlmap",
            target="10.10.10.3", escalation_level=3,
        )
        conn = await db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT expires_at FROM approval_requests WHERE id = ?", (request_id,),
        )
        row = await cursor.fetchone()
        assert row["expires_at"] is not None

    async def test_request_requested_by_orchestrator(self, db):
        """Request wird vom Orchestrator gestellt."""
        await _ensure_scan_job(db, "scan-001")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-001", tool_name="john",
            target="10.10.10.4", escalation_level=3,
        )
        conn = await db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT requested_by FROM approval_requests WHERE id = ?", (request_id,),
        )
        row = await cursor.fetchone()
        assert row["requested_by"] == "orchestrator"

    async def test_multiple_requests_for_same_scan(self, db):
        """Mehrere Requests für denselben Scan sind möglich."""
        await _ensure_scan_job(db, "scan-multi")
        id_a = await create_approval_request(
            db=db, scan_job_id="scan-multi", tool_name="hydra",
            target="10.10.10.1", escalation_level=3,
        )
        id_b = await create_approval_request(
            db=db, scan_job_id="scan-multi", tool_name="metasploit",
            target="10.10.10.1", escalation_level=4,
        )
        assert id_a != id_b

    async def test_status_update_to_approved(self, db):
        """Status kann auf 'approved' geändert werden."""
        await _ensure_scan_job(db, "scan-approve")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-approve", tool_name="sqlmap",
            target="10.10.10.5", escalation_level=3,
        )
        conn = await db.get_connection()
        await conn.execute(
            "UPDATE approval_requests SET status = 'approved', "
            "decided_by = 'admin-1', decided_at = datetime('now') "
            "WHERE id = ?",
            (request_id,),
        )
        await conn.commit()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT status, decided_by FROM approval_requests WHERE id = ?",
            (request_id,),
        )
        row = await cursor.fetchone()
        assert row["status"] == "approved"
        assert row["decided_by"] == "admin-1"

    async def test_status_update_to_rejected(self, db):
        """Status kann auf 'rejected' geändert werden."""
        await _ensure_scan_job(db, "scan-reject")
        request_id = await create_approval_request(
            db=db, scan_job_id="scan-reject", tool_name="hydra",
            target="10.10.10.6", escalation_level=3,
        )
        conn = await db.get_connection()
        await conn.execute(
            "UPDATE approval_requests SET status = 'rejected', "
            "decided_by = 'admin-2', decided_at = datetime('now') "
            "WHERE id = ?",
            (request_id,),
        )
        await conn.commit()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT status FROM approval_requests WHERE id = ?", (request_id,),
        )
        row = await cursor.fetchone()
        assert row["status"] == "rejected"

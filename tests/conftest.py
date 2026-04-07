"""Zentrale Test-Fixtures für SentinelClaw.

Stellt wiederverwendbare Fixtures für Datenbank, Repositories,
Auth-Tokens und Factory-Funktionen bereit. Wird automatisch von
pytest in allen Test-Verzeichnissen geladen.
"""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from src.shared.database import DatabaseManager
from src.shared.repositories import (
    AgentLogRepository,
    AuditLogRepository,
    FindingRepository,
    ScanJobRepository,
)
from src.shared.types.models import (
    AuditLogEntry,
    Finding,
    ScanJob,
    ScanStatus,
    ScanType,
    Severity,
)


# --- Datenbank-Fixtures ---

@pytest.fixture
async def db(tmp_path: Path):
    """Erstellt eine isolierte Test-Datenbank pro Test.

    Verwendet pytest tmp_path für automatische Bereinigung.
    """
    db_path = tmp_path / "test_sentinelclaw.db"
    manager = DatabaseManager(db_path)
    await manager.initialize()

    # Migrationen ausführen
    from src.shared.migrations import run_migrations
    await run_migrations(manager)

    yield manager
    await manager.close()


# --- Repository-Fixtures ---

@pytest.fixture
def scan_job_repo(db: DatabaseManager) -> ScanJobRepository:
    return ScanJobRepository(db)


@pytest.fixture
def finding_repo(db: DatabaseManager) -> FindingRepository:
    return FindingRepository(db)


@pytest.fixture
def audit_repo(db: DatabaseManager) -> AuditLogRepository:
    return AuditLogRepository(db)


@pytest.fixture
def agent_log_repo(db: DatabaseManager) -> AgentLogRepository:
    return AgentLogRepository(db)


# --- Factory-Funktionen ---

def create_test_scan(
    target: str = "10.10.10.1",
    scan_type: ScanType = ScanType.RECON,
    status: ScanStatus = ScanStatus.PENDING,
    max_escalation_level: int = 2,
) -> ScanJob:
    """Erstellt einen ScanJob für Testzwecke."""
    return ScanJob(
        id=uuid4(),
        target=target,
        scan_type=scan_type,
        status=status,
        max_escalation_level=max_escalation_level,
        token_budget=50000,
        created_at=datetime.now(UTC),
    )


def create_test_finding(
    scan_job_id=None,
    title: str = "Test-Finding",
    severity: Severity = Severity.HIGH,
    cvss_score: float = 7.5,
    target_host: str = "10.10.10.1",
    target_port: int = 443,
) -> Finding:
    """Erstellt ein Finding für Testzwecke."""
    return Finding(
        id=uuid4(),
        scan_job_id=scan_job_id or uuid4(),
        tool_name="nuclei",
        title=title,
        severity=severity,
        cvss_score=cvss_score,
        target_host=target_host,
        target_port=target_port,
        service="https",
        description=f"Test-Beschreibung für {title}",
        evidence="Test-Beweis",
        recommendation="Test-Empfehlung",
        created_at=datetime.now(UTC),
    )


def create_test_audit_entry(
    action: str = "test.action",
    resource_type: str = "scan_job",
) -> AuditLogEntry:
    """Erstellt einen Audit-Log-Eintrag für Testzwecke."""
    return AuditLogEntry(
        id=uuid4(),
        action=action,
        resource_type=resource_type,
        resource_id=str(uuid4()),
        details={"test": True},
        triggered_by="test-user",
        created_at=datetime.now(UTC),
    )


def create_test_user_data(
    email: str = "test@example.com",
    role: str = "analyst",
) -> dict:
    """Gibt Testdaten für User-Erstellung zurück."""
    return {
        "email": email,
        "display_name": "Test User",
        "password": "TestPassw0rd!Secure",
        "role": role,
    }

"""
Erweiterte Repository-Tests: delete, get_by_id, kaskadierende Loeschung.

Testet die CRUD-Methoden die ueber create/list hinausgehen:
ScanJobRepository.delete(), FindingRepository.get_by_id/delete(),
sowie die kaskadierende Loeschung aller abhaengigen Daten.
"""

from pathlib import Path
from uuid import uuid4

import pytest

from src.shared.database import DatabaseManager
from src.shared.repositories import (
    AuditLogRepository,
    FindingRepository,
    ScanJobRepository,
)
from src.shared.types.models import (
    AuditLogEntry,
    Finding,
    ScanJob,
    Severity,
)

_REPO_TEST_DB_PATH = Path("/tmp/test_sentinelclaw_repos.db")


@pytest.fixture
async def db():
    """Erstellt eine frische Test-Datenbank fuer jeden Test."""
    manager = DatabaseManager(_REPO_TEST_DB_PATH)
    await manager.initialize()
    yield manager
    await manager.close()
    _REPO_TEST_DB_PATH.unlink(missing_ok=True)


@pytest.fixture
def scan_repo(db):
    """ScanJob-Repository mit Test-DB."""
    return ScanJobRepository(db)


@pytest.fixture
def finding_repo(db):
    """Finding-Repository mit Test-DB."""
    return FindingRepository(db)


@pytest.fixture
def audit_repo(db):
    """AuditLog-Repository mit Test-DB."""
    return AuditLogRepository(db)


# ─── Hilfsfunktion: Test-Daten erzeugen ──────────────────────────

def _make_scan(target: str = "10.0.0.1") -> ScanJob:
    """Erzeugt einen ScanJob mit Standardwerten."""
    return ScanJob(target=target, scan_type="recon")


def _make_finding(scan_job_id, title: str = "Test-Finding", severity: Severity = Severity.HIGH) -> Finding:
    """Erzeugt ein Finding mit Standardwerten."""
    return Finding(
        scan_job_id=scan_job_id,
        tool_name="nmap",
        title=title,
        severity=severity,
        cvss_score=7.5,
        target_host="10.0.0.1",
        target_port=80,
        service="http",
        description="Testbeschreibung",
    )


# ─── ScanJob: Erstellen und Loeschen ─────────────────────────────

async def test_scan_create_then_delete(scan_repo):
    """Scan erstellen, loeschen, pruefen dass er weg ist."""
    job = _make_scan()
    await scan_repo.create(job)

    # Scan existiert nach Erstellung
    loaded = await scan_repo.get_by_id(job.id)
    assert loaded is not None

    # Loeschen
    result = await scan_repo.delete(job.id)
    assert result is True

    # Scan darf nicht mehr existieren
    gone = await scan_repo.get_by_id(job.id)
    assert gone is None


async def test_scan_delete_nonexistent(scan_repo):
    """Loeschen eines nicht-existierenden Scans gibt True zurueck (idempotent)."""
    result = await scan_repo.delete(uuid4())
    assert result is True


# ─── Finding: get_by_id ──────────────────────────────────────────

async def test_finding_get_by_id_correct(finding_repo, scan_repo):
    """Finding per ID laden und Felder pruefen."""
    job = _make_scan()
    await scan_repo.create(job)

    finding = _make_finding(job.id, title="XSS in Suchfeld", severity=Severity.MEDIUM)
    await finding_repo.create(finding)

    # Per ID laden
    loaded = await finding_repo.get_by_id(finding.id)
    assert loaded is not None
    assert loaded.id == finding.id
    assert loaded.title == "XSS in Suchfeld"
    assert loaded.severity == Severity.MEDIUM
    assert loaded.scan_job_id == job.id


async def test_finding_get_by_id_nonexistent(finding_repo):
    """get_by_id fuer nicht-existierendes Finding gibt None zurueck."""
    result = await finding_repo.get_by_id(uuid4())
    assert result is None


# ─── Finding: Erstellen und Loeschen ─────────────────────────────

async def test_finding_create_then_delete(finding_repo, scan_repo):
    """Finding erstellen, loeschen, pruefen dass es weg ist."""
    job = _make_scan()
    await scan_repo.create(job)

    finding = _make_finding(job.id)
    await finding_repo.create(finding)

    # Existiert
    assert await finding_repo.get_by_id(finding.id) is not None

    # Loeschen
    result = await finding_repo.delete(finding.id)
    assert result is True

    # Weg
    assert await finding_repo.get_by_id(finding.id) is None


async def test_finding_delete_removes_from_list(finding_repo, scan_repo):
    """Nach Loeschung taucht das Finding nicht mehr in list_by_scan auf."""
    job = _make_scan()
    await scan_repo.create(job)

    f1 = _make_finding(job.id, title="Finding-A")
    f2 = _make_finding(job.id, title="Finding-B")
    await finding_repo.create(f1)
    await finding_repo.create(f2)

    # Beide da
    findings = await finding_repo.list_by_scan(job.id)
    assert len(findings) == 2

    # Eines loeschen
    await finding_repo.delete(f1.id)

    # Nur noch eines uebrig
    findings = await finding_repo.list_by_scan(job.id)
    assert len(findings) == 1
    assert findings[0].title == "Finding-B"


# ─── Kaskadierende Loeschung ─────────────────────────────────────

async def test_scan_delete_cascades_findings(finding_repo, scan_repo):
    """Scan loeschen entfernt auch alle zugehoerigen Findings."""
    job = _make_scan("192.168.1.1")
    await scan_repo.create(job)

    # Mehrere Findings anlegen
    for title in ["SQLi", "XSS", "CSRF"]:
        await finding_repo.create(_make_finding(job.id, title=title))

    # Alle 3 Findings existieren
    findings = await finding_repo.list_by_scan(job.id)
    assert len(findings) == 3

    # Scan loeschen (kaskadierend)
    await scan_repo.delete(job.id)

    # Scan weg
    assert await scan_repo.get_by_id(job.id) is None

    # Findings muessen ebenfalls weg sein
    findings = await finding_repo.list_by_scan(job.id)
    assert len(findings) == 0


async def test_scan_delete_cascade_does_not_affect_other_scans(finding_repo, scan_repo):
    """Kaskadierende Loeschung betrifft nur den geloeschten Scan."""
    job_a = _make_scan("10.0.0.1")
    job_b = _make_scan("10.0.0.2")
    await scan_repo.create(job_a)
    await scan_repo.create(job_b)

    await finding_repo.create(_make_finding(job_a.id, title="Finding-A"))
    await finding_repo.create(_make_finding(job_b.id, title="Finding-B"))

    # Scan A loeschen
    await scan_repo.delete(job_a.id)

    # Scan B und sein Finding bleiben erhalten
    assert await scan_repo.get_by_id(job_b.id) is not None
    findings_b = await finding_repo.list_by_scan(job_b.id)
    assert len(findings_b) == 1
    assert findings_b[0].title == "Finding-B"


# ─── AuditLog: Kein delete ───────────────────────────────────────

async def test_audit_log_has_no_delete(audit_repo):
    """AuditLogRepository darf KEINE delete-Methode besitzen."""
    assert not hasattr(audit_repo, "delete"), (
        "AuditLogRepository darf kein delete() haben — Audit-Logs sind unveraenderbar"
    )


async def test_audit_log_has_no_update(audit_repo):
    """AuditLogRepository darf KEINE update-Methode besitzen."""
    assert not hasattr(audit_repo, "update"), (
        "AuditLogRepository darf kein update() haben — Audit-Logs sind unveraenderbar"
    )


async def test_audit_log_create_still_works(audit_repo):
    """Trotz fehlender delete/update funktioniert create einwandfrei."""
    entry = AuditLogEntry(
        action="test.action",
        resource_type="test",
        triggered_by="unit_test",
    )
    created = await audit_repo.create(entry)
    assert created.id == entry.id

    logs = await audit_repo.list_recent(10)
    assert len(logs) == 1
    assert logs[0].action == "test.action"

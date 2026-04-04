"""
Unit-Tests fuer den Report-Generator.

Erstellt eine Temp-DB mit Scan + Findings und prueft ob die
generierten Reports (Executive, Technical, Compliance) die
erwarteten Inhalte enthalten.
"""

from pathlib import Path

import pytest

from src.shared.database import DatabaseManager
from src.shared.report_generator import ReportGenerator
from src.shared.repositories import FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob, Severity

_REPORT_TEST_DB_PATH = Path("/tmp/test_sentinelclaw_reports.db")


@pytest.fixture
async def db():
    """Erstellt eine frische Test-Datenbank."""
    manager = DatabaseManager(_REPORT_TEST_DB_PATH)
    await manager.initialize()
    yield manager
    await manager.close()
    _REPORT_TEST_DB_PATH.unlink(missing_ok=True)


@pytest.fixture
async def scan_with_findings(db):
    """Erstellt einen Scan mit gemischten Findings fuer Report-Tests."""
    scan_repo = ScanJobRepository(db)
    finding_repo = FindingRepository(db)

    job = ScanJob(target="example.com", scan_type="full")
    await scan_repo.create(job)

    # Findings mit verschiedenen Schweregraden
    test_data = [
        ("Remote Code Execution", Severity.CRITICAL, 9.8),
        ("SQL Injection", Severity.HIGH, 8.5),
        ("Missing CSP Header", Severity.MEDIUM, 5.0),
        ("Server Version Exposed", Severity.LOW, 2.1),
    ]
    for title, severity, cvss in test_data:
        finding = Finding(
            scan_job_id=job.id,
            tool_name="nuclei",
            title=title,
            severity=severity,
            cvss_score=cvss,
            target_host="example.com",
            target_port=443,
            description=f"Beschreibung fuer {title}",
        )
        await finding_repo.create(finding)

    return db, job.id


# ─── Executive Summary ────────────────────────────────────────────

async def test_executive_contains_target(scan_with_findings):
    """Executive Summary enthaelt den Zielnamen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_executive_summary(scan_id)
    assert "example.com" in report


async def test_executive_contains_severity_counts(scan_with_findings):
    """Executive Summary enthaelt die Schweregrad-Bezeichnungen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_executive_summary(scan_id)
    assert "Critical" in report
    assert "High" in report
    assert "Medium" in report


async def test_executive_contains_risk_assessment(scan_with_findings):
    """Executive Summary enthaelt eine Risikobewertung."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_executive_summary(scan_id)
    # Mit Critical-Findings muss das Risiko als KRITISCH bewertet werden
    assert "KRITISCH" in report


async def test_executive_contains_recommendations(scan_with_findings):
    """Executive Summary enthaelt Handlungsempfehlungen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_executive_summary(scan_id)
    assert "Empfehlungen" in report


# ─── Technischer Report ──────────────────────────────────────────

async def test_technical_contains_all_finding_titles(scan_with_findings):
    """Technischer Report listet alle Finding-Titel auf."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_technical_report(scan_id)

    assert "Remote Code Execution" in report
    assert "SQL Injection" in report
    assert "Missing CSP Header" in report
    assert "Server Version Exposed" in report


async def test_technical_contains_statistics_table(scan_with_findings):
    """Technischer Report enthaelt eine Statistik-Tabelle."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_technical_report(scan_id)
    assert "Statistik" in report
    assert "Schweregrad" in report


async def test_technical_contains_target(scan_with_findings):
    """Technischer Report enthaelt den Zielnamen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_technical_report(scan_id)
    assert "example.com" in report


async def test_technical_contains_cvss_scores(scan_with_findings):
    """Technischer Report enthaelt CVSS-Scores der Findings."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_technical_report(scan_id)
    assert "9.8" in report
    assert "8.5" in report


# ─── Compliance-Report ───────────────────────────────────────────

async def test_compliance_contains_bsi(scan_with_findings):
    """Compliance-Report enthaelt BSI IT-Grundschutz Referenzen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_compliance_report(scan_id)
    assert "BSI" in report


async def test_compliance_contains_iso(scan_with_findings):
    """Compliance-Report enthaelt ISO 27001 Referenzen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_compliance_report(scan_id)
    assert "ISO" in report


async def test_compliance_contains_target(scan_with_findings):
    """Compliance-Report enthaelt den Zielnamen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_compliance_report(scan_id)
    assert "example.com" in report


async def test_compliance_contains_mapping_tables(scan_with_findings):
    """Compliance-Report enthaelt Mapping-Tabellen fuer beide Frameworks."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_compliance_report(scan_id)
    assert "BSI IT-Grundschutz Mapping" in report
    assert "ISO 27001 Mapping" in report


async def test_compliance_critical_findings_noted(scan_with_findings):
    """Bei kritischen Findings wird auf sofortige Massnahmen hingewiesen."""
    db, scan_id = scan_with_findings
    gen = ReportGenerator(db)
    report = await gen.generate_compliance_report(scan_id)
    assert "sofortige Massnahmen" in report.lower() or "sofort" in report.lower()

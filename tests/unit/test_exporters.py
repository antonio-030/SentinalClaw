"""
Unit-Tests fuer die Exportfunktionen (CSV, JSONL, SARIF).

Erstellt eine Temp-DB mit Test-Findings und prueft die
korrekte Formatierung der Export-Ausgaben.
"""

import csv
import io
import json
from pathlib import Path

import pytest

from src.shared.database import DatabaseManager
from src.shared.exporters import (
    export_findings_csv,
    export_findings_jsonl,
    export_findings_sarif,
)
from src.shared.repositories import FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob, Severity

_EXPORT_TEST_DB_PATH = Path("/tmp/test_sentinelclaw_export.db")

# Anzahl der Test-Findings die eingefuegt werden
_NUM_TEST_FINDINGS = 3


@pytest.fixture
async def db():
    """Erstellt eine frische Test-Datenbank."""
    manager = DatabaseManager(_EXPORT_TEST_DB_PATH)
    await manager.initialize()
    yield manager
    await manager.close()
    _EXPORT_TEST_DB_PATH.unlink(missing_ok=True)


@pytest.fixture
async def scan_with_findings(db):
    """Erstellt einen Scan mit mehreren Findings und gibt (db, scan_id) zurueck."""
    scan_repo = ScanJobRepository(db)
    finding_repo = FindingRepository(db)

    job = ScanJob(target="10.0.0.1", scan_type="recon")
    await scan_repo.create(job)

    # Drei Findings mit unterschiedlichen Schweregraden
    test_findings = [
        ("SQL Injection", Severity.CRITICAL, 9.8, "CVE-2024-0001", 3306),
        ("XSS Reflected", Severity.HIGH, 7.5, "CVE-2024-0002", 80),
        ("Info Disclosure", Severity.LOW, 3.1, None, 443),
    ]
    for title, severity, cvss, cve, port in test_findings:
        finding = Finding(
            scan_job_id=job.id,
            tool_name="nuclei",
            title=title,
            severity=severity,
            cvss_score=cvss,
            cve_id=cve,
            target_host="10.0.0.1",
            target_port=port,
            service="http",
            description=f"Beschreibung fuer {title}",
        )
        await finding_repo.create(finding)

    return db, job.id


# ─── CSV-Export ───────────────────────────────────────────────────

async def test_csv_has_header_row(scan_with_findings):
    """CSV-Export beginnt mit einer Kopfzeile."""
    db, scan_id = scan_with_findings
    csv_text = await export_findings_csv(db, scan_id)

    reader = csv.reader(io.StringIO(csv_text))
    headers = next(reader)
    assert "Severity" in headers
    assert "Title" in headers
    assert "Host" in headers
    assert "CVSS" in headers


async def test_csv_correct_row_count(scan_with_findings):
    """CSV enthaelt eine Kopfzeile plus je eine Zeile pro Finding."""
    db, scan_id = scan_with_findings
    csv_text = await export_findings_csv(db, scan_id)

    lines = [line for line in csv_text.strip().split("\n") if line.strip()]
    # 1 Header + 3 Datenzeilen
    assert len(lines) == _NUM_TEST_FINDINGS + 1


async def test_csv_contains_finding_titles(scan_with_findings):
    """CSV enthaelt die Titel aller Findings."""
    db, scan_id = scan_with_findings
    csv_text = await export_findings_csv(db, scan_id)
    assert "SQL Injection" in csv_text
    assert "XSS Reflected" in csv_text
    assert "Info Disclosure" in csv_text


# ─── JSONL-Export ─────────────────────────────────────────────────

async def test_jsonl_each_line_valid_json(scan_with_findings):
    """Jede Zeile im JSONL-Export ist gueltiges JSON."""
    db, scan_id = scan_with_findings
    jsonl_text = await export_findings_jsonl(db, scan_id)

    lines = [line for line in jsonl_text.strip().split("\n") if line.strip()]
    assert len(lines) == _NUM_TEST_FINDINGS

    for line in lines:
        parsed = json.loads(line)  # Wirft JSONDecodeError wenn ungueltig
        assert isinstance(parsed, dict)


async def test_jsonl_contains_required_fields(scan_with_findings):
    """Jedes JSONL-Objekt enthaelt die wichtigsten Felder."""
    db, scan_id = scan_with_findings
    jsonl_text = await export_findings_jsonl(db, scan_id)

    for line in jsonl_text.strip().split("\n"):
        obj = json.loads(line)
        assert "title" in obj
        assert "severity" in obj
        assert "cvss_score" in obj
        assert "target_host" in obj


async def test_jsonl_correct_count(scan_with_findings):
    """JSONL enthaelt genau so viele Zeilen wie Findings vorhanden."""
    db, scan_id = scan_with_findings
    jsonl_text = await export_findings_jsonl(db, scan_id)
    lines = [line for line in jsonl_text.strip().split("\n") if line.strip()]
    assert len(lines) == _NUM_TEST_FINDINGS


# ─── SARIF-Export ─────────────────────────────────────────────────

async def test_sarif_is_valid_json(scan_with_findings):
    """SARIF-Export ist gueltiges JSON."""
    db, scan_id = scan_with_findings
    sarif_text = await export_findings_sarif(db, scan_id)
    doc = json.loads(sarif_text)
    assert isinstance(doc, dict)


async def test_sarif_has_schema(scan_with_findings):
    """SARIF-Dokument enthaelt '$schema'."""
    db, scan_id = scan_with_findings
    doc = json.loads(await export_findings_sarif(db, scan_id))
    assert "$schema" in doc
    assert "sarif" in doc["$schema"].lower()


async def test_sarif_has_version(scan_with_findings):
    """SARIF-Dokument hat version '2.1.0'."""
    db, scan_id = scan_with_findings
    doc = json.loads(await export_findings_sarif(db, scan_id))
    assert doc["version"] == "2.1.0"


async def test_sarif_has_runs(scan_with_findings):
    """SARIF-Dokument enthaelt 'runs' mit mindestens einem Eintrag."""
    db, scan_id = scan_with_findings
    doc = json.loads(await export_findings_sarif(db, scan_id))
    assert "runs" in doc
    assert len(doc["runs"]) >= 1


async def test_sarif_results_match_findings(scan_with_findings):
    """Anzahl der SARIF-Results stimmt mit Findings ueberein."""
    db, scan_id = scan_with_findings
    doc = json.loads(await export_findings_sarif(db, scan_id))
    results = doc["runs"][0]["results"]
    assert len(results) == _NUM_TEST_FINDINGS


async def test_sarif_tool_name(scan_with_findings):
    """SARIF-Tool-Name ist 'SentinelClaw'."""
    db, scan_id = scan_with_findings
    doc = json.loads(await export_findings_sarif(db, scan_id))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SentinelClaw"

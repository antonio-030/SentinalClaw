"""
Finding-Routen fuer die SentinelClaw REST-API.

Enthaelt alle Endpoints unter /api/v1/findings:
  - Alle Findings auflisten (optional nach Severity filtern)
  - Einzelnes Finding abrufen
  - Finding loeschen
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


# ─── Hilfsfunktion: DB-Zugriff ────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkulaere Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


# ─── Endpoints ─────────────────────────────────────────────────────


@router.get("")
async def list_findings(severity: str | None = None, limit: int = 50) -> list[dict]:
    """Listet alle Findings, optional gefiltert nach Severity."""
    from src.shared.repositories import FindingRepository

    db = await _get_db()
    repo = FindingRepository(db)
    findings = await repo.list_all(severity=severity, limit=limit)

    return [
        {
            "id": str(f.id),
            "scan_job_id": str(f.scan_job_id),
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "target_host": f.target_host,
            "target_port": f.target_port,
            "service": f.service,
            "description": f.description,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]


@router.get("/{finding_id}")
async def get_finding(finding_id: str) -> dict:
    """Gibt ein einzelnes Finding anhand seiner ID zurueck."""
    from src.shared.repositories import FindingRepository

    db = await _get_db()
    repo = FindingRepository(db)

    finding = await repo.get_by_id(UUID(finding_id))
    if not finding:
        raise HTTPException(404, f"Finding {finding_id} nicht gefunden")

    return {
        "id": str(finding.id),
        "scan_job_id": str(finding.scan_job_id),
        "tool_name": finding.tool_name,
        "title": finding.title,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "cve_id": finding.cve_id,
        "target_host": finding.target_host,
        "target_port": finding.target_port,
        "service": finding.service,
        "description": finding.description,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
        "raw_output": finding.raw_output,
        "created_at": finding.created_at.isoformat(),
    }


@router.delete("/{finding_id}")
async def delete_finding(finding_id: str) -> dict:
    """Loescht ein einzelnes Finding."""
    from src.shared.repositories import AuditLogRepository, FindingRepository
    from src.shared.types.models import AuditLogEntry

    db = await _get_db()
    repo = FindingRepository(db)
    audit_repo = AuditLogRepository(db)

    # Pruefen ob das Finding existiert
    finding = await repo.get_by_id(UUID(finding_id))
    if not finding:
        raise HTTPException(404, f"Finding {finding_id} nicht gefunden")

    await repo.delete(UUID(finding_id))

    # Audit-Log ueber Loeschung schreiben
    await audit_repo.create(AuditLogEntry(
        action="finding.deleted",
        resource_type="finding",
        resource_id=finding_id,
        details={"title": finding.title, "severity": finding.severity},
        triggered_by="api",
    ))

    logger.info("Finding geloescht", finding_id=finding_id, title=finding.title)
    return {"status": "deleted", "finding_id": finding_id}

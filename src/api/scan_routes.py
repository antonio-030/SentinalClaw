"""
Scan-Routen fuer die SentinelClaw REST-API.

Enthaelt die grundlegenden CRUD-Endpoints unter /api/v1/scans:
  - POST   /scans       -> Scan starten
  - GET    /scans       -> Alle Scans auflisten
  - GET    /scans/{id}  -> Scan-Details abrufen
  - DELETE /scans/{id}  -> Scan loeschen
  - PUT    /scans/{id}/cancel -> Scan abbrechen

Validierungslogik und Background-Ausfuehrung liegen in scan_validation.py.
Sub-Ressourcen (Export, Report, Vergleich, Hosts, Ports, Phasen)
liegen in scan_detail_routes.py.
"""

import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.api.scan_validation import (
    check_security_layers,
    create_scan_job_with_audit,
    parse_scan_uuid,
    resolve_scan_profile,
    run_scan_background,
    validate_scan_target,
)
from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


# ─── Request/Response Modelle ──────────────────────────────────────


class ScanRequest(BaseModel):
    """Anfrage zum Starten eines Scans."""

    target: str = Field(description="Scan-Ziel (IP, CIDR, Domain)", min_length=1, max_length=500)
    ports: str = Field(default="1-1000", description="Port-Range")
    profile: str | None = Field(default=None, description="Scan-Profil Name")
    scan_type: str = Field(default="recon", description="Scan-Typ")
    max_escalation_level: int = Field(default=2, ge=0, le=4)


class ScanResponse(BaseModel):
    """Antwort nach Scan-Start."""

    scan_id: str
    target: str
    status: str
    message: str


# ─── Hilfsfunktion: DB-Zugriff ────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkulaere Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


# ─── Endpoints ─────────────────────────────────────────────────────


@router.post("", response_model=ScanResponse)
async def start_scan(request: Request, body: ScanRequest) -> ScanResponse:
    """Startet einen neuen Scan (analyst+)."""
    caller = require_role(request, "analyst")
    target = validate_scan_target(body.target)
    await check_security_layers()

    # Profil laden oder Defaults verwenden
    ports, escalation = resolve_scan_profile(
        body.profile, body.ports, body.max_escalation_level
    )

    # Scan-Job erstellen und Audit-Log schreiben
    db = await _get_db()
    scan_id = await create_scan_job_with_audit(
        db=db,
        target=target,
        scan_type=body.scan_type,
        escalation=escalation,
        ports=ports,
        profile_name=body.profile,
        caller_email=caller.get("email", "api"),
    )

    # Scan asynchron im Hintergrund starten
    asyncio.create_task(run_scan_background(scan_id, target, ports, escalation))

    return ScanResponse(
        scan_id=scan_id,
        target=body.target,
        status="started",
        message=f"Scan gestartet auf {body.target} (Ports: {ports})",
    )


@router.get("")
async def list_scans(limit: int = 20) -> list[dict]:
    """Listet alle Scans."""
    from src.shared.repositories import ScanJobRepository

    db = await _get_db()
    repo = ScanJobRepository(db)
    scans = await repo.list_all(limit)

    return [
        {
            "id": str(s.id),
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "tokens_used": s.tokens_used,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Gibt Details zu einem Scan zurueck."""
    from src.shared.phase_repositories import OpenPortRepository, ScanPhaseRepository
    from src.shared.repositories import FindingRepository, ScanJobRepository

    scan_uuid = parse_scan_uuid(scan_id)

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    finding_repo = FindingRepository(db)
    phase_repo = ScanPhaseRepository(db)
    port_repo = OpenPortRepository(db)

    job = await scan_repo.get_by_id(scan_uuid)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    findings = await finding_repo.list_by_scan(scan_uuid)
    phases = await phase_repo.list_by_scan(scan_uuid)
    ports = await port_repo.list_by_scan(scan_uuid)

    return {
        "scan": {
            "id": str(job.id),
            "target": job.target,
            "status": job.status,
            "scan_type": job.scan_type,
            "tokens_used": job.tokens_used,
            "created_at": job.created_at.isoformat(),
        },
        "phases": phases,
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "target_host": f.target_host,
                "target_port": f.target_port,
            }
            for f in findings
        ],
        "open_ports": ports,
    }


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, request: Request) -> dict:
    """Loescht einen Scan und alle zugehoerigen Daten (security_lead+)."""
    caller = require_role(request, "security_lead")
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry

    scan_uuid = parse_scan_uuid(scan_id)

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Pruefen ob der Scan existiert
    job = await scan_repo.get_by_id(scan_uuid)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    await scan_repo.delete(scan_uuid)

    # Audit-Log ueber Loeschung schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.deleted",
        resource_type="scan_job",
        resource_id=scan_id,
        details={"target": job.target},
        triggered_by=caller.get("email", "api"),
    ))

    logger.info("Scan geloescht", scan_id=scan_id, target=job.target)
    return {"status": "deleted", "scan_id": scan_id}


@router.put("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request) -> dict:
    """Bricht einen laufenden Scan ab (analyst+)."""
    caller = require_role(request, "analyst")
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanStatus

    scan_uuid = parse_scan_uuid(scan_id)

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Pruefen ob der Scan existiert und laeuft
    job = await scan_repo.get_by_id(scan_uuid)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            409, f"Scan kann nicht abgebrochen werden (Status: {job.status})"
        )

    await scan_repo.update_status(scan_uuid, ScanStatus.CANCELLED)

    # Audit-Log schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.cancelled",
        resource_type="scan_job",
        resource_id=scan_id,
        details={"previous_status": job.status},
        triggered_by=caller.get("email", "api"),
    ))

    logger.info("Scan abgebrochen", scan_id=scan_id)
    return {"status": "cancelled", "scan_id": scan_id}

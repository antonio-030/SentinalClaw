"""
Scan-Routen fuer die SentinelClaw REST-API.

Enthaelt die grundlegenden CRUD-Endpoints unter /api/v1/scans:
  - POST   /scans       -> Scan starten
  - GET    /scans       -> Alle Scans auflisten
  - GET    /scans/{id}  -> Scan-Details abrufen
  - DELETE /scans/{id}  -> Scan loeschen
  - PUT    /scans/{id}/cancel -> Scan abbrechen

Sub-Ressourcen (Export, Report, Vergleich, Hosts, Ports, Phasen)
liegen in scan_detail_routes.py.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


# ─── Request/Response Modelle ──────────────────────────────────────


class ScanRequest(BaseModel):
    """Anfrage zum Starten eines Scans."""

    target: str = Field(description="Scan-Ziel (IP, CIDR, Domain)")
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
async def start_scan(request: ScanRequest) -> ScanResponse:
    """Startet einen neuen Scan."""
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanJob

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Profil laden wenn angegeben
    ports = request.ports
    escalation = request.max_escalation_level
    if request.profile:
        from src.shared.scan_profiles import get_profile
        profile = get_profile(request.profile)
        ports = profile.ports
        escalation = profile.max_escalation_level

    # Scan-Job erstellen
    job = ScanJob(
        target=request.target,
        scan_type=request.scan_type,
        max_escalation_level=escalation,
        config={"ports": ports, "profile": request.profile},
    )
    await scan_repo.create(job)

    # Audit-Log schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.created",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"target": request.target, "ports": ports},
        triggered_by="api",
    ))

    # Scan asynchron starten (Background-Task)
    import asyncio
    asyncio.create_task(
        _run_scan_background(str(job.id), request.target, ports, escalation)
    )

    return ScanResponse(
        scan_id=str(job.id),
        target=request.target,
        status="started",
        message=f"Scan gestartet auf {request.target} (Ports: {ports})",
    )


async def _run_scan_background(
    scan_id: str, target: str, ports: str, escalation: int
) -> None:
    """Fuehrt den Scan im Hintergrund aus."""
    from uuid import UUID as _UUID

    from src.orchestrator.agent import OrchestratorAgent
    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus
    from src.shared.types.scope import PentestScope

    try:
        db = await _get_db()
        scan_repo = ScanJobRepository(db)
        await scan_repo.update_status(_UUID(scan_id), ScanStatus.RUNNING)

        scope = PentestScope(
            targets_include=[target],
            max_escalation_level=escalation,
            ports_include=ports,
        )

        orchestrator = OrchestratorAgent(scope=scope)
        await orchestrator.orchestrate_scan(target, ports=ports, existing_scan_id=scan_id)
        await orchestrator.close()

    except Exception as error:
        logger.error("Background-Scan fehlgeschlagen", scan_id=scan_id, error=str(error))


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

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    finding_repo = FindingRepository(db)
    phase_repo = ScanPhaseRepository(db)
    port_repo = OpenPortRepository(db)

    job = await scan_repo.get_by_id(UUID(scan_id))
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    findings = await finding_repo.list_by_scan(UUID(scan_id))
    phases = await phase_repo.list_by_scan(UUID(scan_id))
    ports = await port_repo.list_by_scan(UUID(scan_id))

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
async def delete_scan(scan_id: str) -> dict:
    """Loescht einen Scan und alle zugehoerigen Daten (kaskadierend)."""
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Pruefen ob der Scan existiert
    job = await scan_repo.get_by_id(UUID(scan_id))
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    await scan_repo.delete(UUID(scan_id))

    # Audit-Log ueber Loeschung schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.deleted",
        resource_type="scan_job",
        resource_id=scan_id,
        details={"target": job.target},
        triggered_by="api",
    ))

    logger.info("Scan geloescht", scan_id=scan_id, target=job.target)
    return {"status": "deleted", "scan_id": scan_id}


@router.put("/{scan_id}/cancel")
async def cancel_scan(scan_id: str) -> dict:
    """Bricht einen laufenden Scan ab."""
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanStatus

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Pruefen ob der Scan existiert und laeuft
    job = await scan_repo.get_by_id(UUID(scan_id))
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")

    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            409, f"Scan kann nicht abgebrochen werden (Status: {job.status})"
        )

    await scan_repo.update_status(UUID(scan_id), ScanStatus.CANCELLED)

    # Audit-Log schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.cancelled",
        resource_type="scan_job",
        resource_id=scan_id,
        details={"previous_status": job.status},
        triggered_by="api",
    ))

    logger.info("Scan abgebrochen", scan_id=scan_id)
    return {"status": "cancelled", "scan_id": scan_id}

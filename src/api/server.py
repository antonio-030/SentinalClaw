"""
SentinelClaw REST-API Server.

FastAPI-basierte API die alle SentinelClaw-Funktionen exponiert.
Basis für die Web-UI und externe Integrationen.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger, setup_logging

logger = get_logger(__name__)

# Globale DB-Instanz (wird im Lifespan initialisiert)
_db: DatabaseManager | None = None


async def get_db() -> DatabaseManager:
    """Gibt die aktive DB-Verbindung zurück. Lazy-Init falls nötig."""
    global _db
    if _db is None:
        settings = get_settings()
        _db = DatabaseManager(settings.db_path)
        await _db.initialize()
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialisiert und schließt Ressourcen beim Server-Start/-Stop."""
    global _db
    settings = get_settings()
    setup_logging(settings.log_level)

    _db = DatabaseManager(settings.db_path)
    await _db.initialize()
    logger.info("API-Server gestartet", port=settings.mcp_port)

    yield

    await _db.close()
    logger.info("API-Server gestoppt")


app = FastAPI(
    title="SentinelClaw API",
    description="AI-gestützte Security Assessment Platform — REST API",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS für Web-UI (nur eigene Domain im Produkt)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


class KillRequest(BaseModel):
    """Kill-Switch Anfrage."""

    reason: str = Field(default="API Kill-Request")


class HealthResponse(BaseModel):
    """System-Health-Status."""

    status: str
    version: str
    provider: str
    sandbox_running: bool
    db_connected: bool
    timestamp: str


# ─── Endpoints ─────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """System-Health-Check — wird von Docker Healthcheck genutzt."""
    settings = get_settings()
    sandbox_ok = False

    try:
        import docker
        client = docker.from_env()
        container = client.containers.get("sentinelclaw-sandbox")
        sandbox_ok = container.status == "running"
    except Exception:
        pass

    db_ok = _db is not None
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version="0.1.0",
        provider=settings.llm_provider,
        sandbox_running=sandbox_ok,
        db_connected=db_ok,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/api/v1/scans", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Startet einen neuen Scan."""
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanJob, ScanStatus

    db = await get_db()
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

    # Audit-Log
    await audit_repo.create(AuditLogEntry(
        action="scan.created",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"target": request.target, "ports": ports},
        triggered_by="api",
    ))

    # Scan asynchron starten (Background-Task)
    import asyncio
    asyncio.create_task(_run_scan_background(str(job.id), request.target, ports, escalation))

    return ScanResponse(
        scan_id=str(job.id),
        target=request.target,
        status="started",
        message=f"Scan gestartet auf {request.target} (Ports: {ports})",
    )


async def _run_scan_background(scan_id: str, target: str, ports: str, escalation: int):
    """Führt den Scan im Hintergrund aus."""
    from uuid import UUID
    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus
    from src.shared.types.scope import PentestScope
    from src.orchestrator.agent import OrchestratorAgent

    try:
        db = await get_db()
        scan_repo = ScanJobRepository(db)
        await scan_repo.update_status(UUID(scan_id), ScanStatus.RUNNING)

        scope = PentestScope(
            targets_include=[target],
            max_escalation_level=escalation,
            ports_include=ports,
        )

        orchestrator = OrchestratorAgent(scope=scope)
        await orchestrator.orchestrate_scan(target, ports=ports)
        await orchestrator.close()

    except Exception as error:
        logger.error("Background-Scan fehlgeschlagen", scan_id=scan_id, error=str(error))


@app.get("/api/v1/scans")
async def list_scans(limit: int = 20):
    """Listet alle Scans."""
    from src.shared.repositories import ScanJobRepository

    db = await get_db()
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


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Gibt Details zu einem Scan zurück."""
    from uuid import UUID
    from src.shared.repositories import ScanJobRepository, FindingRepository
    from src.shared.phase_repositories import ScanPhaseRepository, OpenPortRepository

    db = await get_db()
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


@app.get("/api/v1/findings")
async def list_findings(severity: str | None = None, limit: int = 50):
    """Listet alle Findings, optional gefiltert nach Severity."""
    from src.shared.repositories import FindingRepository

    db = await get_db()
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


@app.post("/api/v1/kill")
async def emergency_kill(request: KillRequest):
    """Aktiviert den Kill-Switch — stoppt ALLE laufenden Scans."""
    from src.shared.kill_switch import KillSwitch
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanStatus

    ks = KillSwitch()
    ks.activate(triggered_by="api_user", reason=request.reason)

    # Laufende Scans in DB auf KILLED setzen
    db = await get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    running = await scan_repo.list_by_status(ScanStatus.RUNNING)
    for job in running:
        await scan_repo.update_status(job.id, ScanStatus.EMERGENCY_KILLED)

    await audit_repo.create(AuditLogEntry(
        action="kill.activated",
        resource_type="system",
        details={"reason": request.reason, "scans_killed": len(running)},
        triggered_by="api_user",
    ))

    return {"status": "killed", "scans_stopped": len(running), "reason": request.reason}


@app.get("/api/v1/audit")
async def list_audit_logs(limit: int = 50, action: str | None = None):
    """Listet Audit-Log-Einträge."""
    from src.shared.repositories import AuditLogRepository

    db = await get_db()
    repo = AuditLogRepository(db)

    if action:
        entries = await repo.list_by_action(action, limit)
    else:
        entries = await repo.list_recent(limit)

    return [
        {
            "id": str(e.id),
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "details": e.details,
            "triggered_by": e.triggered_by,
            "created_at": e.created_at.isoformat(),
        }
        for e in entries
    ]


@app.get("/api/v1/profiles")
async def list_scan_profiles():
    """Listet alle verfügbaren Scan-Profile."""
    from src.shared.scan_profiles import list_profiles

    return [
        {
            "name": p.name,
            "description": p.description,
            "ports": p.ports,
            "max_escalation_level": p.max_escalation_level,
            "estimated_duration_minutes": p.estimated_duration_minutes,
        }
        for p in list_profiles()
    ]


@app.get("/api/v1/status")
async def system_status():
    """Gibt den System-Status zurück."""
    import shutil

    settings = get_settings()
    sandbox_ok = False
    docker_version = "nicht verfügbar"

    try:
        import docker
        client = docker.from_env()
        docker_version = client.version().get("Version", "?")
        container = client.containers.get("sentinelclaw-sandbox")
        sandbox_ok = container.status == "running"
    except Exception:
        pass

    claude_available = shutil.which("claude") is not None
    openclaw_available = False
    try:
        from openclaw import OpenClaw
        openclaw_available = True
    except Exception:
        pass

    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus

    db = await get_db()
    scan_repo = ScanJobRepository(db)
    running = await scan_repo.list_by_status(ScanStatus.RUNNING)
    all_scans = await scan_repo.list_all(1000)

    from src.shared.kill_switch import KillSwitch
    kill_active = KillSwitch().is_active()

    return {
        "system": {
            "version": "0.1.0",
            "llm_provider": settings.llm_provider,
            "claude_cli": claude_available,
            "openclaw_sdk": openclaw_available,
            "docker": docker_version,
            "sandbox_running": sandbox_ok,
            "kill_switch_active": kill_active,
        },
        "scans": {
            "running": len(running),
            "total": len(all_scans),
        },
    }

"""
SentinelClaw REST-API Server.

FastAPI-basierte API die alle SentinelClaw-Funktionen exponiert.
Basis fuer die Web-UI und externe Integrationen.

Routen-Aufteilung:
  - server.py              -> App-Setup, Health, Status, Kill, Audit, Profile
  - scan_routes.py         -> CRUD fuer /api/v1/scans (Start, List, Get, Delete, Cancel)
  - scan_detail_routes.py  -> Sub-Ressourcen (Export, Compare, Report, Hosts, Ports, Phasen)
  - finding_routes.py      -> Alle /api/v1/findings/* Endpoints
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from src.shared.auth import decode_token
from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger, setup_logging

logger = get_logger(__name__)

# Globale DB-Instanz (wird im Lifespan initialisiert)
_db: DatabaseManager | None = None


async def get_db() -> DatabaseManager:
    """Gibt die aktive DB-Verbindung zurueck. Lazy-Init falls noetig."""
    global _db
    if _db is None:
        settings = get_settings()
        _db = DatabaseManager(settings.db_path)
        await _db.initialize()
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialisiert und schliesst Ressourcen beim Server-Start/-Stop."""
    global _db
    settings = get_settings()
    setup_logging(settings.log_level)

    _db = DatabaseManager(settings.db_path)
    await _db.initialize()

    # Standard-Admin anlegen falls noch nicht vorhanden
    from src.shared.auth import ensure_default_admin
    await ensure_default_admin(_db)

    # Hängende Scans aufräumen (>10min running = failed)
    await _cleanup_stuck_scans(_db)

    # Kill-Switch zurücksetzen falls er noch aktiv ist (vom letzten Lauf)
    from src.shared.kill_switch import KillSwitch
    if KillSwitch().is_active():
        KillSwitch().reset()
        logger.info("Kill-Switch zurückgesetzt (war aktiv vom letzten Lauf)")

    # Sandbox-Container starten falls gestoppt
    await _ensure_sandbox_running()

    logger.info("API-Server gestartet", port=settings.mcp_port)

    yield

    await _db.close()
    logger.info("API-Server gestoppt")


app = FastAPI(
    title="SentinelClaw API",
    description="AI-gestuetzte Security Assessment Platform — REST API",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS fuer Web-UI (nur eigene Domain im Produkt)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Auth-Middleware ──────────────────────────────────────────────

# Oeffentliche Pfade die keine Authentifizierung erfordern
_PUBLIC_PATHS = {"/health", "/api/v1/auth/login", "/docs", "/openapi.json", "/redoc"}


class AuthMiddleware(BaseHTTPMiddleware):
    """Prueft den Authorization-Header und setzt request.state.user."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Oeffentliche Pfade durchlassen
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        # Authorization-Header pruefen
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return Response(
                content='{"detail":"Token fehlt oder ungueltig"}',
                status_code=401,
                media_type="application/json",
            )

        token = auth_header.removeprefix("Bearer ").strip()
        payload = decode_token(token)
        if payload is None:
            return Response(
                content='{"detail":"Token abgelaufen oder ungueltig"}',
                status_code=401,
                media_type="application/json",
            )

        # Benutzer-Daten im Request verfuegbar machen
        request.state.user = payload
        return await call_next(request)


app.add_middleware(AuthMiddleware)

# ─── Router einbinden ─────────────────────────────────────────────

from src.api.auth_routes import router as auth_router  # noqa: E402
from src.api.chat_routes import router as chat_router  # noqa: E402
from src.api.finding_routes import router as finding_router  # noqa: E402
from src.api.scan_detail_routes import router as scan_detail_router  # noqa: E402
from src.api.scan_routes import router as scan_router  # noqa: E402

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(scan_detail_router)
app.include_router(finding_router)
app.include_router(chat_router)


# ─── Auto-Start: Sandbox beim Server-Start sicherstellen ─────────


async def _ensure_sandbox_running() -> None:
    """Startet den Sandbox-Container falls er gestoppt ist."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        try:
            container = client.containers.get("sentinelclaw-sandbox")
            if container.status != "running":
                container.start()
                logger.info("Sandbox-Container automatisch gestartet")
            else:
                logger.info("Sandbox-Container laeuft bereits")
        except docker_lib.errors.NotFound:
            logger.warning("Sandbox-Container nicht gefunden")
    except Exception as e:
        logger.debug("Sandbox-Auto-Start fehlgeschlagen", error=str(e))


# ─── Cleanup: Hängende Scans aufräumen ────────────────────────────


async def _cleanup_stuck_scans(db: DatabaseManager) -> int:
    """Markiert Scans die >10min 'running' sind als 'failed'."""
    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus

    repo = ScanJobRepository(db)
    running = await repo.list_by_status(ScanStatus.RUNNING)
    cleaned = 0

    for scan in running:
        if scan.started_at:
            elapsed = (datetime.now(UTC) - scan.started_at).total_seconds()
            if elapsed > 600:  # 10 Minuten
                await repo.update_status(scan.id, ScanStatus.FAILED)
                logger.warning(
                    "Hängenden Scan aufgeräumt",
                    scan_id=str(scan.id),
                    target=scan.target,
                    elapsed_s=int(elapsed),
                )
                cleaned += 1

    if cleaned:
        logger.info(f"{cleaned} hängende Scans aufgeräumt")
    return cleaned


# ─── Request/Response Modelle ──────────────────────────────────────


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


# ─── Endpoints: Health, Kill, Audit, Profile, Status ──────────────


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """System-Health-Check — wird von Docker Healthcheck genutzt."""
    settings = get_settings()
    sandbox_ok = False

    try:
        import docker
        client = docker.from_env()
        container = client.containers.get("sentinelclaw-sandbox")
        sandbox_ok = container.status == "running"
    except Exception as e:
        logger.debug("Docker nicht erreichbar", error=str(e))

    db_ok = _db is not None
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version="0.1.0",
        provider=settings.llm_provider,
        sandbox_running=sandbox_ok,
        db_connected=db_ok,
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.post("/api/v1/sandbox/start")
async def start_sandbox() -> dict:
    """Startet den Sandbox-Container."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        try:
            container = client.containers.get("sentinelclaw-sandbox")
            if container.status != "running":
                container.start()
                return {"status": "started", "message": "Sandbox-Container gestartet"}
            return {"status": "already_running", "message": "Sandbox läuft bereits"}
        except docker_lib.errors.NotFound:
            return {"status": "not_found", "message": "Sandbox-Container nicht vorhanden. Bitte 'docker compose up -d sandbox' ausführen."}
    except Exception as e:
        logger.debug("Sandbox-Start fehlgeschlagen", error=str(e))
        raise HTTPException(500, f"Sandbox konnte nicht gestartet werden: {e}")


@app.post("/api/v1/sandbox/stop")
async def stop_sandbox() -> dict:
    """Stoppt den Sandbox-Container."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        container = client.containers.get("sentinelclaw-sandbox")
        if container.status == "running":
            container.stop()
            return {"status": "stopped", "message": "Sandbox-Container gestoppt"}
        return {"status": "already_stopped", "message": "Sandbox ist bereits gestoppt"}
    except Exception as e:
        logger.debug("Sandbox-Stop fehlgeschlagen", error=str(e))
        raise HTTPException(500, f"Sandbox konnte nicht gestoppt werden: {e}")


@app.post("/api/v1/kill")
async def emergency_kill(request: KillRequest) -> dict:
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
async def list_audit_logs(limit: int = 50, action: str | None = None) -> list[dict]:
    """Listet Audit-Log-Eintraege."""
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
async def list_scan_profiles() -> list[dict]:
    """Listet alle verfuegbaren Scan-Profile."""
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
async def system_status() -> dict:
    """Gibt den System-Status zurueck."""
    import shutil

    settings = get_settings()
    sandbox_ok = False
    docker_version = "nicht verfuegbar"

    try:
        import docker
        client = docker.from_env()
        docker_version = client.version().get("Version", "?")
        container = client.containers.get("sentinelclaw-sandbox")
        sandbox_ok = container.status == "running"
    except Exception as e:
        logger.debug("Docker nicht erreichbar", error=str(e))

    claude_available = shutil.which("claude") is not None
    openclaw_available = False
    try:
        from openclaw import OpenClaw  # noqa: F401
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

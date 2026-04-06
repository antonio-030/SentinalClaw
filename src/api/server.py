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

import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from src.shared.auth import decode_token, require_role
from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger, setup_logging

logger = get_logger(__name__)


# ─── Login Rate-Limiter (In-Memory, IP-basiert) ─────────────────


class LoginRateLimiter:
    """Begrenzt fehlgeschlagene Login-Versuche pro IP-Adresse.

    Speichert Zeitstempel fehlgeschlagener Versuche und blockiert
    weitere Logins wenn das Limit innerhalb des Zeitfensters erreicht ist.
    """

    WINDOW_SECONDS = 300  # 5 Minuten

    def __init__(self, max_attempts: int = 5) -> None:
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._max_attempts = max_attempts

    def is_blocked(self, ip: str) -> bool:
        """Prueft ob die IP blockiert ist."""
        now = time.time()
        # Alte Eintraege ausserhalb des Zeitfensters entfernen
        self._attempts[ip] = [
            t for t in self._attempts[ip]
            if now - t < self.WINDOW_SECONDS
        ]
        return len(self._attempts[ip]) >= self._max_attempts

    def record_failure(self, ip: str) -> None:
        """Registriert einen fehlgeschlagenen Login-Versuch."""
        self._attempts[ip].append(time.time())

    def reset(self, ip: str) -> None:
        """Setzt den Zaehler fuer eine IP zurueck (nach erfolgreichem Login)."""
        self._attempts.pop(ip, None)


# Globale Rate-Limiter-Instanz
_rate_limiter: LoginRateLimiter | None = None


def get_rate_limiter() -> LoginRateLimiter:
    """Gibt den globalen Rate-Limiter zurueck (Lazy-Init)."""
    global _rate_limiter
    if _rate_limiter is None:
        settings = get_settings()
        _rate_limiter = LoginRateLimiter(max_attempts=settings.login_rate_limit_attempts)
    return _rate_limiter

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

    # Standard-Einstellungen und Builtin-Profile in die DB säen
    from src.shared.settings_repository import seed_defaults
    from src.shared.profile_repository import seed_builtin_profiles
    from src.shared.settings_service import init_settings_service
    await seed_defaults(_db)
    await seed_builtin_profiles(_db)
    init_settings_service(_db)

    # Sandbox-Container starten falls gestoppt
    await _ensure_sandbox_running()

    logger.info("API-Server gestartet", port=settings.mcp_port)

    yield

    await _db.close()
    logger.info("API-Server gestoppt")


# API-Dokumentation nur im Debug-Modus exponieren
_init_settings = get_settings()
_docs_url = "/docs" if _init_settings.debug else None
_redoc_url = "/redoc" if _init_settings.debug else None

if not _init_settings.debug:
    logger.info("Produktion: /docs und /redoc deaktiviert")

app = FastAPI(
    title="SentinelClaw API",
    description="AI-gestuetzte Security Assessment Platform — REST API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url="/openapi.json" if _init_settings.debug else None,
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
# /docs, /redoc, /openapi.json nur im Debug-Modus (werden sonst gar nicht gemountet)
_PUBLIC_PATHS: set[str] = {"/health", "/api/v1/auth/login", "/api/v1/auth/mfa/login"}
if _init_settings.debug:
    _PUBLIC_PATHS |= {"/docs", "/openapi.json", "/redoc"}


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
from src.api.agent_tool_routes import router as agent_tool_router  # noqa: E402
from src.api.whitelist_routes import router as whitelist_router  # noqa: E402
from src.api.settings_routes import router as settings_router  # noqa: E402
from src.api.approval_routes import router as approval_router  # noqa: E402
from src.api.kill_verification_routes import router as kill_verify_router  # noqa: E402
from src.api.mfa_routes import router as mfa_router  # noqa: E402

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(scan_detail_router)
app.include_router(finding_router)
app.include_router(chat_router)
app.include_router(agent_tool_router)
app.include_router(whitelist_router)
app.include_router(settings_router)
app.include_router(approval_router)
app.include_router(kill_verify_router)
app.include_router(mfa_router)


# ─── WebSocket-Endpoint ──────────────────────────────────────────

from fastapi import WebSocket, WebSocketDisconnect  # noqa: E402
from src.api.websocket_manager import ws_manager  # noqa: E402


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket) -> None:
    """WebSocket für Echtzeit-Chat und Approval-Benachrichtigungen."""
    # Token aus Query-Parameter lesen (WebSocket hat keinen Auth-Header)
    token = websocket.query_params.get("token", "")
    payload = decode_token(token)
    if payload is None:
        await websocket.close(code=4001, reason="Token ungültig")
        return

    user_id = payload.get("sub", "anonymous")
    await ws_manager.connect(websocket, user_id)

    try:
        while True:
            # Heartbeat/Ping empfangen — hält Verbindung offen
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event":"pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)


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
async def start_sandbox(request: Request) -> dict:
    """Startet den Sandbox-Container (security_lead+)."""
    require_role(request, "security_lead")
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
async def stop_sandbox(request: Request) -> dict:
    """Stoppt den Sandbox-Container (security_lead+)."""
    require_role(request, "security_lead")
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
async def emergency_kill(request: Request, body: KillRequest) -> dict:
    """Aktiviert den Kill-Switch — stoppt ALLE laufenden Scans (security_lead+)."""
    caller = require_role(request, "security_lead")
    from src.shared.kill_switch import KillSwitch
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanStatus

    ks = KillSwitch()
    ks.activate(triggered_by=caller.get("email", "api_user"), reason=body.reason)

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
        details={"reason": body.reason, "scans_killed": len(running)},
        triggered_by=caller.get("email", "api_user"),
    ))

    return {"status": "killed", "scans_stopped": len(running), "reason": body.reason}


@app.post("/api/v1/kill/reset")
async def reset_kill_switch(request: Request) -> dict:
    """Setzt den Kill-Switch zurück und startet die Sandbox neu (security_lead+).

    Stellt das System nach einem Emergency-Kill wieder her:
    1. Kill-Switch zurücksetzen
    2. Sandbox-Container starten
    3. Audit-Log schreiben
    """
    caller = require_role(request, "security_lead")
    from src.shared.kill_switch import KillSwitch
    from src.shared.repositories import AuditLogRepository
    from src.shared.types.models import AuditLogEntry

    ks = KillSwitch()
    if not ks.is_active():
        return {"status": "already_reset", "message": "Kill-Switch ist nicht aktiv"}

    ks.reset()

    # Sandbox neu starten
    sandbox_started = False
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        try:
            container = client.containers.get("sentinelclaw-sandbox")
            if container.status != "running":
                container.start()
                sandbox_started = True
        except docker_lib.errors.NotFound:
            logger.warning("Sandbox-Container nicht gefunden")
    except Exception as exc:
        logger.warning("Sandbox-Neustart fehlgeschlagen", error=str(exc))

    # Audit-Log
    db = await get_db()
    audit_repo = AuditLogRepository(db)
    await audit_repo.create(AuditLogEntry(
        action="kill.reset",
        resource_type="system",
        details={"sandbox_restarted": sandbox_started},
        triggered_by=caller.get("email", "api_user"),
    ))

    logger.info(
        "Kill-Switch zurückgesetzt",
        by=caller.get("email"),
        sandbox=sandbox_started,
    )

    return {
        "status": "reset",
        "sandbox_started": sandbox_started,
        "message": "System wiederhergestellt",
    }


@app.get("/api/v1/audit")
async def list_audit_logs(request: Request, limit: int = 50, action: str | None = None) -> list[dict]:
    """Listet Audit-Log-Eintraege (analyst+)."""
    require_role(request, "analyst")
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

    # NemoClaw/OpenShell Status pruefen
    nemoclaw_available = False
    nemoclaw_version = ""
    openshell_available = shutil.which("openshell") is not None

    try:
        from src.agents.nemoclaw_runtime import NemoClawRuntime
        runtime = NemoClawRuntime()
        status = await runtime.check_sandbox_status()
        nemoclaw_available = status.get("status") != "unreachable"
        nemoclaw_version = status.get("version", "")
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
            "nemoclaw_available": nemoclaw_available,
            "nemoclaw_version": nemoclaw_version,
            "openshell_available": openshell_available,
            "docker": docker_version,
            "sandbox_running": sandbox_ok,
            "kill_switch_active": kill_active,
        },
        "scans": {
            "running": len(running),
            "total": len(all_scans),
        },
    }

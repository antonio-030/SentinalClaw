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
from starlette.middleware.base import BaseHTTPMiddleware

from src.shared.auth import decode_token
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
        _db = DatabaseManager(
            db_path=settings.db_path,
            db_type=settings.db_type,
            db_dsn=settings.get_db_dsn() if settings.db_type == "postgresql" else "",
        )
        await _db.initialize()
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialisiert und schliesst Ressourcen beim Server-Start/-Stop."""
    global _db
    settings = get_settings()
    setup_logging(settings.log_level)

    _db = DatabaseManager(
        db_path=settings.db_path,
        db_type=settings.db_type,
        db_dsn=settings.get_db_dsn() if settings.db_type == "postgresql" else "",
    )
    await _db.initialize()

    # Schema-Migrationen ausführen (nach initialize, vor Seed-Daten)
    from src.shared.migrations import run_migrations
    await run_migrations(_db)

    # Standard-Admin anlegen falls noch nicht vorhanden
    from src.shared.auth import ensure_default_admin, validate_jwt_secret_for_production
    await ensure_default_admin(_db)

    # JWT-Secret im Produktionsmodus erzwingen
    validate_jwt_secret_for_production(settings.debug)

    # Token-Blacklist aus DB laden (für serverseitiges Logout über Neustarts)
    await token_blacklist.load_from_db(_db)
    await token_blacklist.cleanup_expired(_db)

    # Auto-Backup beim Start (bevor Retention-Cleanup läuft)
    try:
        from src.shared.backup_service import cleanup_old_backups, create_backup
        await create_backup(_db)
        cleanup_old_backups(max_age_days=30)
    except Exception as backup_err:
        logger.warning("Auto-Backup fehlgeschlagen", error=str(backup_err))

    # DSGVO: Aufbewahrungsfristen durchsetzen (alte Scans löschen)
    from src.shared.retention_service import run_retention_cleanup
    await run_retention_cleanup(_db)

    # Hängende Scans aufräumen (>10min running = failed)
    await _cleanup_stuck_scans(_db)

    # Kill-Switch zurücksetzen falls er noch aktiv ist (vom letzten Lauf)
    from src.shared.kill_switch import KillSwitch
    if KillSwitch().is_active():
        KillSwitch().reset()
        logger.info("Kill-Switch zurückgesetzt (war aktiv vom letzten Lauf)")

    # Standard-Einstellungen und Builtin-Profile in die DB säen
    from src.shared.profile_repository import seed_builtin_profiles
    from src.shared.settings_repository import seed_defaults
    from src.shared.settings_service import init_settings_service
    await seed_defaults(_db)
    await seed_builtin_profiles(_db)
    init_settings_service(_db)

    # Produktions-Anforderungen prüfen (vor Sandbox-Start)
    if not settings.debug:
        _enforce_production_requirements(settings)

    # Sandbox-Container starten falls gestoppt
    await _ensure_sandbox_running()

    # NemoClaw-Verfügbarkeit beim Start prüfen (kein Blocker)
    _check_nemoclaw_on_startup()

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

# CORS — Origins konfigurierbar über SENTINEL_CORS_ORIGINS
_cors_origins = [o.strip() for o in _init_settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

# ─── Auth-Middleware ──────────────────────────────────────────────

# Oeffentliche Pfade die keine Authentifizierung erfordern
# /docs, /redoc, /openapi.json nur im Debug-Modus (werden sonst gar nicht gemountet)
_PUBLIC_PATHS: set[str] = {"/health", "/metrics", "/api/v1/auth/login", "/api/v1/auth/mfa/login"}
if _init_settings.debug:
    _PUBLIC_PATHS |= {"/docs", "/openapi.json", "/redoc"}

# HTTP-Methoden die den Serverzustand ändern — CSRF-Schutz erforderlich
_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "DELETE", "PATCH"}

from src.shared.auth import SESSION_INACTIVITY_MINUTES  # noqa: E402
from src.shared.token_blacklist import token_blacklist  # noqa: E402

# In-Memory: Letzte Aktivität pro Session (jti → Zeitstempel)
_session_activity: dict[str, float] = {}


class AuthMiddleware(BaseHTTPMiddleware):
    """Prüft Auth-Cookie (oder Bearer-Header), Blacklist, CSRF und Inaktivität."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Öffentliche Pfade durchlassen
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        # Token extrahieren: Cookie bevorzugt, Bearer-Header als Fallback
        token = request.cookies.get("sc_session", "")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.removeprefix("Bearer ").strip()

        if not token:
            return Response(
                content='{"detail":"Token fehlt oder ungueltig"}',
                status_code=401,
                media_type="application/json",
            )

        payload = decode_token(token)
        if payload is None:
            return Response(
                content='{"detail":"Token abgelaufen oder ungueltig"}',
                status_code=401,
                media_type="application/json",
            )

        # Token-Revokation prüfen (serverseitiges Logout)
        jti = payload.get("jti", "")
        if jti and token_blacklist.is_revoked(jti):
            return Response(
                content='{"detail":"Session wurde beendet"}',
                status_code=401,
                media_type="application/json",
            )

        # Inaktivitäts-Timeout prüfen
        import time
        now = time.time()
        if jti and jti in _session_activity:
            last_active = _session_activity[jti]
            if (now - last_active) > SESSION_INACTIVITY_MINUTES * 60:
                return Response(
                    content='{"detail":"Session wegen Inaktivitaet abgelaufen"}',
                    status_code=401,
                    media_type="application/json",
                )

        # CSRF-Schutz für zustandsändernde Requests mit Cookie-Auth
        if request.method in _STATE_CHANGING_METHODS and request.cookies.get("sc_session"):
            csrf_cookie = request.cookies.get("sc_csrf", "")
            csrf_header = request.headers.get("X-CSRF-Token", "")
            if not csrf_cookie or csrf_cookie != csrf_header:
                return Response(
                    content='{"detail":"CSRF-Token fehlt oder ungueltig"}',
                    status_code=403,
                    media_type="application/json",
                )

        # Aktivität tracken und Benutzer-Daten setzen
        if jti:
            _session_activity[jti] = now
        request.state.user = payload
        return await call_next(request)


app.add_middleware(AuthMiddleware)

# Security-Headers (CSP, X-Frame-Options, etc.) auf jede Response
from src.api.security_headers import SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(SecurityHeadersMiddleware)

# Globales Rate-Limiting — wird VOR AuthMiddleware ausgeführt (LIFO-Reihenfolge)
from src.api.rate_limiter import RateLimitMiddleware  # noqa: E402

app.add_middleware(RateLimitMiddleware)

# ─── Router einbinden ─────────────────────────────────────────────

from src.api.agent_tool_routes import router as agent_tool_router  # noqa: E402
from src.api.approval_routes import router as approval_router  # noqa: E402
from src.api.auth_routes import router as auth_router  # noqa: E402
from src.api.backup_routes import router as backup_router  # noqa: E402
from src.api.chat_routes import router as chat_router  # noqa: E402
from src.api.finding_routes import router as finding_router  # noqa: E402
from src.api.gdpr_routes import router as gdpr_router  # noqa: E402
from src.api.kill_verification_routes import router as kill_verify_router  # noqa: E402
from src.api.metrics_routes import router as metrics_router  # noqa: E402
from src.api.mfa_routes import router as mfa_router  # noqa: E402
from src.api.org_routes import router as org_router  # noqa: E402
from src.api.scan_detail_routes import router as scan_detail_router  # noqa: E402
from src.api.scan_routes import router as scan_router  # noqa: E402
from src.api.settings_routes import router as settings_router  # noqa: E402
from src.api.system_routes import router as system_router  # noqa: E402
from src.api.whitelist_routes import router as whitelist_router  # noqa: E402
from src.api.workspace_routes import router as workspace_router  # noqa: E402

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
app.include_router(workspace_router)
app.include_router(gdpr_router)
app.include_router(org_router)
app.include_router(backup_router)
app.include_router(metrics_router)
app.include_router(system_router)


# ─── WebSocket-Endpoint ──────────────────────────────────────────

from fastapi import WebSocket, WebSocketDisconnect  # noqa: E402

from src.api.websocket_manager import ws_manager  # noqa: E402


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket) -> None:
    """WebSocket für Echtzeit-Chat und Approval-Benachrichtigungen."""
    # Token aus Cookie lesen (bevorzugt), Query-Parameter als Fallback
    token = websocket.cookies.get("sc_session", "")
    if not token:
        token = websocket.query_params.get("token", "")
    payload = decode_token(token)
    if payload is None:
        await websocket.close(code=4001, reason="Token ungültig")
        return

    # Revozierte Tokens auch für WebSocket blockieren
    jti = payload.get("jti", "")
    if jti and token_blacklist.is_revoked(jti):
        await websocket.close(code=4001, reason="Session beendet")
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


# ─── NemoClaw Startup-Check ──────────────────────────────────────


def _check_nemoclaw_on_startup() -> None:
    """Prüft NemoClaw-Verfügbarkeit beim Server-Start.

    Loggt eine Warnung wenn NemoClaw nicht erreichbar ist.
    Blockiert den Start NICHT — Graceful Degradation greift zur Laufzeit.
    """
    try:
        from src.agents.nemoclaw_runtime import NemoClawRuntime
        status = NemoClawRuntime.check_availability()
        if status.get("available", False):
            logger.info(
                "NemoClaw verfügbar",
                details=status.get("details", {}),
            )
        else:
            logger.warning(
                "NemoClaw beim Start NICHT verfügbar — Fallback-Provider wird bei Bedarf genutzt",
                reason=status.get("reason", "unbekannt"),
                details=status.get("details", {}),
            )
    except Exception as error:
        logger.warning(
            "NemoClaw Startup-Check fehlgeschlagen",
            error=str(error),
        )


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


# ─── Docker-Verfügbarkeit prüfen ─────────────────────────────────


def _is_docker_available() -> bool:
    """Prüft ob Docker erreichbar ist (für Health-Check)."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        client.ping()
        return True
    except Exception:
        return False


# ─── Produktions-Anforderungen ────────────────────────────────────


def _enforce_production_requirements(settings: object) -> None:
    """Prüft Produktionsanforderungen beim Start. Bricht ab wenn nicht erfüllt."""
    from src.shared.auth import _DEFAULT_DEV_SECRET, SECRET_KEY

    errors: list[str] = []
    if SECRET_KEY == _DEFAULT_DEV_SECRET:
        errors.append(
            "SENTINEL_JWT_SECRET nicht gesetzt (Dev-Default ist unsicher)"
        )
    if not settings.db_path.parent.exists():
        errors.append(
            f"DB-Verzeichnis existiert nicht: {settings.db_path.parent}"
        )
    if errors:
        for err in errors:
            logger.error("Produktions-Anforderung nicht erfüllt", detail=err)
        raise RuntimeError(
            f"Server kann nicht im Produktionsmodus starten. "
            f"{len(errors)} Anforderung(en) nicht erfüllt."
        )
    logger.info("Alle Produktions-Anforderungen erfüllt")


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


# System-Endpoints (Health, Kill, Audit, Status) → system_routes.py

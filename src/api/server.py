"""
SentinelClaw REST-API Server.

FastAPI-basierte API die alle SentinelClaw-Funktionen exponiert.
Basis fuer die Web-UI und externe Integrationen.

Routen-Aufteilung:
  - server.py              -> App-Setup, Lifespan, Router-Bindung
  - auth_middleware.py      -> Auth-Cookie/Bearer, CSRF, Session-Timeout
  - rate_limit_login.py     -> Login-Rate-Limiting (IP-basiert)
  - startup.py             -> Initialisierungs-Aufgaben (Migrations, Seed, Checks)
  - scan_routes.py         -> CRUD fuer /api/v1/scans
  - scan_detail_routes.py  -> Sub-Ressourcen (Export, Compare, Report, Hosts, Ports)
  - finding_routes.py      -> Alle /api/v1/findings/* Endpoints
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from src.shared.auth import decode_token
from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger, setup_logging
from src.shared.token_blacklist import token_blacklist

logger = get_logger(__name__)

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

    # Alle Startup-Aufgaben (Admin, Blacklist, Backup, Seed, Checks)
    from src.api.startup import run_startup_tasks
    await run_startup_tasks(_db, settings)

    logger.info("API-Server gestartet", port=settings.mcp_port)
    yield
    await _db.close()
    logger.info("API-Server gestoppt")


# ─── App-Konfiguration ──────────────────────────────────────────

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
_cors_origins = [
    o.strip() for o in _init_settings.cors_origins.split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

# ─── Middleware-Stack (LIFO: Rate-Limit → Auth → Security-Headers) ─

from src.api.auth_middleware import AuthMiddleware  # noqa: E402
from src.api.rate_limiter import RateLimitMiddleware  # noqa: E402
from src.api.security_headers import SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(AuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# ─── Router einbinden ─────────────────────────────────────────────

from src.api.agent_report_routes import router as agent_report_router  # noqa: E402
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
from src.api.agent_memory_routes import router as agent_memory_router  # noqa: E402
from src.api.nemoclaw_setup_routes import router as nemoclaw_setup_router  # noqa: E402
from src.api.org_routes import router as org_router  # noqa: E402
from src.api.scan_detail_routes import router as scan_detail_router  # noqa: E402
from src.api.scan_routes import router as scan_router  # noqa: E402
from src.api.settings_routes import router as settings_router  # noqa: E402
from src.api.system_routes import router as system_router  # noqa: E402
from src.api.user_management_routes import router as user_mgmt_router  # noqa: E402
from src.api.whitelist_routes import router as whitelist_router  # noqa: E402
from src.api.workspace_routes import router as workspace_router  # noqa: E402

app.include_router(auth_router)
app.include_router(user_mgmt_router)
app.include_router(scan_router)
app.include_router(scan_detail_router)
app.include_router(finding_router)
app.include_router(chat_router)
app.include_router(agent_report_router)
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
app.include_router(nemoclaw_setup_router)
app.include_router(agent_memory_router)


# ─── WebSocket-Endpoint ──────────────────────────────────────────

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
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event":"pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)

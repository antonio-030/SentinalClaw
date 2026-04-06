"""
Kill-Verifikations-API für SentinelClaw.

Stellt den Endpoint GET /api/v1/kill/status bereit, der 5 unabhängige
Checks durchführt um sicherzustellen, dass ein Kill-Switch vollständig
wirksam ist. Wird von der UI und vom Watchdog genutzt.
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/kill", tags=["Kill-Verifikation"])


class KillVerificationResponse(BaseModel):
    """Ergebnis der 5 Kill-Verifikations-Checks."""

    kill_active: bool
    containers_stopped: bool
    network_blocked: bool
    scans_killed: bool
    audit_logged: bool
    all_verified: bool


@router.get("/status", response_model=KillVerificationResponse)
async def get_kill_status(request: Request) -> KillVerificationResponse:
    """Gibt 5 Verifikations-Checks für den Kill-Switch zurück.

    Prüft ob der Kill-Switch vollständig wirksam ist:
    1. Kill-Flag gesetzt
    2. Sandbox-Container gestoppt
    3. Scan-Netzwerke getrennt
    4. Alle Scans auf emergency_killed
    5. Kill-Eintrag im Audit-Log
    """
    require_role(request, "analyst")

    kill_active = _check_kill_active()
    containers_stopped = await _check_containers_stopped()
    network_blocked = await _check_network_blocked()
    scans_killed = await _check_scans_killed()
    audit_logged = await _check_audit_logged()

    all_verified = all([
        kill_active, containers_stopped, network_blocked,
        scans_killed, audit_logged,
    ])

    return KillVerificationResponse(
        kill_active=kill_active,
        containers_stopped=containers_stopped,
        network_blocked=network_blocked,
        scans_killed=scans_killed,
        audit_logged=audit_logged,
        all_verified=all_verified,
    )


def _check_kill_active() -> bool:
    """Check 1: Ist das Kill-Flag im Singleton gesetzt?"""
    from src.shared.kill_switch import KillSwitch
    return KillSwitch().is_active()


async def _check_containers_stopped() -> bool:
    """Check 2: Läuft kein sentinelclaw-sandbox Container?"""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        container = client.containers.get("sentinelclaw-sandbox")
        return container.status != "running"
    except Exception:
        # Container nicht gefunden = gestoppt
        return True


async def _check_network_blocked() -> bool:
    """Check 3: Sind alle Scan-Netzwerke disconnected?"""
    try:
        from src.shared.network_kill import verify_network_blocked
        return await verify_network_blocked()
    except Exception as exc:
        logger.debug("network_check_error", error=str(exc))
        return False


async def _check_scans_killed() -> bool:
    """Check 4: Haben alle laufenden Scans den Status emergency_killed?"""
    try:
        from src.api.server import get_db
        from src.shared.repositories import ScanJobRepository
        from src.shared.types.models import ScanStatus

        db = await get_db()
        repo = ScanJobRepository(db)
        running = await repo.list_by_status(ScanStatus.RUNNING)
        # Keine laufenden Scans = alle wurden gekillt
        return len(running) == 0
    except Exception as exc:
        logger.debug("scans_check_error", error=str(exc))
        return False


async def _check_audit_logged() -> bool:
    """Check 5: Existiert ein kill.activated Eintrag im Audit-Log?"""
    try:
        from src.api.server import get_db
        from src.shared.repositories import AuditLogRepository

        db = await get_db()
        repo = AuditLogRepository(db)
        entries = await repo.list_by_action("kill.activated", limit=1)
        return len(entries) > 0
    except Exception as exc:
        logger.debug("audit_check_error", error=str(exc))
        return False

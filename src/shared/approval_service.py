"""Approval-Service für Eskalationsgenehmigungen.

Erstellt Approval-Requests wenn der Agent Tools mit hoher
Eskalationsstufe (≥3) nutzen will. Der Admin muss über die
Web-UI genehmigen bevor der Scan fortfahren kann.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

def _get_approval_timeout() -> int:
    """Liest den Approval-Timeout aus den Settings (konfigurierbar über UI)."""
    try:
        from src.shared.settings_service import get_setting_int_sync
        return get_setting_int_sync("approval_timeout_seconds", 300)
    except Exception:
        return 300


# Intervall zwischen Status-Prüfungen
POLL_INTERVAL_SECONDS = 5


async def create_approval_request(
    db: DatabaseManager,
    scan_job_id: str,
    tool_name: str,
    target: str,
    escalation_level: int,
    description: str = "",
) -> str:
    """Erstellt einen neuen Approval-Request in der Datenbank.

    Returns:
        Die ID des erstellten Requests.
    """
    request_id = str(uuid4())
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=_get_approval_timeout())

    conn = await db.get_connection()
    await conn.execute(
        """INSERT INTO approval_requests
           (id, scan_job_id, requested_by, action_type, escalation_level,
            target, tool_name, description, status, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
        (
            request_id, scan_job_id, "orchestrator", "tool_execution",
            escalation_level, target, tool_name, description,
            expires_at.isoformat(), now.isoformat(),
        ),
    )
    await conn.commit()

    logger.info(
        "Approval-Request erstellt",
        id=request_id, tool=tool_name,
        level=escalation_level, target=target,
    )

    # WebSocket-Benachrichtigung an verbundene Clients
    try:
        from src.api.websocket_manager import ws_manager
        await ws_manager.broadcast({
            "event": "approval_required",
            "data": {
                "id": request_id,
                "scan_job_id": scan_job_id,
                "tool_name": tool_name,
                "target": target,
                "escalation_level": escalation_level,
                "description": description,
            },
        })
    except Exception:
        pass  # WebSocket nicht verfügbar — nicht kritisch

    return request_id


async def wait_for_approval(
    db: DatabaseManager,
    request_id: str,
    timeout: int = _get_approval_timeout(),
) -> bool:
    """Wartet auf eine Genehmigungsentscheidung.

    Pollt die Datenbank alle POLL_INTERVAL_SECONDS Sekunden.

    Returns:
        True wenn genehmigt, False wenn abgelehnt oder Timeout.
    """
    deadline = asyncio.get_event_loop().time() + timeout

    while asyncio.get_event_loop().time() < deadline:
        conn = await db.get_connection()
        cursor = await conn.execute(
            "SELECT status FROM approval_requests WHERE id = ?",
            (request_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return False

        status = row[0]
        if status == "approved":
            logger.info("Approval genehmigt", id=request_id)
            return True
        if status == "rejected":
            logger.info("Approval abgelehnt", id=request_id)
            return False

        await asyncio.sleep(POLL_INTERVAL_SECONDS)

    # Timeout — als abgelaufen markieren
    conn = await db.get_connection()
    await conn.execute(
        "UPDATE approval_requests SET status = 'expired' WHERE id = ? AND status = 'pending'",
        (request_id,),
    )
    await conn.commit()
    logger.warning("Approval-Timeout", id=request_id)
    return False


async def check_and_request_approval(
    db: DatabaseManager,
    scan_job_id: str,
    tool_name: str,
    target: str,
    escalation_level: int,
    max_allowed_level: int,
) -> bool:
    """Prüft ob ein Tool eine Genehmigung braucht und wartet darauf.

    Stufe 0-2: Keine Genehmigung nötig (automatisch erlaubt)
    Stufe 3+: Approval-Request erstellen und auf Entscheidung warten

    Returns:
        True wenn erlaubt (direkt oder nach Genehmigung), False wenn blockiert.
    """
    # Genehmigungsschwelle aus Settings laden (konfigurierbar über UI)
    from src.shared.settings_service import get_setting_int_sync
    approval_threshold = get_setting_int_sync("agent_approval_required_level", 3)

    # Unter der Genehmigungsschwelle — direkt erlaubt
    if escalation_level < approval_threshold:
        return True

    # Eskalationsstufe übersteigt den erlaubten Scope
    if escalation_level > max_allowed_level:
        logger.warning(
            "Eskalationsstufe übersteigt Scope",
            tool=tool_name, level=escalation_level, max=max_allowed_level,
        )
        return False

    description = (
        f"Tool '{tool_name}' (Stufe {escalation_level}) auf Ziel '{target}' "
        f"erfordert Genehmigung durch security_lead oder höher."
    )

    request_id = await create_approval_request(
        db, scan_job_id, tool_name, target, escalation_level, description,
    )

    return await wait_for_approval(db, request_id)

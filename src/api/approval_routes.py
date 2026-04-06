"""
Approval-Routen für Eskalationsgenehmigungen.

Agents erstellen Approval-Requests wenn sie Tools mit Eskalationsstufe 3+
ausführen wollen. Security-Leads/Org-Admins genehmigen oder lehnen ab.
Jede Entscheidung wird im Audit-Log protokolliert.
"""

from datetime import UTC, datetime

import aiosqlite
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger
from src.shared.types.models import AuditLogEntry

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/approvals", tags=["Approvals"])


# ─── Request/Response Modelle ────────────────────────────────────────


class ApprovalOut(BaseModel):
    """Approval-Request Ausgabe."""

    id: str
    scan_job_id: str
    requested_by: str
    action_type: str
    escalation_level: int
    target: str
    tool_name: str
    description: str
    risk_assessment: str
    status: str
    decided_by: str | None
    decided_at: str | None
    expires_at: str
    created_at: str


class ApprovalDecisionRequest(BaseModel):
    """Genehmigung oder Ablehnung."""

    reason: str = Field(default="", description="Optionale Begründung")


# ─── DB-Zugriff ─────────────────────────────────────────────────────


async def _get_db():
    from src.api.server import get_db
    return await get_db()


# ─── Endpoints ──────────────────────────────────────────────────────


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(request: Request, status: str | None = None):
    """Listet Approval-Requests (analyst+). Optional nach Status filtern."""
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()
    conn.row_factory = aiosqlite.Row

    if status:
        cursor = await conn.execute(
            "SELECT * FROM approval_requests WHERE status = ? "
            "ORDER BY created_at DESC", (status,),
        )
    else:
        cursor = await conn.execute(
            "SELECT * FROM approval_requests ORDER BY created_at DESC"
        )

    rows = await cursor.fetchall()

    # Abgelaufene Requests automatisch als expired markieren
    now = datetime.now(UTC).isoformat()
    for row in rows:
        if row["status"] == "pending" and row["expires_at"] < now:
            await conn.execute(
                "UPDATE approval_requests SET status = 'expired' WHERE id = ?",
                (row["id"],),
            )
    await conn.commit()

    return [ApprovalOut(**dict(row)) for row in rows]


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_approval(approval_id: str, request: Request):
    """Einzelnen Approval-Request laden."""
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()
    conn.row_factory = aiosqlite.Row
    cursor = await conn.execute(
        "SELECT * FROM approval_requests WHERE id = ?", (approval_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Approval-Request nicht gefunden")
    return ApprovalOut(**dict(row))


@router.put("/{approval_id}/approve")
async def approve_request(
    approval_id: str, request: Request, body: ApprovalDecisionRequest,
):
    """Genehmigt einen Approval-Request. Stufe 3: security_lead+, Stufe 4: org_admin."""
    db = await _get_db()
    conn = await db.get_connection()
    conn.row_factory = aiosqlite.Row

    cursor = await conn.execute(
        "SELECT * FROM approval_requests WHERE id = ?", (approval_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Approval-Request nicht gefunden")
    if row["status"] != "pending":
        raise HTTPException(409, f"Request bereits entschieden: {row['status']}")

    # Rollenprüfung abhängig von Eskalationsstufe
    required = "org_admin" if row["escalation_level"] >= 4 else "security_lead"
    user = require_role(request, required)

    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "UPDATE approval_requests SET status = 'approved', "
        "decided_by = ?, decided_at = ? WHERE id = ?",
        (user["email"], now, approval_id),
    )
    await conn.commit()

    # Audit-Log
    from src.shared.repositories import AuditLogRepository
    audit = AuditLogRepository(db)
    await audit.create(AuditLogEntry(
        action="approval.approved",
        resource_type="approval_request",
        resource_id=approval_id,
        details={
            "target": row["target"],
            "tool": row["tool_name"],
            "escalation_level": row["escalation_level"],
            "reason": body.reason,
        },
        triggered_by=user["email"],
    ))

    # WebSocket-Benachrichtigung
    try:
        from src.api.websocket_manager import ws_manager
        await ws_manager.broadcast("approval_decided", {
            "id": approval_id, "status": "approved",
            "decided_by": user["email"],
        })
    except Exception as ws_err:
        logger.debug("WS-Push fehlgeschlagen", error=str(ws_err))

    logger.info("Approval genehmigt", id=approval_id, by=user["email"])
    return {"status": "approved", "decided_by": user["email"]}


@router.put("/{approval_id}/reject")
async def reject_request(
    approval_id: str, request: Request, body: ApprovalDecisionRequest,
):
    """Lehnt einen Approval-Request ab."""
    db = await _get_db()
    conn = await db.get_connection()
    conn.row_factory = aiosqlite.Row

    cursor = await conn.execute(
        "SELECT * FROM approval_requests WHERE id = ?", (approval_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Approval-Request nicht gefunden")
    if row["status"] != "pending":
        raise HTTPException(409, f"Request bereits entschieden: {row['status']}")

    required = "org_admin" if row["escalation_level"] >= 4 else "security_lead"
    user = require_role(request, required)

    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "UPDATE approval_requests SET status = 'rejected', "
        "decided_by = ?, decided_at = ? WHERE id = ?",
        (user["email"], now, approval_id),
    )
    await conn.commit()

    # Audit-Log
    from src.shared.repositories import AuditLogRepository
    audit = AuditLogRepository(db)
    await audit.create(AuditLogEntry(
        action="approval.rejected",
        resource_type="approval_request",
        resource_id=approval_id,
        details={
            "target": row["target"],
            "tool": row["tool_name"],
            "escalation_level": row["escalation_level"],
            "reason": body.reason,
        },
        triggered_by=user["email"],
    ))

    try:
        from src.api.websocket_manager import ws_manager
        await ws_manager.broadcast("approval_decided", {
            "id": approval_id, "status": "rejected",
            "decided_by": user["email"],
        })
    except Exception as ws_err:
        logger.debug("WS-Push fehlgeschlagen", error=str(ws_err))

    logger.info("Approval abgelehnt", id=approval_id, by=user["email"])
    return {"status": "rejected", "decided_by": user["email"]}

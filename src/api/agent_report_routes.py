"""
Agent-Report-Routen für die SentinelClaw REST-API.

CRUD-Endpunkte für Agent-Reports — ausgelagert aus chat_routes.py
um die 300-Zeilen-Grenze einzuhalten.
"""

from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["Agent Reports"])


# ─── Request-Modell ──────────────────────────────────────────────────


class SaveReportRequest(BaseModel):
    """Manuelles Speichern einer Agent-Antwort als Report."""

    content: str = Field(description="Agent-Antwort als Markdown")


# ─── DB-Zugriff ─────────────────────────────────────────────────────


async def _get_db():
    """Gibt die aktive DB-Instanz zurück (Lazy-Import aus server.py)."""
    from src.api.server import get_db
    return await get_db()


# ─── Endpoints ───────────────────────────────────────────────────────


@router.get("/reports/agent")
async def list_agent_reports(request: Request) -> list[dict]:
    """Listet alle Agent-Reports (analyst+)."""
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute(
        "SELECT id, title, report_type, target, created_at "
        "FROM agent_reports ORDER BY created_at DESC LIMIT 50"
    )
    return [
        {"id": r[0], "title": r[1], "report_type": r[2],
         "target": r[3], "created_at": r[4]}
        for r in await cursor.fetchall()
    ]


@router.get("/reports/agent/{report_id}")
async def get_agent_report(report_id: str, request: Request) -> dict:
    """Gibt einen einzelnen Agent-Report zurück."""
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute(
        "SELECT id, title, report_type, content, target, created_at "
        "FROM agent_reports WHERE id = ?", (report_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Report nicht gefunden")
    return {
        "id": row[0], "title": row[1], "report_type": row[2],
        "content": row[3], "target": row[4], "created_at": row[5],
    }


@router.post("/reports/save")
async def save_agent_report_manual(
    request: Request, body: SaveReportRequest,
) -> dict:
    """Speichert eine Agent-Antwort manuell als Report (analyst+)."""
    require_role(request, "analyst")
    from src.agents.report_persistence import (
        _detect_report_type,
        _extract_target,
        _extract_title,
    )

    title = _extract_title(body.content)
    target = _extract_target(title, body.content)
    report_type = _detect_report_type(body.content)
    report_id = str(uuid4())

    db = await _get_db()
    conn = await db.get_connection()
    await conn.execute(
        "INSERT INTO agent_reports "
        "(id, title, report_type, content, target, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (report_id, title, report_type, body.content, target,
         datetime.now(UTC).isoformat()),
    )
    await conn.commit()
    logger.info("Agent-Report manuell gespeichert",
                id=report_id, title=title)
    return {"id": report_id, "title": title, "report_type": report_type}


@router.delete("/reports/agent/{report_id}")
async def delete_agent_report(
    report_id: str, request: Request,
) -> dict:
    """Löscht einen Agent-Report (security_lead+)."""
    require_role(request, "security_lead")

    db = await _get_db()
    conn = await db.get_connection()

    cursor = await conn.execute(
        "SELECT id, title FROM agent_reports WHERE id = ?",
        (report_id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Report nicht gefunden")

    await conn.execute(
        "DELETE FROM agent_reports WHERE id = ?", (report_id,),
    )
    await conn.commit()

    logger.info("Agent-Report gelöscht",
                report_id=report_id, title=row[1])
    return {"status": "deleted", "report_id": report_id}

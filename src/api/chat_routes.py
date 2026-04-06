"""
Chat-Routen fuer die SentinelClaw REST-API.

Agent-Chat — der Agent entscheidet autonom welche Tools er nutzt.
Keine Regex-Erkennung, keine hardcoded Scan-Befehle.
"""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from src.agents.chat_agent import ask_agent
from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["Chat"])


# ─── Request/Response Modelle ──────────────────────────────────────


class ChatRequest(BaseModel):
    message: str = Field(description="Nachricht an den Agent")
    scan_id: str | None = Field(default=None, description="Optionale Scan-ID")


class ChatResponseModel(BaseModel):
    response: str
    scan_started: bool = False
    scan_id: str | None = None


class ChatMessageOut(BaseModel):
    id: str
    role: str
    content: str
    message_type: str
    created_at: str
    scan_id: str | None = None


# ─── DB-Zugriff ──────────────────────────────────────────────────────


async def _get_db():
    from src.api.server import get_db
    return await get_db()


async def _save_message(role: str, content: str, scan_id: str | None = None,
                        message_type: str = "text") -> None:
    """Speichert eine Chat-Nachricht in der DB."""
    db = await _get_db()
    conn = await db.get_connection()
    await conn.execute(
        "INSERT INTO chat_messages (id, scan_id, role, content, message_type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid4()), scan_id, role, content, message_type, datetime.now(UTC).isoformat()),
    )
    await conn.commit()


async def _load_history_for_agent(
    limit: int = 20,
) -> list[dict[str, str]]:
    """Laedt die letzten Chat-Nachrichten als Messages-Liste fuer den Agent.

    Mappt DB-Rollen auf LLM-Rollen: "agent" → "assistant".
    Filtert System-Nachrichten raus (nur user/assistant relevant).
    """
    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute(
        "SELECT role, content FROM chat_messages "
        "WHERE role IN ('user', 'agent') "
        "ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    rows = await cursor.fetchall()

    messages: list[dict[str, str]] = []
    for row in reversed(rows):
        role = "assistant" if row[0] == "agent" else "user"
        content = row[1] or ""
        if content:
            messages.append({"role": role, "content": content})

    return messages


# ─── Chat-Endpoint ──────────────────────────────────────────────────


@router.post("", response_model=ChatResponseModel)
async def send_chat_message(request: Request, body: ChatRequest) -> ChatResponseModel:
    """Chat mit dem Agent (analyst+). Agent entscheidet autonom ueber Tools."""
    require_role(request, "analyst")
    message = body.message.strip()
    scan_id = body.scan_id

    if not message:
        return ChatResponseModel(response="Bitte gib eine Nachricht ein.")

    try:
        await _save_message("user", message, scan_id=scan_id)
    except Exception:
        pass

    # Agent laeuft im Hintergrund — Frontend pollt /chat/history
    asyncio.create_task(_run_agent_background(message, scan_id))

    return ChatResponseModel(
        response="__AGENT_THINKING__",
        scan_started=False,
    )


async def _run_agent_background(message: str, scan_id: str | None) -> None:
    """Fuehrt den Agent im Hintergrund aus und speichert das Ergebnis.

    Laedt die Chat-History aus der DB damit Claude den
    Konversationskontext behaelt.
    """
    try:
        history = await _load_history_for_agent()
    except Exception as error:
        logger.warning("History nicht ladbar, Agent startet ohne Kontext",
                       error=str(error))
        history = None

    try:
        response_text = await ask_agent(message, history=history)
    except Exception as error:
        logger.error("Background-Agent fehlgeschlagen", error=str(error))
        response_text = f"Agent-Fehler: {error}"

    try:
        await _save_message("agent", response_text, scan_id=scan_id)
    except Exception as error:
        logger.error("Agent-Antwort nicht gespeichert", error=str(error))

    # WebSocket-Push an alle verbundenen Clients
    try:
        from src.api.websocket_manager import ws_manager
        await ws_manager.broadcast("agent_response", {
            "content": response_text,
            "scan_id": scan_id,
        })
    except Exception as ws_err:
        logger.debug("WS-Push fehlgeschlagen", error=str(ws_err))


# ─── Chat-History ────────────────────────────────────────────────────


@router.get("/history", response_model=list[ChatMessageOut])
async def get_chat_history(
    request: Request,
    scan_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ChatMessageOut]:
    """Gibt den Chat-Verlauf zurueck (analyst+)."""
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()

    if scan_id:
        cursor = await conn.execute(
            "SELECT * FROM chat_messages WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
            (scan_id, limit),
        )
    else:
        cursor = await conn.execute(
            "SELECT * FROM chat_messages ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

    rows = await cursor.fetchall()
    return [
        ChatMessageOut(
            id=row[0], scan_id=row[1], role=row[2], content=row[3],
            message_type=row[4], created_at=row[5],
        )
        for row in reversed(rows)
    ]


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
        {"id": r[0], "title": r[1], "report_type": r[2], "target": r[3], "created_at": r[4]}
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
        from fastapi import HTTPException
        raise HTTPException(404, "Report nicht gefunden")
    return {
        "id": row[0], "title": row[1], "report_type": row[2],
        "content": row[3], "target": row[4], "created_at": row[5],
    }


@router.delete("/history")
async def clear_chat_history(request: Request) -> dict:
    """Löscht den Chat-Verlauf und die Agent-Sessions (analyst+).

    Wird aufgerufen wenn der User im Chat auf 'Leeren' klickt.
    Löscht auch die OpenClaw-Sessions in der Sandbox damit
    der Agent frisch startet.
    """
    require_role(request, "analyst")
    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute("DELETE FROM chat_messages")
    await conn.commit()
    deleted = cursor.rowcount

    # OpenClaw-Sessions in der Sandbox löschen
    try:
        from src.agents.openshell_executor import run_in_sandbox
        await run_in_sandbox("rm -rf /sandbox/.claude/sessions/*", timeout=5)
        logger.info("Chat + Sessions geleert", messages=deleted)
    except Exception as error:
        logger.warning("Sessions nicht löschbar", error=str(error))

    return {"status": "cleared", "deleted": deleted}

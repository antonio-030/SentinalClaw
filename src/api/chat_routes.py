"""
Chat-Routen fuer die SentinelClaw REST-API.

Agent-Chat — der Agent entscheidet autonom welche Tools er nutzt.
Keine Regex-Erkennung, keine hardcoded Scan-Befehle.
"""

import asyncio
import json
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
    message: str = Field(description="Nachricht an den Agent", min_length=1, max_length=10_000)
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
    metadata: str = "{}"


# ─── DB-Zugriff ──────────────────────────────────────────────────────


async def _get_db():
    from src.api.server import get_db
    return await get_db()


async def _save_message(
    role: str, content: str, scan_id: str | None = None,
    message_type: str = "text", metadata: str = "{}",
) -> None:
    """Speichert eine Chat-Nachricht in der DB (inkl. optionaler Metadata)."""
    db = await _get_db()
    conn = await db.get_connection()
    await conn.execute(
        "INSERT INTO chat_messages "
        "(id, scan_id, role, content, message_type, metadata, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()), scan_id, role, content, message_type,
            metadata, datetime.now(UTC).isoformat(),
        ),
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
    import re


    require_role(request, "analyst")
    message = body.message.strip()
    scan_id = body.scan_id

    # HTML-Tags entfernen — verhindert Stored XSS bei API-Konsumenten
    message = re.sub(r"<[^>]+>", "", message).strip()

    if not message:
        return ChatResponseModel(response="Bitte gib eine Nachricht ein.")

    # Sicherheitsschichten prüfen — Agent darf nur arbeiten wenn alles aktiv ist
    from src.shared.security_layer_check import check_all_security_layers
    layers_ok, layer_errors = await check_all_security_layers()
    if not layers_ok:
        error_msg = (
            "Agent blockiert — nicht alle Sicherheitsschichten aktiv:\n"
            + "\n".join(f"- {e}" for e in layer_errors)
            + "\n\nBitte stelle sicher dass alle Systeme laufen bevor du den Agent nutzt."
        )
        return ChatResponseModel(response=error_msg)

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
    """Führt den Agent im Hintergrund aus und speichert das Ergebnis.

    Lädt die Chat-History aus der DB damit Claude den
    Konversationskontext behält. Tool-Steps werden als Metadata
    an der Agent-Nachricht gespeichert.
    """
    try:
        history = await _load_history_for_agent()
    except Exception as error:
        logger.warning("History nicht ladbar, Agent startet ohne Kontext",
                       error=str(error))
        history = None

    tool_steps: list[dict] = []
    try:
        response_text, tool_steps = await ask_agent(message, history=history)
    except Exception as error:
        logger.error("Background-Agent fehlgeschlagen", error=str(error))
        response_text = f"Agent-Fehler: {error}"

    # Metadata aus Tool-Steps serialisieren
    metadata = json.dumps({"tool_steps": tool_steps}, ensure_ascii=False)

    try:
        await _save_message("agent", response_text, scan_id=scan_id, metadata=metadata)
    except Exception as error:
        logger.error("Agent-Antwort nicht gespeichert", error=str(error))

    # Findings aus Agent-Antwort extrahieren und in DB speichern
    try:
        from src.shared.finding_extractor import persist_chat_findings
        db = await _get_db()
        await persist_chat_findings(response_text, scan_id, db)
    except Exception as extract_err:
        logger.debug("Finding-Extraktion fehlgeschlagen", error=str(extract_err))

    # WebSocket-Push: finale Antwort an alle verbundenen Clients
    try:
        from src.api.websocket_manager import ws_manager
        await ws_manager.broadcast("agent_response", {
            "content": response_text,
            "scan_id": scan_id,
            "tool_steps": tool_steps,
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

    # Explizite Spaltenliste für stabile Zuordnung (metadata seit Migration 8)
    columns = "id, scan_id, role, content, message_type, created_at, metadata"
    if scan_id:
        cursor = await conn.execute(
            f"SELECT {columns} FROM chat_messages "
            "WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
            (scan_id, limit),
        )
    else:
        cursor = await conn.execute(
            f"SELECT {columns} FROM chat_messages "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

    rows = await cursor.fetchall()
    return [
        ChatMessageOut(
            id=row[0], scan_id=row[1], role=row[2], content=row[3],
            message_type=row[4], created_at=row[5],
            # Metadata-Spalte existiert erst nach Migration 8
            metadata=row[6] if len(row) > 6 and row[6] else "{}",
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


class SaveReportRequest(BaseModel):
    """Manuelles Speichern einer Agent-Antwort als Report."""

    content: str = Field(description="Agent-Antwort als Markdown")


@router.post("/reports/save")
async def save_agent_report_manual(request: Request, body: SaveReportRequest) -> dict:
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
        "INSERT INTO agent_reports (id, title, report_type, content, target, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (report_id, title, report_type, body.content, target,
         datetime.now(UTC).isoformat()),
    )
    await conn.commit()
    logger.info("Agent-Report manuell gespeichert", id=report_id, title=title)
    return {"id": report_id, "title": title, "report_type": report_type}


@router.delete("/reports/agent/{report_id}")
async def delete_agent_report(report_id: str, request: Request) -> dict:
    """Löscht einen Agent-Report (security_lead+)."""
    require_role(request, "security_lead")

    db = await _get_db()
    conn = await db.get_connection()

    cursor = await conn.execute(
        "SELECT id, title FROM agent_reports WHERE id = ?", (report_id,)
    )
    row = await cursor.fetchone()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, "Report nicht gefunden")

    await conn.execute("DELETE FROM agent_reports WHERE id = ?", (report_id,))
    await conn.commit()

    logger.info("Agent-Report gelöscht", report_id=report_id, title=row[1])
    return {"status": "deleted", "report_id": report_id}


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

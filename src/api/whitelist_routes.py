"""
Whitelist-Routen — autorisierte Scan-Ziele verwalten.

Bei Änderung wird die CLAUDE.md in der Sandbox aktualisiert.
"""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/whitelist", tags=["Whitelist"])


# ─── Request/Response Modelle ────────────────────────────────────────


class AuthorizeTargetRequest(BaseModel):
    """Anfrage zum Autorisieren eines Scan-Ziels."""

    target: str = Field(description="Domain, IP oder CIDR")
    confirmation: str = Field(
        default="owner",
        description="Art der Bestätigung: owner, pentest_mandate, internal",
    )
    notes: str = Field(default="", description="Optionale Notizen")


class AuthorizedTargetOut(BaseModel):
    """Autorisiertes Scan-Ziel."""

    id: str
    target: str
    confirmed_by: str
    confirmation: str
    notes: str
    created_at: str


# ─── DB-Zugriff ─────────────────────────────────────────────────────


async def _get_db():
    from src.api.server import get_db
    return await get_db()


async def _get_all_targets() -> list[dict]:
    """Lädt alle autorisierten Ziele aus der DB."""
    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute(
        "SELECT id, target, confirmed_by, confirmation, notes, created_at "
        "FROM authorized_targets ORDER BY created_at DESC",
    )
    rows = await cursor.fetchall()
    return [
        {"id": r[0], "target": r[1], "confirmed_by": r[2],
         "confirmation": r[3], "notes": r[4], "created_at": r[5]}
        for r in rows
    ]


async def _sync_sandbox_agent_config() -> None:
    """Aktualisiert die Agent-Konfiguration (AGENT.md) in der Sandbox."""
    from src.agents.openshell_executor import run_in_sandbox
    from src.shared.constants.agent_tools import AGENT_TOOL_REGISTRY, PREINSTALLED_TOOLS

    targets = await _get_all_targets()
    target_lines = "\n".join(f"- **{t['target']}** ({t['confirmation']})"
                             for t in targets) or "Keine Ziele autorisiert."

    tool_lines = "\n".join(f"- **{n}** (vorinstalliert)" for n in sorted(PREINSTALLED_TOOLS))
    tool_lines += "\n" + "\n".join(
        f"- **{t.name}** — {t.description}" for t in AGENT_TOOL_REGISTRY.values()
    )

    claude_md = f"""# SentinelClaw — Security-Analyse-Plattform

Du arbeitest als Security-Assistent in der SentinelClaw-Plattform.

## Autorisierte Scan-Ziele

Die folgenden Ziele wurden vom User autorisiert. Du darfst
ALLE verfügbaren Tools (einschließlich sqlmap, nmap, etc.)
gegen diese Ziele einsetzen — ohne Rückfrage:

{target_lines}

Nicht autorisierte Ziele: Nur passive Reconnaissance (dig, whois, curl).
Für aktive Scans sage: "Bitte autorisiere das Ziel unter Whitelist."

## Verfügbare Security-Tools

{tool_lines}

Wenn ein Tool fehlt: "Bitte installiere es unter Einstellungen > Agent Tools."

## Arbeitsweise

1. Ziel genannt → Scan-Plan erstellen → ausführen
2. Ergebnisse auf Deutsch mit Markdown berichten
3. Erwähne NICHT deine internen Tools (Read, Write, Edit, etc.)
4. Maximal 10 Tool-Aufrufe pro Nachricht
"""
    escaped = claude_md.replace("'", "'\\''")
    try:
        await run_in_sandbox(f"cat > /sandbox/AGENT.md << 'ENDOFFILE'\n{escaped}\nENDOFFILE", timeout=10)
        logger.info("Sandbox CLAUDE.md aktualisiert", targets=len(targets))
    except Exception as error:
        logger.warning("CLAUDE.md Sync fehlgeschlagen", error=str(error))

    # Netzwerk-Policy aktualisieren (Scan-Ziele freischalten)
    from src.agents.sandbox_policy import update_policy_with_targets
    target_names = [t["target"] for t in targets]
    try:
        await update_policy_with_targets(target_names)
    except Exception as error:
        logger.warning("Policy-Sync fehlgeschlagen", error=str(error))


# ─── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=list[AuthorizedTargetOut])
async def list_targets(request: Request) -> list[AuthorizedTargetOut]:
    """Gibt alle autorisierten Ziele zurück (analyst+)."""
    require_role(request, "analyst")
    targets = await _get_all_targets()
    return [AuthorizedTargetOut(**t) for t in targets]


@router.post("", response_model=AuthorizedTargetOut)
async def authorize_target(
    request: Request, body: AuthorizeTargetRequest,
) -> AuthorizedTargetOut:
    """Autorisiert ein Scan-Ziel (security_lead+).

    Der User bestätigt damit, dass er berechtigt ist
    dieses Ziel aktiv zu scannen.
    """
    require_role(request, "security_lead")

    from src.shared.auth import extract_user_from_request
    user = extract_user_from_request(request)

    target = body.target.strip().lower()
    if not target:
        raise HTTPException(400, "Ziel darf nicht leer sein")

    db = await _get_db()
    conn = await db.get_connection()

    # Duplikat prüfen
    existing = await conn.execute(
        "SELECT id FROM authorized_targets WHERE target = ?", (target,),
    )
    if await existing.fetchone():
        raise HTTPException(409, f"Ziel '{target}' ist bereits autorisiert")

    entry_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "INSERT INTO authorized_targets (id, target, confirmed_by, confirmation, notes, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entry_id, target, user["email"], body.confirmation, body.notes, now),
    )
    await conn.commit()

    logger.info("Ziel autorisiert", target=target, by=user["email"])

    # Sandbox-CLAUDE.md asynchron aktualisieren
    asyncio.create_task(_sync_sandbox_agent_config())

    return AuthorizedTargetOut(
        id=entry_id, target=target, confirmed_by=user["email"],
        confirmation=body.confirmation, notes=body.notes, created_at=now,
    )


@router.delete("/{target_id}")
async def revoke_target(request: Request, target_id: str) -> dict:
    """Widerruft die Autorisierung eines Scan-Ziels (security_lead+)."""
    require_role(request, "security_lead")

    db = await _get_db()
    conn = await db.get_connection()
    cursor = await conn.execute(
        "DELETE FROM authorized_targets WHERE id = ?", (target_id,),
    )
    await conn.commit()

    if cursor.rowcount == 0:
        raise HTTPException(404, "Ziel nicht gefunden")

    logger.info("Ziel-Autorisierung widerrufen", id=target_id)
    asyncio.create_task(_sync_sandbox_agent_config())

    return {"status": "revoked"}


@router.get("/policy")
async def get_policy_status(request: Request) -> dict:
    """Gibt den aktuellen OpenShell-Policy-Status zurück (analyst+)."""
    require_role(request, "analyst")
    from src.agents.sandbox_policy import get_policy_status
    return await get_policy_status()

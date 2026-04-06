"""
Agent-Tool-Management-Routen fuer die SentinelClaw REST-API.

Ermoeglicht Installation und Deinstallation von Security-Tools
in der OpenShell-Sandbox ueber die Web-UI.

Endpoints unter /api/v1/agent/tools:
  - GET  /              -> Alle Tools + Status
  - POST /{name}/install -> Tool installieren (security_lead+)
  - DELETE /{name}       -> Tool deinstallieren (security_lead+)
"""

import re
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.agents.openshell_executor import check_tool, install_tool, uninstall_tool
from src.shared.auth import require_role
from src.shared.constants.agent_tools import (
    AGENT_TOOL_REGISTRY,
    PREINSTALLED_TOOLS,
    AgentToolDefinition,
)
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/agent/tools", tags=["Agent Tools"])

# Validierung: Nur alphanumerische Tool-Namen
_TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")


# ─── Response-Modelle ────────────────────────────────────────────────


class AgentToolOut(BaseModel):
    """Status eines Agent-Tools."""

    name: str
    display_name: str
    description: str
    category: str
    installed: bool
    check_output: str = ""
    preinstalled: bool = False


class AgentToolActionResponse(BaseModel):
    """Antwort nach Install/Uninstall."""

    status: str
    tool_name: str
    output: str = ""
    duration_seconds: float = 0.0


# ─── Hilfsfunktionen ────────────────────────────────────────────────


def _validate_tool_name(name: str) -> AgentToolDefinition:
    """Validiert den Tool-Namen gegen die Registry."""
    if not _TOOL_NAME_PATTERN.match(name):
        raise HTTPException(400, "Ungueltiger Tool-Name")
    tool = AGENT_TOOL_REGISTRY.get(name)
    if not tool:
        raise HTTPException(404, f"Tool '{name}' nicht in der Registry")
    return tool


# ─── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=list[AgentToolOut])
async def list_agent_tools(request: Request) -> list[AgentToolOut]:
    """Gibt alle registrierten Tools mit aktuellem Status zurueck (analyst+)."""
    require_role(request, "analyst")
    results: list[AgentToolOut] = []

    # Vorinstallierte Tools (immer verfuegbar)
    for name in sorted(PREINSTALLED_TOOLS):
        results.append(AgentToolOut(
            name=name, display_name=name, description="Vorinstalliert",
            category="utility", installed=True, preinstalled=True,
        ))

    # Installierbare Tools — Status via SSH pruefen
    for tool in AGENT_TOOL_REGISTRY.values():
        installed, check_output = await check_tool(tool)
        results.append(AgentToolOut(
            name=tool.name,
            display_name=tool.display_name,
            description=tool.description,
            category=tool.category,
            installed=installed,
            check_output=check_output,
        ))

    return results


@router.post("/{name}/install", response_model=AgentToolActionResponse)
async def install_agent_tool(request: Request, name: str) -> AgentToolActionResponse:
    """Installiert ein Tool in der OpenShell-Sandbox (security_lead+)."""
    require_role(request, "security_lead")
    tool = _validate_tool_name(name)

    # Pruefen ob schon installiert
    installed, _ = await check_tool(tool)
    if installed:
        return AgentToolActionResponse(
            status="already_installed", tool_name=name,
        )

    start = time.monotonic()
    try:
        output = await install_tool(tool)
    except RuntimeError as error:
        logger.error("Tool-Installation fehlgeschlagen", tool=name, error=str(error))
        raise HTTPException(500, f"Installation fehlgeschlagen: {error}")

    duration = time.monotonic() - start
    logger.info("Tool ueber API installiert", tool=name, duration=f"{duration:.1f}s")
    return AgentToolActionResponse(
        status="installed", tool_name=name,
        output=output[:500], duration_seconds=round(duration, 1),
    )


@router.delete("/{name}", response_model=AgentToolActionResponse)
async def uninstall_agent_tool(request: Request, name: str) -> AgentToolActionResponse:
    """Deinstalliert ein Tool aus der OpenShell-Sandbox (security_lead+)."""
    require_role(request, "security_lead")
    tool = _validate_tool_name(name)

    start = time.monotonic()
    try:
        output = await uninstall_tool(tool)
    except RuntimeError as error:
        logger.error("Tool-Deinstallation fehlgeschlagen", tool=name, error=str(error))
        raise HTTPException(500, f"Deinstallation fehlgeschlagen: {error}")

    duration = time.monotonic() - start
    logger.info("Tool ueber API deinstalliert", tool=name, duration=f"{duration:.1f}s")
    return AgentToolActionResponse(
        status="uninstalled", tool_name=name,
        output=output[:500], duration_seconds=round(duration, 1),
    )

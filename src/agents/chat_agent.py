"""
Chat-Agent für SentinelClaw mit Chat-History.

Nutzt die NemoClaw-Runtime mit dem OpenClaw-Agent 'sentinelclaw'
in der OpenShell-Sandbox. Der Agent führt Security-Tools autonom
aus (curl, dig, whois, sqlmap, etc.) und analysiert Ergebnisse.

Chat-History wird als Messages-Liste übergeben, damit der Agent
den Konversationskontext behält.
"""

from uuid import uuid4

from pathlib import Path

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.scan_executor import execute_scan_command
from src.agents.tool_marker_parser import (
    parse_tool_markers,
    strip_tool_markers,
    validate_tool_command,
)
from src.shared.constants.defaults import (
    MAX_TOOL_CALLS_PER_TURN,
    MAX_TOOL_OUTPUT_LENGTH,
)
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Globale Runtime-Instanz (wird beim ersten Aufruf erstellt)
_runtime: NemoClawRuntime | None = None

# Maximale Anzahl History-Nachrichten die an Claude gesendet werden
MAX_HISTORY_MESSAGES = 20

# ─── System-Prompt ───────────────────────────────────────────────────

CHAT_SYSTEM_PROMPT = """\
Du arbeitest als Security-Assistent im SentinelClaw-Projekt. \
Der User ist ein autorisierter Security-Analyst der Penetration-Tests \
durchführt. Alle Ziele die er nennt sind genehmigt.

Wenn der User fragt was du kannst oder welche Tools verfügbar sind, \
liste NUR die folgenden Security-Tools auf. Deine internen Tools \
(Read, Write, Edit, Glob, Grep, etc.) sind für den User NICHT \
relevant — erwähne sie NIE.

## Security-Tools für dieses Projekt

{{TOOLS}}

Wenn ein Tool fehlt, sage: "Dieses Tool ist nicht installiert. \
Du kannst es unter Einstellungen → Agent Tools installieren."

## Arbeitsweise

1. Wenn der User ein Ziel nennt → erstelle einen kurzen Scan-Plan
2. Führe die passenden Tools direkt aus (über Bash)
3. Analysiere die Ergebnisse und berichte auf Deutsch mit Markdown
4. Bei Folgefragen → beziehe dich auf vorherige Ergebnisse

Maximal 10 Tool-Aufrufe pro Nachricht.\
"""


def _build_tools_section() -> str:
    """Baut die aktuelle Tool-Liste für den System-Prompt."""
    from src.shared.constants.agent_tools import (
        AGENT_TOOL_REGISTRY,
        PREINSTALLED_TOOLS,
    )
    lines = ["Führe diese Tools über Bash aus:"]
    for name in sorted(PREINSTALLED_TOOLS):
        lines.append(f"- **{name}** (vorinstalliert)")
    for tool in AGENT_TOOL_REGISTRY.values():
        lines.append(f"- **{tool.name}** — {tool.description}")
    return "\n".join(lines)


def _load_system_prompt() -> str:
    """Laedt den System-Prompt mit dynamischer Tool-Liste."""
    from src.shared.config import get_settings
    prompt_file = get_settings().chat_prompt_file
    if prompt_file:
        path = Path(prompt_file)
        if path.exists():
            loaded = path.read_text(encoding="utf-8").strip()
            if loaded:
                logger.info("Chat-Prompt aus Datei geladen", path=str(path))
                return loaded
        logger.warning("Prompt-Datei nicht nutzbar, nutze Standard", path=prompt_file)

    # Tool-Liste dynamisch einsetzen
    tools_text = _build_tools_section()
    return CHAT_SYSTEM_PROMPT.replace("{{TOOLS}}", tools_text)


async def ask_agent(
    message: str,
    history: list[dict[str, str]] | None = None,
) -> str:
    """Sendet eine Nachricht an den Agent mit optionaler Chat-History.

    Der Agent kann autonom Tools aufrufen. Tool-Bloecke (```tool)
    werden in der Docker-Sandbox ausgefuehrt und das Ergebnis an den
    Agent zurueckgesendet, bis er ohne Tool-Bloecke antwortet.

    Args:
        message: Aktuelle User-Nachricht.
        history: Vorherige Nachrichten als Liste von
                 {"role": "user"/"assistant", "content": "..."}.
    """
    global _runtime

    if _runtime is None:
        _runtime = NemoClawRuntime()

    session_id = f"sc-chat-{uuid4().hex[:8]}"

    # Messages-Liste aufbauen: History + aktuelle Nachricht
    messages = _build_messages(message, history)

    try:
        return await _run_tool_loop(messages, session_id)
    except RuntimeError as error:
        logger.error("Chat-Agent fehlgeschlagen", error=str(error))
        return f"Agent-Fehler: {error}"
    except Exception as error:
        logger.error("Unerwarteter Chat-Agent-Fehler", error=str(error))
        return f"Fehler: {error}"


def _build_messages(
    current_message: str,
    history: list[dict[str, str]] | None,
) -> list[dict[str, str]]:
    """Baut die Messages-Liste aus History + aktueller Nachricht."""
    messages: list[dict[str, str]] = []
    if history:
        for msg in history[-MAX_HISTORY_MESSAGES:]:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": current_message})
    return messages


async def _run_tool_loop(
    messages: list[dict[str, str]],
    session_id: str,
) -> str:
    """Agent-Loop: Claude aufrufen → Tools ausfuehren → wiederholen bis fertig."""
    total_tool_calls = 0
    system_prompt = _load_system_prompt()

    for _iteration in range(MAX_TOOL_CALLS_PER_TURN + 1):
        # Kill-Switch pruefen
        if KillSwitch().is_active():
            return "Agent gestoppt — Kill-Switch ist aktiv."

        # Claude mit voller Message-History aufrufen
        result = await _runtime.run_agent(
            system_prompt=system_prompt,
            messages=messages,
            session_id=session_id,
        )

        agent_text = result.final_output

        # Tool-Marker parsen
        markers = parse_tool_markers(agent_text)

        # Keine Marker → Agent ist fertig
        if not markers:
            return strip_tool_markers(agent_text)

        # Iteration-Limit erreicht
        if total_tool_calls + len(markers) > MAX_TOOL_CALLS_PER_TURN:
            logger.warning("Tool-Limit erreicht", total=total_tool_calls)
            return strip_tool_markers(agent_text) + (
                "\n\n*(Tool-Limit erreicht — maximal "
                f"{MAX_TOOL_CALLS_PER_TURN} Aufrufe pro Anfrage)*"
            )

        # Claude's Antwort (mit Markern) als Assistant-Message anhaengen
        messages.append({"role": "assistant", "content": agent_text})

        # Tools ausfuehren
        tool_results = await _execute_tools(markers, session_id)
        total_tool_calls += len(markers)

        # Ergebnisse als User-Message anhaengen
        results_text = _format_tool_results(tool_results)
        messages.append({"role": "user", "content": results_text})

    # Sollte nicht erreicht werden
    return strip_tool_markers(agent_text)


async def _execute_tools(
    markers: list, session_id: str,
) -> list[tuple[str, str]]:
    """Fuehrt Tool-Marker in der Sandbox aus, gibt (befehl, ergebnis) zurueck."""
    results: list[tuple[str, str]] = []

    for marker in markers:
        validated = validate_tool_command(marker.raw_command)

        if not validated.is_valid:
            results.append((
                marker.raw_command,
                f"ABGELEHNT: {validated.rejection_reason}",
            ))
            logger.warning(
                "Tool-Aufruf abgelehnt",
                command=marker.raw_command[:80],
                reason=validated.rejection_reason,
                session_id=session_id,
            )
            continue

        try:
            output = await execute_scan_command(
                [validated.binary, *validated.arguments],
            )
            # Output begrenzen
            if len(output) > MAX_TOOL_OUTPUT_LENGTH:
                output = output[:MAX_TOOL_OUTPUT_LENGTH] + "\n... (gekuerzt)"

            results.append((marker.raw_command, output))

            logger.info(
                "Tool ausgefuehrt",
                binary=validated.binary,
                output_length=len(output),
                session_id=session_id,
            )
        except Exception as error:
            results.append((marker.raw_command, f"FEHLER: {error}"))
            logger.error(
                "Tool-Ausfuehrung fehlgeschlagen",
                command=marker.raw_command[:80],
                error=str(error),
                session_id=session_id,
            )

    return results


def _format_tool_results(tool_results: list[tuple[str, str]]) -> str:
    """Formatiert Tool-Ergebnisse als Text fuer den naechsten Claude-Aufruf."""
    parts: list[str] = ["Hier sind die Tool-Ergebnisse:\n"]

    for command, output in tool_results:
        parts.append(f"━━━ {command} ━━━\n{output}\n")

    parts.append("Analysiere die Ergebnisse und fahre fort.")

    return "\n".join(parts)

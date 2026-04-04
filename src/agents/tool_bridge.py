"""
Tool-Bridge — Verbindung zwischen Agent und MCP-Server Tools.

Implementiert das ToolExecutor-Protocol aus agent_runtime.py und
uebersetzt ToolCallRequest-Objekte in echte Tool-Aufrufe. Jeder
Aufruf wird mit Scope und Executor abgesichert.
"""

import json
import traceback
from collections.abc import Callable, Coroutine
from dataclasses import asdict
from typing import Any

from src.mcp_server.tools.exec_command import run_exec_command
from src.mcp_server.tools.parse_output import parse_output
from src.mcp_server.tools.port_scan import run_port_scan
from src.mcp_server.tools.vuln_scan import run_vuln_scan
from src.sandbox.executor import SandboxExecutor
from src.shared.logging_setup import get_logger
from src.shared.scope_validator import ScopeValidator
from src.shared.types.agent_runtime import (
    ToolCallRequest,
    ToolCallResult,
    ToolDefinition,
)
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)

# JSON-Schema Parameterdefinitionen fuer die vier MCP-Tools
_PORT_SCAN_PARAMS: dict[str, Any] = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string", "description": "Ziel-IP oder Domain"},
        "ports": {"type": "string", "description": "Port-Range, z.B. '1-1000'", "default": "1-1000"},
        "flags": {
            "type": "array", "items": {"type": "string"},
            "description": "nmap-Flags, z.B. ['-sV']", "default": ["-sV"],
        },
    },
}

_VULN_SCAN_PARAMS: dict[str, Any] = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string", "description": "Ziel-URL oder IP"},
        "templates": {
            "type": "array", "items": {"type": "string"},
            "description": "nuclei-Templates", "default": ["cves", "vulnerabilities"],
        },
    },
}

_EXEC_COMMAND_PARAMS: dict[str, Any] = {
    "type": "object",
    "required": ["command_parts"],
    "properties": {
        "command_parts": {
            "type": "array", "items": {"type": "string"},
            "description": "Befehl als Liste, z.B. ['nmap', '-sV', '10.10.10.5']",
        },
        "timeout": {"type": "integer", "description": "Timeout in Sekunden", "default": 60},
    },
}

_PARSE_OUTPUT_PARAMS: dict[str, Any] = {
    "type": "object",
    "required": ["raw_output"],
    "properties": {
        "raw_output": {"type": "string", "description": "Rohdaten die geparsed werden sollen"},
        "output_format": {
            "type": "string", "enum": ["nmap_xml", "nuclei_jsonl", "plaintext"],
            "description": "Format der Rohdaten", "default": "nmap_xml",
        },
    },
}

# Tool-Definitionen die dem Agent bereitgestellt werden
TOOL_DEFINITIONS: list[ToolDefinition] = [
    ToolDefinition(
        name="port_scan",
        description="nmap Port-Scan mit strukturiertem Ergebnis",
        parameters=_PORT_SCAN_PARAMS,
    ),
    ToolDefinition(
        name="vuln_scan",
        description="nuclei Vulnerability-Scan mit strukturierten Findings",
        parameters=_VULN_SCAN_PARAMS,
    ),
    ToolDefinition(
        name="exec_command",
        description="Befehl in der Sandbox ausfuehren (nur Allowlist-Binaries)",
        parameters=_EXEC_COMMAND_PARAMS,
    ),
    ToolDefinition(
        name="parse_output",
        description="Scan-Rohdaten (nmap-XML, nuclei-JSONL, Plaintext) strukturiert parsen",
        parameters=_PARSE_OUTPUT_PARAMS,
    ),
]


def _serialize_result(result: Any) -> str:
    """Wandelt ein Tool-Ergebnis in einen JSON-String um."""
    try:
        if hasattr(result, "__dataclass_fields__"):
            return json.dumps(asdict(result), ensure_ascii=False, default=str)
        if isinstance(result, dict):
            return json.dumps(result, ensure_ascii=False, default=str)
        return str(result)
    except (TypeError, ValueError) as error:
        logger.warning("Serialisierung fehlgeschlagen, Fallback auf str()", error=str(error))
        return str(result)


class McpToolBridge:
    """Bruecke zwischen Agent-Runtime und MCP-Server Tools.

    Empfaengt ToolCallRequest-Objekte vom Agent, routet sie an das
    passende Tool, injiziert Scope und Executor, und gibt ein
    ToolCallResult zurueck.
    """

    def __init__(
        self,
        scope: PentestScope,
        scope_validator: ScopeValidator,
        executor: SandboxExecutor,
    ) -> None:
        """Initialisiert die ToolBridge mit Scope und Sandbox.

        Args:
            scope: Geltungsbereich des Pentests.
            scope_validator: Validator fuer Scope-Checks bei jedem Aufruf.
            executor: SandboxExecutor fuer sichere Befehlsausfuehrung.
        """
        self._scope = scope
        self._scope_validator = scope_validator
        self._executor = executor

    async def execute_tool(self, request: ToolCallRequest) -> ToolCallResult:
        """Fuehrt ein Tool aus und gibt das Ergebnis zurueck.

        Args:
            request: Tool-Aufruf mit Name, Argumenten und Call-ID.

        Returns:
            Ergebnis der Tool-Ausfuehrung als ToolCallResult.
        """
        logger.info(
            "Tool-Aufruf empfangen",
            tool=request.tool_name,
            call_id=request.call_id,
            arg_keys=list(request.arguments.keys()),
        )

        # Dispatch-Tabelle fuer die Tool-Handler
        handlers: dict[str, Callable[..., Coroutine[Any, Any, str]]] = {
            "port_scan": self._handle_port_scan,
            "vuln_scan": self._handle_vuln_scan,
            "exec_command": self._handle_exec_command,
            "parse_output": self._handle_parse_output,
        }

        handler = handlers.get(request.tool_name)
        if handler is None:
            available = ", ".join(sorted(handlers.keys()))
            return ToolCallResult(
                call_id=request.call_id,
                output=f"Unbekanntes Tool: '{request.tool_name}'. Verfuegbar: {available}",
                is_error=True,
            )

        try:
            output = await handler(request.arguments)
            logger.info(
                "Tool-Aufruf erfolgreich",
                tool=request.tool_name,
                call_id=request.call_id,
                output_length=len(output),
            )
            return ToolCallResult(call_id=request.call_id, output=output, is_error=False)

        except PermissionError as error:
            # Scope-Verletzung — klar kommunizieren
            logger.warning(
                "Scope-Verletzung bei Tool-Aufruf",
                tool=request.tool_name, call_id=request.call_id, error=str(error),
            )
            return ToolCallResult(
                call_id=request.call_id, output=f"Scope-Verletzung: {error}", is_error=True,
            )

        except ValueError as error:
            # Eingabevalidierung fehlgeschlagen
            logger.warning(
                "Validierungsfehler bei Tool-Aufruf",
                tool=request.tool_name, call_id=request.call_id, error=str(error),
            )
            return ToolCallResult(
                call_id=request.call_id, output=f"Validierungsfehler: {error}", is_error=True,
            )

        except Exception as error:
            # Unerwarteter Fehler — Stacktrace loggen, nur Nachricht zurueckgeben
            logger.error(
                "Unerwarteter Fehler bei Tool-Aufruf",
                tool=request.tool_name, call_id=request.call_id,
                error=str(error), traceback=traceback.format_exc(),
            )
            return ToolCallResult(
                call_id=request.call_id,
                output=f"Fehler bei '{request.tool_name}': {error}",
                is_error=True,
            )

    def get_available_tools(self) -> list[ToolDefinition]:
        """Gibt die Liste aller verfuegbaren Tools zurueck."""
        return list(TOOL_DEFINITIONS)

    # -- Handler fuer die einzelnen Tools --

    async def _handle_port_scan(self, arguments: dict[str, Any]) -> str:
        """Delegiert an run_port_scan mit Scope und Executor."""
        result = await run_port_scan(
            target=arguments["target"],
            ports=arguments.get("ports", "1-1000"),
            flags=arguments.get("flags"),
            scope=self._scope,
            executor=self._executor,
            scope_validator=self._scope_validator,
        )
        return _serialize_result(result)

    async def _handle_vuln_scan(self, arguments: dict[str, Any]) -> str:
        """Delegiert an run_vuln_scan mit Scope und Executor."""
        result = await run_vuln_scan(
            target=arguments["target"],
            templates=arguments.get("templates"),
            scope=self._scope,
            executor=self._executor,
            scope_validator=self._scope_validator,
        )
        return _serialize_result(result)

    async def _handle_exec_command(self, arguments: dict[str, Any]) -> str:
        """Delegiert an run_exec_command mit Scope und Executor."""
        result = await run_exec_command(
            command_parts=arguments["command_parts"],
            timeout=arguments.get("timeout", 60),
            scope=self._scope,
            executor=self._executor,
            scope_validator=self._scope_validator,
        )
        return _serialize_result(result)

    async def _handle_parse_output(self, arguments: dict[str, Any]) -> str:
        """Delegiert an parse_output (synchron, keine Sandbox noetig)."""
        result = parse_output(
            raw_output=arguments["raw_output"],
            output_format=arguments.get("output_format", "nmap_xml"),
        )
        return _serialize_result(result)

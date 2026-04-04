"""
Audit-Logger für MCP-Tool-Aufrufe.

Loggt jeden Tool-Aufruf mit Zeitstempel, Parametern und Ergebnis.
Sensible Daten (Credentials, PII) werden automatisch maskiert.
"""

import re
from typing import Any

from src.shared.constants.defaults import SECRET_PATTERNS
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AgentLogRepository, AuditLogRepository
from src.shared.types.models import AgentLogEntry, AuditLogEntry

logger = get_logger(__name__)

# Kompilierte Regex-Pattern für Secret-Erkennung
_SECRET_REGEXES = [re.compile(p, re.IGNORECASE) for p in SECRET_PATTERNS]


def _mask_secrets_in_str(text: str) -> str:
    """Maskiert Secrets in einem String."""
    result = text
    for regex in _SECRET_REGEXES:
        result = regex.sub("[REDACTED]", result)
    return result


def _mask_secrets_in_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Maskiert Secrets in allen String-Werten eines Dicts."""
    masked = {}
    for key, value in data.items():
        if isinstance(value, str):
            masked[key] = _mask_secrets_in_str(value)
        elif isinstance(value, dict):
            masked[key] = _mask_secrets_in_dict(value)
        else:
            masked[key] = value
    return masked


class ToolAuditLogger:
    """Loggt MCP-Tool-Aufrufe in die Datenbank.

    Jeder Tool-Aufruf erzeugt:
    1. Einen Eintrag in audit_logs (unveränderbar)
    2. Einen Eintrag in agent_logs (für Scan-Zuordnung)
    """

    def __init__(self, db: DatabaseManager) -> None:
        self._audit_repo = AuditLogRepository(db)
        self._agent_repo = AgentLogRepository(db)

    async def log_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        result_summary: str,
        duration_ms: int,
        scan_job_id: str | None = None,
        scope_check_passed: bool = True,
    ) -> None:
        """Loggt einen Tool-Aufruf in beide Log-Tabellen."""
        # Sensible Daten maskieren BEVOR sie gespeichert werden
        masked_params = _mask_secrets_in_dict(parameters)
        masked_summary = _mask_secrets_in_str(result_summary[:1000])

        # Audit-Log (unveränderbar)
        await self._audit_repo.create(AuditLogEntry(
            action=f"tool.{tool_name}",
            resource_type="mcp_tool",
            resource_id=tool_name,
            details={
                "parameters": masked_params,
                "result_summary": masked_summary,
                "duration_ms": duration_ms,
                "scope_check_passed": scope_check_passed,
            },
            triggered_by="agent",
        ))

        # Agent-Log (für Scan-Zuordnung, wenn Scan-ID vorhanden)
        if scan_job_id:
            from uuid import UUID
            await self._agent_repo.create(AgentLogEntry(
                scan_job_id=UUID(scan_job_id),
                agent_name="mcp-server",
                step_description=f"Tool {tool_name} ausgeführt",
                tool_name=tool_name,
                input_params=masked_params,
                output_summary=masked_summary,
                duration_ms=duration_ms,
            ))

        logger.info(
            "Tool-Aufruf geloggt",
            tool=tool_name,
            duration_ms=duration_ms,
            scope_passed=scope_check_passed,
        )

    async def log_scope_violation(
        self,
        tool_name: str,
        target: str,
        reason: str,
    ) -> None:
        """Loggt eine Scope-Verletzung als Sicherheits-Event."""
        await self._audit_repo.create(AuditLogEntry(
            action="security.scope_violation",
            resource_type="mcp_tool",
            resource_id=tool_name,
            details={
                "target": target,
                "reason": reason,
                "tool": tool_name,
            },
            triggered_by="agent",
        ))

        logger.warning(
            "Scope-Verletzung geloggt",
            tool=tool_name,
            target=target,
            reason=reason,
        )

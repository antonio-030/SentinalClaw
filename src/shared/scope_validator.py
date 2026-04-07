"""
Scope-Validator — Sicherheitskern von SentinelClaw.

Validiert JEDEN Tool-Aufruf gegen den definierten Scope.
Wird im MCP-Server aufgerufen — der Agent hat keinen Bypass.
Alle 8 Checks müssen bestanden werden, sonst wird blockiert.

Einzelne Check-Funktionen sind in scope_checks.py ausgelagert.
"""

from src.shared.logging_setup import get_logger
from src.shared.scope_checks import (
    check_escalation_level,
    check_forbidden_actions,
    check_port_in_scope,
    check_target_in_scope,
    check_target_not_excluded,
    check_target_not_forbidden,
    check_time_window,
    check_tool_allowed,
)
from src.shared.types.scope import PentestScope, ValidationResult

logger = get_logger(__name__)

# Tool → Eskalationsstufe Zuordnung (Default, konfigurierbar über UI)
DEFAULT_TOOL_ESCALATION_MAP: dict[str, int] = {
    # Stufe 0: Passiv — OSINT, DNS, Whois (kein Zielkontakt)
    "whois": 0, "dig": 0, "host": 0, "curl": 0, "jq": 0,
    "shodan": 0, "censys": 0, "theharvester": 0, "sublist3r": 0,
    "holehe": 0, "python-whois": 0, "dnspython": 0,
    # Stufe 1: Aktive Scans — Direkter Kontakt mit Ziel
    "nmap": 1, "whatweb": 1, "dirsearch": 1, "dirb": 1,
    "wafw00f": 1, "sslyze": 1, "sslscan": 1, "arjun": 1,
    "netcat": 1, "nc": 1, "socat": 1, "httpie": 1, "paramiko": 1,
    # Stufe 2: Vulnerability — Schwachstellen-Erkennung + PoC
    "nuclei": 2, "nikto": 2, "wapiti": 2, "python-nmap": 2,
    "sqlmap_detect": 2, "pyjwt": 2, "tlsx": 2,
    # Stufe 3: Exploitation — Aktives Ausnutzen von Schwachstellen
    "sqlmap": 3, "sqlmap_exploit": 3, "hydra": 3, "john": 3,
    "hashcat": 3, "msfconsole": 3, "msfvenom": 3, "metasploit": 3,
    "impacket": 3, "crackmapexec": 3, "pwncat-cs": 3,
    # Stufe 4: Post-Exploitation — Privilege Escalation, Pivoting
    "linpeas": 4, "winpeas": 4, "chisel": 4, "mimikatz": 4,
}


class ScopeValidator:
    """Validiert Tool-Aufrufe gegen den definierten Scope.

    Führt 8 unabhängige Checks durch. Wenn EINER fehlschlägt,
    wird der gesamte Aufruf blockiert. Es gibt kein "teilweise erlaubt".
    """

    def __init__(
        self,
        tool_escalation_map: dict[str, int] | None = None,
    ) -> None:
        self._tool_map = tool_escalation_map or DEFAULT_TOOL_ESCALATION_MAP

    def validate(
        self,
        target: str,
        port: int | None,
        tool_name: str,
        scope: PentestScope,
        arguments: str = "",
    ) -> ValidationResult:
        """Führt alle 8 Scope-Checks durch.

        Gibt BLOCK zurück wenn auch nur EINE Prüfung fehlschlägt.
        """
        # Check 8 zuerst: Verbotene Aktionen sind immer blockiert
        forbidden_result = check_forbidden_actions(
            target, port, tool_name, scope, arguments,
        )
        if not forbidden_result.allowed:
            return forbidden_result

        # Checks 1-5 und 7: Gleiche Signatur (target, port, tool, scope)
        results = self._run_standard_checks(target, port, tool_name, scope)
        for result in results:
            if not result.allowed:
                self._log_violation(result, target, tool_name)
                return result

        logger.debug(
            "Scope-Check bestanden", target=target, tool=tool_name, port=port,
        )
        return ValidationResult(allowed=True, check_name="all_passed")

    def _run_standard_checks(
        self,
        target: str,
        port: int | None,
        tool_name: str,
        scope: PentestScope,
    ) -> list[ValidationResult]:
        """Führt die Standard-Checks 1-7 aus und gibt alle Ergebnisse zurück."""
        results = [
            check_target_in_scope(target, port, tool_name, scope),
            check_target_not_excluded(target, port, tool_name, scope),
            check_target_not_forbidden(target, port, tool_name, scope),
            check_port_in_scope(target, port, tool_name, scope),
            check_time_window(target, port, tool_name, scope),
            check_escalation_level(target, port, tool_name, scope, self._tool_map),
            check_tool_allowed(target, port, tool_name, scope),
        ]
        return results

    @staticmethod
    def _log_violation(result: ValidationResult, target: str, tool_name: str) -> None:
        """Loggt eine Scope-Verletzung."""
        logger.warning(
            "Scope-Verletzung",
            check=result.check_name,
            target=target,
            tool=tool_name,
            reason=result.reason,
        )

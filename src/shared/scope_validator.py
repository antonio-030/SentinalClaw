"""
Scope-Validator — Sicherheitskern von SentinelClaw.

Validiert JEDEN Tool-Aufruf gegen den definierten Scope.
Wird im MCP-Server aufgerufen — der Agent hat keinen Bypass.
Alle 7 Checks müssen bestanden werden, sonst wird blockiert.
"""

import ipaddress
from datetime import UTC, datetime

from src.shared.constants.defaults import (
    FORBIDDEN_IP_RANGES,
)
from src.shared.logging_setup import get_logger
from src.shared.types.scope import PentestScope, ValidationResult

logger = get_logger(__name__)

# Tool → Eskalationsstufe Zuordnung (Default, konfigurierbar über UI)
DEFAULT_TOOL_ESCALATION_MAP: dict[str, int] = {
    # Stufe 0: Passiv
    "whois": 0, "dig": 0, "host": 0,
    # Stufe 1: Aktive Scans
    "nmap": 1, "whatweb": 1, "dirsearch": 1,
    # Stufe 2: Vulnerability Checks
    "nuclei": 2, "nikto": 2, "sslscan": 2, "sqlmap_detect": 2,
    # Stufe 3: Exploitation
    "metasploit": 3, "sqlmap_exploit": 3, "hydra": 3, "john": 3, "hashcat": 3,
    # Stufe 4: Post-Exploitation
    "mimikatz": 4, "linpeas": 4, "winpeas": 4, "chisel": 4,
}


def _is_ip_address(target: str) -> bool:
    """Prüft ob ein String eine gültige IP-Adresse oder CIDR-Range ist."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def _ip_in_network(ip_str: str, network_str: str) -> bool:
    """Prüft ob eine IP-Adresse in einem Netzwerk liegt."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError:
        return False


def _ip_in_any_network(ip_str: str, networks: list[str]) -> bool:
    """Prüft ob eine IP in irgendeinem der Netzwerke liegt."""
    return any(_ip_in_network(ip_str, network) for network in networks)


def _target_matches_scope_entry(target: str, scope_entry: str) -> bool:
    """Prüft ob ein Ziel einem Scope-Eintrag entspricht.

    Unterstützt: IP-Adressen, CIDR-Ranges, Domain-Matching.
    """
    # Exakte Übereinstimmung (Domain oder IP)
    if target == scope_entry:
        return True

    # IP in CIDR-Range
    if _is_ip_address(target) and "/" in scope_entry:
        return _ip_in_network(target, scope_entry)

    # Wildcard-Domain-Matching (*.example.com)
    return bool(scope_entry.startswith("*.") and target.endswith(scope_entry[1:]))


def _parse_port_range(port_spec: str) -> set[int]:
    """Parst einen Port-Range-String in eine Menge von Ports.

    Unterstützt: "80", "80,443", "1-1000", "80,443,8000-8100"
    """
    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = max(1, int(start_str))
            end = min(65535, int(end_str))
            ports.update(range(start, end + 1))
        elif part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


class ScopeValidator:
    """Validiert Tool-Aufrufe gegen den definierten Scope.

    Führt 7 unabhängige Checks durch. Wenn EINER fehlschlägt,
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
    ) -> ValidationResult:
        """Führt alle 7 Scope-Checks durch.

        Gibt BLOCK zurück wenn auch nur EINE Prüfung fehlschlägt.
        """
        checks = [
            self._check_target_in_scope,
            self._check_target_not_excluded,
            self._check_target_not_forbidden,
            self._check_port_in_scope,
            self._check_time_window,
            self._check_escalation_level,
            self._check_tool_allowed,
        ]

        for check in checks:
            result = check(target, port, tool_name, scope)
            if not result.allowed:
                logger.warning(
                    "Scope-Verletzung",
                    check=result.check_name,
                    target=target,
                    tool=tool_name,
                    reason=result.reason,
                )
                return result

        logger.debug(
            "Scope-Check bestanden",
            target=target,
            tool=tool_name,
            port=port,
        )
        return ValidationResult(allowed=True, check_name="all_passed")

    def _check_target_in_scope(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 1: Ist das Ziel in der Include-Liste?"""
        if not scope.targets_include:
            return ValidationResult(
                allowed=False,
                check_name="target_in_scope",
                reason="Keine Scan-Ziele konfiguriert (targets_include ist leer)",
            )

        for entry in scope.targets_include:
            if _target_matches_scope_entry(target, entry):
                return ValidationResult(allowed=True, check_name="target_in_scope")

        return ValidationResult(
            allowed=False,
            check_name="target_in_scope",
            reason=f"Ziel '{target}' ist nicht in der Whitelist",
        )

    def _check_target_not_excluded(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 2: Ist das Ziel NICHT in der Exclude-Liste?"""
        for entry in scope.targets_exclude:
            if _target_matches_scope_entry(target, entry):
                return ValidationResult(
                    allowed=False,
                    check_name="target_not_excluded",
                    reason=f"Ziel '{target}' ist explizit ausgeschlossen",
                )
        return ValidationResult(allowed=True, check_name="target_not_excluded")

    def _check_target_not_forbidden(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 3: Ist das Ziel nicht in den verbotenen IP-Ranges?"""
        if not _is_ip_address(target):
            # Domains werden nicht gegen IP-Ranges geprüft
            return ValidationResult(allowed=True, check_name="target_not_forbidden")

        if _ip_in_any_network(target, FORBIDDEN_IP_RANGES):
            return ValidationResult(
                allowed=False,
                check_name="target_not_forbidden",
                reason=f"Ziel '{target}' liegt in einer verbotenen IP-Range (Loopback, Multicast)",
            )
        return ValidationResult(allowed=True, check_name="target_not_forbidden")

    def _check_port_in_scope(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 4: Ist der Port im erlaubten Bereich?"""
        if port is None:
            # Kein spezifischer Port angegeben (z.B. bei Host Discovery)
            return ValidationResult(allowed=True, check_name="port_in_scope")

        if port in scope.ports_exclude:
            return ValidationResult(
                allowed=False,
                check_name="port_in_scope",
                reason=f"Port {port} ist explizit ausgeschlossen",
            )

        allowed_ports = _parse_port_range(scope.ports_include)
        if port not in allowed_ports:
            return ValidationResult(
                allowed=False,
                check_name="port_in_scope",
                reason=f"Port {port} ist nicht im erlaubten Bereich ({scope.ports_include})",
            )

        return ValidationResult(allowed=True, check_name="port_in_scope")

    def _check_time_window(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 5: Sind wir innerhalb des erlaubten Zeitfensters?"""
        now = datetime.now(UTC)

        if scope.time_window_start and now < scope.time_window_start:
            return ValidationResult(
                allowed=False,
                check_name="time_window",
                reason=f"Zeitfenster beginnt erst um {scope.time_window_start.isoformat()}",
            )

        if scope.time_window_end and now > scope.time_window_end:
            return ValidationResult(
                allowed=False,
                check_name="time_window",
                reason=f"Zeitfenster ist abgelaufen seit {scope.time_window_end.isoformat()}",
            )

        return ValidationResult(allowed=True, check_name="time_window")

    def _check_escalation_level(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 6: Ist das Tool innerhalb der erlaubten Eskalationsstufe?"""
        tool_level = self._tool_map.get(tool_name)

        if tool_level is None:
            return ValidationResult(
                allowed=False,
                check_name="escalation_level",
                reason=f"Tool '{tool_name}' ist nicht in der Tool-Zuordnung registriert",
            )

        if tool_level > scope.max_escalation_level:
            return ValidationResult(
                allowed=False,
                check_name="escalation_level",
                reason=(
                    f"Tool '{tool_name}' (Stufe {tool_level}) überschreitet "
                    f"die erlaubte Stufe {scope.max_escalation_level}"
                ),
            )

        return ValidationResult(allowed=True, check_name="escalation_level")

    def _check_tool_allowed(
        self, target: str, port: int | None, tool_name: str, scope: PentestScope
    ) -> ValidationResult:
        """Check 7: Ist das Tool in der expliziten Allowlist (falls gesetzt)?"""
        if not scope.allowed_tools:
            # Keine explizite Allowlist → alle Tools der erlaubten Stufe sind ok
            return ValidationResult(allowed=True, check_name="tool_allowed")

        if tool_name in scope.allowed_tools:
            return ValidationResult(allowed=True, check_name="tool_allowed")

        return ValidationResult(
            allowed=False,
            check_name="tool_allowed",
            reason=f"Tool '{tool_name}' ist nicht in der Allowlist: {scope.allowed_tools}",
        )

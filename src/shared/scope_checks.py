"""
Scope-Check Hilfsfunktionen — Einzelne Validierungsprüfungen.

Extrahiert aus scope_validator.py für bessere Modularität.
Wird vom ScopeValidator aufgerufen — nicht direkt verwenden.
"""

import ipaddress
from datetime import UTC, datetime

from src.shared.constants.defaults import FORBIDDEN_IP_RANGES
from src.shared.types.scope import PentestScope, ValidationResult


def is_ip_address(target: str) -> bool:
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


def ip_in_network(ip_str: str, network_str: str) -> bool:
    """Prüft ob eine IP-Adresse in einem Netzwerk liegt."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError:
        return False


def ip_in_any_network(ip_str: str, networks: list[str]) -> bool:
    """Prüft ob eine IP in irgendeinem der Netzwerke liegt."""
    return any(ip_in_network(ip_str, network) for network in networks)


def target_matches_scope_entry(target: str, scope_entry: str) -> bool:
    """Prüft ob ein Ziel einem Scope-Eintrag entspricht.

    Unterstützt: IP-Adressen, CIDR-Ranges, Domain-Matching.
    """
    # Exakte Übereinstimmung (Domain oder IP)
    if target == scope_entry:
        return True

    # IP in CIDR-Range
    if is_ip_address(target) and "/" in scope_entry:
        return ip_in_network(target, scope_entry)

    # Wildcard-Domain-Matching (*.example.com)
    return bool(scope_entry.startswith("*.") and target.endswith(scope_entry[1:]))


def parse_port_range(port_spec: str) -> set[int]:
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


def check_target_in_scope(
    target: str, port: int | None, tool_name: str, scope: PentestScope
) -> ValidationResult:
    """Check 1: Ist das Ziel in der Include-Liste?"""
    if not scope.targets_include:
        return ValidationResult(
            allowed=False,
            check_name="target_in_scope",
            reason="Keine Scan-Ziele konfiguriert (targets_include ist leer)",
        )

    for entry in scope.targets_include:
        if target_matches_scope_entry(target, entry):
            return ValidationResult(allowed=True, check_name="target_in_scope")

    return ValidationResult(
        allowed=False,
        check_name="target_in_scope",
        reason=f"Ziel '{target}' ist nicht in der Whitelist",
    )


def check_target_not_excluded(
    target: str, port: int | None, tool_name: str, scope: PentestScope
) -> ValidationResult:
    """Check 2: Ist das Ziel NICHT in der Exclude-Liste?"""
    for entry in scope.targets_exclude:
        if target_matches_scope_entry(target, entry):
            return ValidationResult(
                allowed=False,
                check_name="target_not_excluded",
                reason=f"Ziel '{target}' ist explizit ausgeschlossen",
            )
    return ValidationResult(allowed=True, check_name="target_not_excluded")


def check_target_not_forbidden(
    target: str, port: int | None, tool_name: str, scope: PentestScope
) -> ValidationResult:
    """Check 3: Ist das Ziel nicht in den verbotenen IP-Ranges?"""
    if not is_ip_address(target):
        # Domains werden nicht gegen IP-Ranges geprüft
        return ValidationResult(allowed=True, check_name="target_not_forbidden")

    if ip_in_any_network(target, FORBIDDEN_IP_RANGES):
        return ValidationResult(
            allowed=False,
            check_name="target_not_forbidden",
            reason=f"Ziel '{target}' liegt in einer verbotenen IP-Range (Loopback, Multicast)",
        )
    return ValidationResult(allowed=True, check_name="target_not_forbidden")


def check_port_in_scope(
    target: str, port: int | None, tool_name: str, scope: PentestScope
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

    allowed_ports = parse_port_range(scope.ports_include)
    if port not in allowed_ports:
        return ValidationResult(
            allowed=False,
            check_name="port_in_scope",
            reason=f"Port {port} ist nicht im erlaubten Bereich ({scope.ports_include})",
        )

    return ValidationResult(allowed=True, check_name="port_in_scope")


def check_time_window(
    target: str, port: int | None, tool_name: str, scope: PentestScope
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


def check_escalation_level(
    target: str,
    port: int | None,
    tool_name: str,
    scope: PentestScope,
    tool_map: dict[str, int],
) -> ValidationResult:
    """Check 6: Ist das Tool innerhalb der erlaubten Eskalationsstufe?"""
    tool_level = tool_map.get(tool_name)

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


def check_tool_allowed(
    target: str, port: int | None, tool_name: str, scope: PentestScope
) -> ValidationResult:
    """Check 7: Ist das Tool in der expliziten Allowlist (falls gesetzt)?"""
    if not scope.allowed_tools:
        # Keine explizite Allowlist — alle Tools der erlaubten Stufe sind ok
        return ValidationResult(allowed=True, check_name="tool_allowed")

    if tool_name in scope.allowed_tools:
        return ValidationResult(allowed=True, check_name="tool_allowed")

    return ValidationResult(
        allowed=False,
        check_name="tool_allowed",
        reason=f"Tool '{tool_name}' ist nicht in der Allowlist: {scope.allowed_tools}",
    )


def check_forbidden_actions(
    target: str,
    port: int | None,
    tool_name: str,
    scope: PentestScope,
    arguments: str = "",
) -> ValidationResult:
    """Check 8: Verstößt der Aufruf gegen die Forbidden-Actions-Liste?

    Diese Prüfung kann NICHT überschrieben werden — verbotene Aktionen
    (DoS, Ransomware, Massen-Exfiltration) sind IMMER blockiert.
    """
    from src.shared.forbidden_action_map import check_forbidden_action

    violated = check_forbidden_action(
        tool_name, arguments, scope.forbidden_actions,
    )
    if violated:
        return ValidationResult(
            allowed=False,
            check_name="forbidden_actions",
            reason=f"Verbotene Aktion: '{violated}' (Tool: {tool_name})",
        )

    return ValidationResult(allowed=True, check_name="forbidden_actions")

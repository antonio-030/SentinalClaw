"""Mapping von Tool+Argument-Kombinationen auf verbotene Aktionen.

Wird vom ScopeValidator verwendet um gefährliche Tool-Aufrufe zu blockieren,
selbst wenn die Eskalationsstufe erlaubt wäre. Diese Aktionen sind IMMER verboten
und können weder vom Admin noch vom Agent überschrieben werden.
"""

import re

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


# Verbotene Aktions-Kategorien mit zugehörigen Tool+Args-Mustern
FORBIDDEN_ACTION_PATTERNS: list[dict[str, str]] = [
    # Denial-of-Service — Massenanfragen, Flood-Angriffe
    {"action": "denial_of_service", "tool": "hping3", "args": ".*"},
    {"action": "denial_of_service", "tool": "slowloris", "args": ".*"},
    {"action": "denial_of_service", "tool": "hydra", "args": ".*(--rate|--tasks)\\s+(\\d{3,})"},
    {"action": "denial_of_service", "tool": "nmap", "args": ".*-T5.*"},

    # Massen-Datenexfiltration — komplette Datenbank-Dumps
    {"action": "data_exfiltration_bulk", "tool": "sqlmap", "args": ".*(--dump-all|--dump|--all)"},
    {"action": "data_exfiltration_bulk", "tool": "crackmapexec", "args": ".*(--shares|--sam|--ntds)"},

    # Ransomware/Zerstörung — Verschlüsselung, Datenlöschung
    {"action": "ransomware", "tool": ".*", "args": ".*(rm\\s+-rf|mkfs|dd\\s+if=|shred)"},

    # Persistenz ohne Genehmigung — Backdoors, Cron-Jobs
    {"action": "persistence_without_roe", "tool": ".*", "args": ".*(crontab|systemctl\\s+enable|backdoor)"},
    {"action": "persistence_without_roe", "tool": "chisel", "args": ".*server.*--reverse"},

    # Angriff auf Dritte — Ziele außerhalb des Scope
    {"action": "attack_third_party", "tool": ".*", "args": ".*(-oA|-oN).*(/tmp/|/var/).*"},
]

# Kompilierte Patterns für Performance (einmalig beim Import)
_COMPILED_PATTERNS: list[tuple[str, re.Pattern, re.Pattern]] = [
    (p["action"], re.compile(p["tool"], re.IGNORECASE), re.compile(p["args"], re.IGNORECASE))
    for p in FORBIDDEN_ACTION_PATTERNS
]


def check_forbidden_action(
    tool_name: str,
    arguments: str,
    forbidden_actions: list[str],
) -> str | None:
    """Prüft ob eine Tool+Args-Kombination eine verbotene Aktion darstellt.

    Args:
        tool_name: Name des aufgerufenen Tools
        arguments: Kommandozeilen-Argumente als String
        forbidden_actions: Liste der verbotenen Aktions-Kategorien aus dem Scope

    Returns:
        Name der verletzten Aktion oder None wenn erlaubt.
    """
    for action, tool_pattern, args_pattern in _COMPILED_PATTERNS:
        if action not in forbidden_actions:
            continue
        if tool_pattern.match(tool_name) and args_pattern.match(arguments):
            logger.warning(
                "Verbotene Aktion erkannt",
                action=action, tool=tool_name, args=arguments[:100],
            )
            return action

    return None

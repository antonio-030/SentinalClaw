"""
Tool-Marker-Parser für SentinelClaw (Fallback).

Fallback-Parser für LLM-Provider ohne native Tool-Unterstützung.
Der primäre Pfad (OpenClaw) nutzt native Bash-Tools.
Dieser Parser erkennt Tool-Aufrufe in ```tool Blöcken oder
<<TOOL:befehl>> Markern und validiert gegen die Allowlist.
"""

import re
import shlex
from dataclasses import dataclass

from src.shared.constants.defaults import ALLOWED_SANDBOX_BINARIES

# Primaeres Format: ```tool Code-Bloecke (Claude generiert diese natuerlich)
_TOOL_BLOCK_PATTERN = re.compile(
    r"```tool\s*\n(.+?)\n```", re.DOTALL,
)

# Legacy-Format: <<TOOL:befehl>> Marker (Fallback)
_TOOL_MARKER_PATTERN = re.compile(r"<<TOOL:(.+?)>>", re.DOTALL)

# Verbotene Shell-Metazeichen (Command-Injection-Schutz)
_FORBIDDEN_CHARS = frozenset(";|&`$()><!")


@dataclass(frozen=True)
class ToolMarker:
    """Ein geparster Tool-Aufruf aus dem Agent-Output."""

    raw_command: str
    binary: str
    arguments: list[str]


@dataclass(frozen=True)
class ValidatedCommand:
    """Ergebnis der Befehlsvalidierung."""

    binary: str
    arguments: list[str]
    is_valid: bool
    rejection_reason: str = ""


def parse_tool_markers(text: str) -> list[ToolMarker]:
    """Extrahiert Tool-Aufrufe aus dem Text.

    Prueft zuerst auf ```tool Bloecke (bevorzugt),
    dann auf <<TOOL:...>> Marker (Legacy-Fallback).
    Jede nicht-leere Zeile in einem Block ist ein separater Befehl.
    """
    markers: list[ToolMarker] = []

    # Primaer: ```tool Bloecke parsen
    for match in _TOOL_BLOCK_PATTERN.finditer(text):
        block_content = match.group(1).strip()
        for line in block_content.splitlines():
            marker = _parse_single_command(line.strip())
            if marker:
                markers.append(marker)

    # Fallback: <<TOOL:...>> Marker (nur wenn keine Bloecke gefunden)
    if not markers:
        for match in _TOOL_MARKER_PATTERN.finditer(text):
            marker = _parse_single_command(match.group(1).strip())
            if marker:
                markers.append(marker)

    return markers


def _parse_single_command(raw: str) -> ToolMarker | None:
    """Parst einen einzelnen Befehl zu einem ToolMarker."""
    if not raw:
        return None

    try:
        parts = shlex.split(raw)
    except ValueError:
        return None

    if not parts:
        return None

    return ToolMarker(
        raw_command=raw,
        binary=parts[0],
        arguments=parts[1:],
    )


def strip_tool_markers(text: str) -> str:
    """Entfernt alle Tool-Marker aus dem Text.

    Entfernt sowohl ```tool Bloecke als auch <<TOOL:...>> Marker.
    Gibt sauberen, menschenlesbaren Text zurueck.
    """
    cleaned = _TOOL_BLOCK_PATTERN.sub("", text)
    cleaned = _TOOL_MARKER_PATTERN.sub("", cleaned)
    # Mehrfach-Leerzeilen aufraeumen
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def validate_tool_command(raw_command: str) -> ValidatedCommand:
    """Validiert einen Tool-Befehl gegen die Allowlist.

    Prueft:
    - Binary in ALLOWED_SANDBOX_BINARIES
    - Keine Shell-Metazeichen (Command-Injection-Schutz)
    - Befehl ist nicht leer
    """
    if not raw_command.strip():
        return ValidatedCommand("", [], False, "Leerer Befehl")

    # Shell-Metazeichen pruefen
    for char in _FORBIDDEN_CHARS:
        if char in raw_command:
            return ValidatedCommand(
                "", [], False,
                f"Verbotenes Zeichen '{char}' im Befehl",
            )

    try:
        parts = shlex.split(raw_command)
    except ValueError as error:
        return ValidatedCommand("", [], False, f"Parsing-Fehler: {error}")

    if not parts:
        return ValidatedCommand("", [], False, "Leerer Befehl nach Parsing")

    binary = parts[0]
    arguments = parts[1:]

    if binary not in ALLOWED_SANDBOX_BINARIES:
        return ValidatedCommand(
            binary, arguments, False,
            f"Binary '{binary}' nicht erlaubt. "
            f"Erlaubt: {', '.join(sorted(ALLOWED_SANDBOX_BINARIES))}",
        )

    return ValidatedCommand(binary, arguments, True)

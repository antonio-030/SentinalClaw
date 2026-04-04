"""
Scope-Typen für SentinelClaw.

Definiert den Geltungsbereich eines Pentests: welche Ziele,
Ports, Tools und Eskalationsstufen erlaubt sind.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

EscalationLevel = Literal[0, 1, 2, 3, 4]


class PentestScope(BaseModel):
    """Definiert was ein Scan darf und was nicht."""

    # Erlaubte Ziele (CIDR-Notation oder einzelne IPs/Domains)
    targets_include: list[str] = Field(
        default_factory=list,
        description="Erlaubte Scan-Ziele (z.B. '10.10.10.0/24', 'webapp.test.de')",
    )
    targets_exclude: list[str] = Field(
        default_factory=list,
        description="Ausgeschlossene Adressen innerhalb des Include-Bereichs",
    )

    # Erlaubte Ports
    ports_include: str = Field(
        default="1-65535",
        description="Erlaubte Port-Range (z.B. '1-1000' oder '80,443,8080')",
    )
    ports_exclude: list[int] = Field(
        default_factory=list,
        description="Ausgeschlossene Ports",
    )

    # Maximale Eskalationsstufe (0=passiv, 4=post-exploit)
    max_escalation_level: EscalationLevel = Field(default=2)

    # Erlaubte Tools (leer = alle Tools der erlaubten Stufe)
    allowed_tools: list[str] = Field(default_factory=list)

    # Zeitfenster
    time_window_start: datetime | None = Field(default=None)
    time_window_end: datetime | None = Field(default=None)

    # Verbotene Aktionen (absolut, unabhängig von Stufe)
    forbidden_actions: list[str] = Field(
        default_factory=lambda: [
            "denial_of_service",
            "ransomware",
            "data_exfiltration_bulk",
            "persistence_without_roe",
            "attack_third_party",
        ],
    )


class ValidationResult(BaseModel):
    """Ergebnis einer Scope-Validierung."""

    allowed: bool
    reason: str = ""
    check_name: str = ""

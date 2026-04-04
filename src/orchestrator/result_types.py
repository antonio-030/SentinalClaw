"""
Ergebnis-Typen für den Orchestrator-Agent.

Der Orchestrator gibt ein umfassenderes Ergebnis zurück als
der Recon-Agent, weil er mehrere Phasen koordiniert und eine
Gesamtbewertung erstellt.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.agents.recon.result_types import ReconResult


@dataclass
class ScanPhase:
    """Eine Phase im Scan-Plan des Orchestrators."""

    name: str
    description: str
    status: str = "pending"  # pending, running, completed, failed, skipped
    duration_seconds: float = 0.0
    error: str | None = None


@dataclass
class OrchestratorResult:
    """Gesamtergebnis eines orchestrierten Scans."""

    scan_id: str
    target: str
    scan_type: str = "recon"
    plan: list[ScanPhase] = field(default_factory=list)
    recon_result: ReconResult | None = None
    executive_summary: str = ""
    full_report: str = ""
    risk_assessment: str = ""
    recommendations: list[str] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    total_tokens_used: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @property
    def phases_completed(self) -> int:
        return len([p for p in self.plan if p.status == "completed"])

    @property
    def phases_total(self) -> int:
        return len(self.plan)

    @property
    def is_successful(self) -> bool:
        return self.phases_completed > 0 and self.recon_result is not None

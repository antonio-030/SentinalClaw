"""
Datenmodelle für SentinelClaw.

Pydantic-Modelle die in der gesamten Anwendung genutzt werden.
Orientiert am DB-Schema aus ADR-002, reduziert auf PoC-Scope
(kein Multi-Tenant, keine Organizations).
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    """Mögliche Status eines Scan-Jobs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EMERGENCY_KILLED = "emergency_killed"


class ScanType(StrEnum):
    """Scan-Typen die der Orchestrator unterstützt."""

    RECON = "recon"
    VULN = "vuln"
    FULL = "full"


class Severity(StrEnum):
    """CVSS-Severity-Stufen."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def _utc_now() -> datetime:
    """Gibt die aktuelle UTC-Zeit zurück."""
    return datetime.now(UTC)


class ScanJob(BaseModel):
    """Ein Scan-Auftrag — von der Erstellung bis zum Ergebnis."""

    id: UUID = Field(default_factory=uuid4)
    target: str = Field(description="Scan-Ziel (IP, CIDR oder Domain)")
    scan_type: ScanType = Field(default=ScanType.RECON)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Scan-spezifische Konfiguration (Ports, Flags, etc.)",
    )
    max_escalation_level: int = Field(
        default=2,
        ge=0,
        le=4,
        description="Maximale Eskalationsstufe für diesen Scan",
    )
    token_budget: int = Field(
        default=50_000,
        description="Token-Budget für LLM-Aufrufe",
    )
    tokens_used: int = Field(default=0)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=_utc_now)


class Finding(BaseModel):
    """Ein einzelnes Security-Finding aus einem Scan."""

    id: UUID = Field(default_factory=uuid4)
    scan_job_id: UUID
    tool_name: str = Field(description="Tool das den Fund gemacht hat (nmap, nuclei)")
    title: str
    severity: Severity
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cve_id: str | None = Field(default=None)
    target_host: str
    target_port: int | None = Field(default=None)
    service: str | None = Field(default=None)
    description: str = Field(default="")
    evidence: str = Field(default="", description="Beweis (Output, Screenshot-Referenz)")
    recommendation: str = Field(default="")
    raw_output: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=_utc_now)


class ScanResult(BaseModel):
    """Gesamtergebnis eines Tool-Aufrufs."""

    id: UUID = Field(default_factory=uuid4)
    scan_job_id: UUID
    tool_name: str
    result_type: str = Field(description="port_scan, vuln_scan, etc.")
    findings: list[Finding] = Field(default_factory=list)
    raw_output: str | None = Field(default=None)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    duration_seconds: float = Field(default=0.0)
    created_at: datetime = Field(default_factory=_utc_now)


class AuditLogEntry(BaseModel):
    """Unveränderlicher Audit-Log-Eintrag. Kein Update, kein Delete."""

    id: UUID = Field(default_factory=uuid4)
    action: str = Field(description="z.B. scan.started, tool.executed, kill.activated")
    resource_type: str | None = Field(default=None, description="scan_job, user, system")
    resource_id: str | None = Field(default=None)
    details: dict[str, Any] = Field(default_factory=dict)
    triggered_by: str = Field(default="system", description="User-ID oder 'system'")
    created_at: datetime = Field(default_factory=_utc_now)


class AgentLogEntry(BaseModel):
    """Log-Eintrag für einen Agent-Schritt (Tool-Aufruf, Entscheidung)."""

    id: UUID = Field(default_factory=uuid4)
    scan_job_id: UUID
    agent_name: str = Field(description="orchestrator, recon-agent, etc.")
    step_description: str
    tool_name: str | None = Field(default=None)
    input_params: dict[str, Any] = Field(default_factory=dict)
    output_summary: str = Field(default="")
    duration_ms: int = Field(default=0)
    created_at: datetime = Field(default_factory=_utc_now)

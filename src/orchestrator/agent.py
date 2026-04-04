"""
Orchestrator-Agent — Koordiniert den gesamten Scan-Ablauf.

Erstellt einen Ausführungsplan mit mindestens 2 Phasen,
delegiert an den Recon-Agent und erstellt eine Gesamtbewertung.
Entspricht FA-01 im Lastenheft.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, FindingRepository, ScanJobRepository
from src.shared.scope_validator import ScopeValidator
from src.shared.types.models import AuditLogEntry, ScanJob, ScanStatus
from src.shared.types.scope import PentestScope
from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.recon.agent import ReconAgent
from src.agents.recon.result_types import ReconResult
from src.orchestrator.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from src.orchestrator.result_types import OrchestratorResult, ScanPhase

logger = get_logger(__name__)


class OrchestratorAgent:
    """Übergeordneter Agent der Scan-Assessments koordiniert.

    Erstellt einen Plan, delegiert die Ausführung an den
    Recon-Agent (über NemoClaw-Runtime) und sammelt die Ergebnisse.
    Entspricht FA-01: Mindestens 2 Phasen, autonomer Start,
    strukturierte Zusammenfassung am Ende.
    """

    def __init__(self, scope: PentestScope) -> None:
        self._scope = scope
        self._settings = get_settings()
        self._runtime = NemoClawRuntime()
        self._db: DatabaseManager | None = None
        self._scan_repo: ScanJobRepository | None = None
        self._audit_repo: AuditLogRepository | None = None

    async def _ensure_db(self) -> None:
        """Initialisiert die Datenbank-Verbindung bei Bedarf."""
        if self._db is None:
            self._db = DatabaseManager(self._settings.db_path)
            await self._db.initialize()
            self._scan_repo = ScanJobRepository(self._db)
            self._audit_repo = AuditLogRepository(self._db)
            self._finding_repo = FindingRepository(self._db)

    async def orchestrate_scan(
        self,
        target: str,
        scan_type: str = "recon",
        ports: str = "1-1000",
    ) -> OrchestratorResult:
        """Führt einen vollständig orchestrierten Scan durch.

        1. Erstellt Scan-Job in DB
        2. Plant den Scan (mindestens 2 Phasen)
        3. Führt den Scan über NemoClaw-Runtime aus
        4. Analysiert Ergebnisse und erstellt Bericht
        5. Speichert alles in DB + Audit-Log
        """
        await self._ensure_db()
        start_time = time.monotonic()
        scan_id = str(uuid4())[:8]

        logger.info(
            "Orchestrator startet",
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
        )

        # Scan-Plan erstellen (FA-01: mindestens 2 Phasen)
        plan = self._create_scan_plan(target, scan_type, ports)

        result = OrchestratorResult(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            plan=plan,
        )

        # Scan-Job in DB erstellen
        job = ScanJob(
            target=target,
            scan_type=scan_type,
            max_escalation_level=self._scope.max_escalation_level,
            token_budget=self._settings.llm_max_tokens_per_scan,
            config={"ports": ports, "plan_phases": len(plan)},
        )
        await self._scan_repo.create(job)
        await self._scan_repo.update_status(job.id, ScanStatus.RUNNING)

        # Audit-Log: Scan gestartet
        await self._audit_repo.create(AuditLogEntry(
            action="scan.started",
            resource_type="scan_job",
            resource_id=str(job.id),
            details={
                "target": target,
                "scan_type": scan_type,
                "plan_phases": len(plan),
                "orchestrator_scan_id": scan_id,
            },
            triggered_by="orchestrator",
        ))

        try:
            # Multi-Phase Scan ausführen (3 separate Agent-Aufrufe)
            from src.orchestrator.multi_phase import run_multi_phase_scan

            for phase in plan:
                phase.status = "running"

            recon_result = await run_multi_phase_scan(
                target=target,
                ports=ports,
                allowed_targets=self._scope.targets_include,
                max_escalation_level=self._scope.max_escalation_level,
                runtime=self._runtime,
            )

            # Phasen als abgeschlossen markieren
            for phase in plan:
                phase.status = "completed"

            result.recon_result = recon_result
            result.full_report = recon_result.agent_summary
            result.total_tokens_used = recon_result.total_tokens_used

            # Findings in DB persistieren
            await self._persist_findings(job.id, recon_result)

            # Executive Summary erstellen
            result.executive_summary = self._create_executive_summary(recon_result)
            result.risk_assessment = self._create_risk_assessment(recon_result)
            result.recommendations = self._create_recommendations(recon_result)

            # Scan erfolgreich abgeschlossen
            duration = time.monotonic() - start_time
            result.total_duration_seconds = duration
            result.completed_at = datetime.now(timezone.utc)

            await self._scan_repo.update_status(
                job.id, ScanStatus.COMPLETED, tokens_used=recon_result.total_tokens_used
            )

            await self._audit_repo.create(AuditLogEntry(
                action="scan.completed",
                resource_type="scan_job",
                resource_id=str(job.id),
                details={
                    "hosts": recon_result.total_hosts,
                    "open_ports": recon_result.total_open_ports,
                    "vulnerabilities": recon_result.total_vulnerabilities,
                    "duration_s": round(duration, 1),
                    "tokens": recon_result.total_tokens_used,
                },
                triggered_by="orchestrator",
            ))

            logger.info(
                "Orchestrator abgeschlossen",
                scan_id=scan_id,
                phases=result.phases_completed,
                hosts=recon_result.total_hosts,
                ports=recon_result.total_open_ports,
                vulns=recon_result.total_vulnerabilities,
                duration_s=round(duration, 1),
            )

        except Exception as error:
            duration = time.monotonic() - start_time
            result.total_duration_seconds = duration

            for phase in plan:
                if phase.status == "running":
                    phase.status = "failed"
                    phase.error = str(error)

            await self._scan_repo.update_status(job.id, ScanStatus.FAILED)

            await self._audit_repo.create(AuditLogEntry(
                action="scan.failed",
                resource_type="scan_job",
                resource_id=str(job.id),
                details={"error": str(error)[:500], "duration_s": round(duration, 1)},
                triggered_by="orchestrator",
            ))

            logger.error(
                "Orchestrator fehlgeschlagen",
                scan_id=scan_id,
                error=str(error),
                duration_s=round(duration, 1),
            )

        return result

    async def _persist_findings(self, job_id, recon_result: ReconResult) -> None:
        """Speichert alle Findings aus dem Recon-Ergebnis in die Datenbank."""
        from src.shared.types.models import Finding, Severity

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for vuln in recon_result.vulnerabilities:
            finding = Finding(
                scan_job_id=job_id,
                tool_name="recon-agent",
                title=vuln.title,
                severity=severity_map.get(vuln.severity, Severity.INFO),
                cvss_score=vuln.cvss_score,
                cve_id=vuln.cve_id,
                target_host=vuln.host or recon_result.target,
                target_port=vuln.port,
                description=vuln.description,
                recommendation=vuln.recommendation,
            )
            await self._finding_repo.create(finding)

        # Audit-Log: Findings persistiert
        if recon_result.vulnerabilities:
            await self._audit_repo.create(AuditLogEntry(
                action="findings.persisted",
                resource_type="scan_job",
                resource_id=str(job_id),
                details={
                    "count": len(recon_result.vulnerabilities),
                    "severity_counts": recon_result.severity_counts,
                },
                triggered_by="orchestrator",
            ))

            logger.info(
                "Findings in DB gespeichert",
                count=len(recon_result.vulnerabilities),
                severities=recon_result.severity_counts,
            )

    def _create_scan_plan(
        self, target: str, scan_type: str, ports: str
    ) -> list[ScanPhase]:
        """Erstellt den Scan-Plan (FA-01: mindestens 2 Phasen)."""
        plan = [
            ScanPhase(
                name="Reconnaissance",
                description=f"Host Discovery und Port-Scan auf {target} (Ports: {ports})",
            ),
            ScanPhase(
                name="Analyse & Bewertung",
                description="Ergebnisse analysieren, Schwachstellen bewerten, Report erstellen",
            ),
        ]

        if scan_type in ("vuln", "full"):
            plan.insert(1, ScanPhase(
                name="Vulnerability Assessment",
                description=f"Vulnerability-Scan mit nuclei auf entdeckte Services",
            ))

        return plan

    def _create_executive_summary(self, recon: ReconResult) -> str:
        """Erstellt eine Management-Zusammenfassung."""
        if not recon.open_ports and not recon.vulnerabilities:
            return (
                f"Der Scan von {recon.target} hat keine offenen Ports "
                f"oder Schwachstellen ergeben."
            )

        sev = recon.severity_counts
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)

        summary = (
            f"Scan von {recon.target}: "
            f"{recon.total_hosts} Host(s), "
            f"{recon.total_open_ports} offene Ports, "
            f"{recon.total_vulnerabilities} Findings. "
        )

        if critical > 0:
            summary += f"ACHTUNG: {critical} kritische Schwachstelle(n) gefunden! "
        if high > 0:
            summary += f"{high} Schwachstelle(n) mit hohem Risiko. "

        return summary

    def _create_risk_assessment(self, recon: ReconResult) -> str:
        """Erstellt eine Risikobewertung basierend auf den Findings."""
        if not recon.vulnerabilities and not recon.open_ports:
            return "Keine signifikanten Risiken identifiziert."

        risks = []
        for vuln in sorted(recon.vulnerabilities, key=lambda v: v.cvss_score, reverse=True)[:3]:
            risks.append(f"- {vuln.severity.upper()}: {vuln.title}")

        for port in recon.open_ports:
            if port.service in ("ssh", "mysql", "postgres", "ftp"):
                if "old" in port.version.lower() or any(
                    v in port.version for v in ["5.", "6.", "7."]
                ):
                    risks.append(f"- Veralteter Dienst: {port.service} {port.version} auf Port {port.port}")

        return "\n".join(risks) if risks else "Keine kritischen Risiken identifiziert."

    def _create_recommendations(self, recon: ReconResult) -> list[str]:
        """Erstellt Handlungsempfehlungen."""
        recs: list[str] = []

        if recon.has_critical:
            recs.append("SOFORT: Kritische Schwachstellen beheben (siehe Findings)")

        for port in recon.open_ports:
            if "OpenSSH" in port.version and any(
                v in port.version for v in ["5.", "6.", "7."]
            ):
                recs.append(f"SSH auf {port.host}:{port.port} aktualisieren ({port.version} → aktuell)")

            if "Apache" in port.version and "2.4.7" in port.version:
                recs.append(f"Apache auf {port.host}:{port.port} aktualisieren ({port.version})")

        if not recs:
            recs.append("Regelmäßige Scans durchführen um neue Schwachstellen zu erkennen")

        return recs

    async def close(self) -> None:
        """Schließt die Datenbank-Verbindung."""
        if self._db:
            await self._db.close()

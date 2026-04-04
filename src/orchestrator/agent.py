"""
Orchestrator-Agent — Koordiniert den gesamten Scan-Ablauf.

Erstellt einen Ausführungsplan mit mindestens 2 Phasen,
delegiert an den Recon-Agent und erstellt eine Gesamtbewertung.
Entspricht FA-01 im Lastenheft.
"""

import time
from datetime import UTC, datetime
from uuid import uuid4

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.recon.result_types import ReconResult
from src.orchestrator.result_types import OrchestratorResult, ScanPhase
from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, FindingRepository, ScanJobRepository
from src.shared.types.models import AuditLogEntry, ScanJob, ScanStatus
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


class OrchestratorAgent:
    """Übergeordneter Agent der Scan-Assessments koordiniert.

    Erstellt einen Plan, delegiert die Ausführung an den
    Recon-Agent (über NemoClaw-Runtime) und sammelt die Ergebnisse.
    Entspricht FA-01: Mindestens 2 Phasen, autonomer Start,
    strukturierte Zusammenfassung am Ende.
    """

    def __init__(self, scope: PentestScope, db: DatabaseManager | None = None) -> None:
        self._scope = scope
        self._settings = get_settings()
        self._runtime = NemoClawRuntime()
        self._db = db
        self._scan_repo: ScanJobRepository | None = None
        self._audit_repo: AuditLogRepository | None = None
        self._owns_db = db is None  # Nur schließen wenn selbst erstellt

    async def _ensure_db(self) -> None:
        """Initialisiert die Datenbank-Verbindung bei Bedarf."""
        if self._db is None:
            self._db = DatabaseManager(self._settings.db_path)
            await self._db.initialize()
        if self._scan_repo is None:
            self._scan_repo = ScanJobRepository(self._db)
            self._audit_repo = AuditLogRepository(self._db)
            self._finding_repo = FindingRepository(self._db)

    async def orchestrate_scan(
        self,
        target: str,
        scan_type: str = "recon",
        ports: str = "1-1000",
        existing_scan_id: str | None = None,
    ) -> OrchestratorResult:
        """Führt einen vollständig orchestrierten Scan durch.

        existing_scan_id: Wenn gesetzt, wird kein neuer Job erstellt
        sondern der bestehende genutzt (z.B. aus Chat oder API).

        1. Erstellt Scan-Job in DB (oder nutzt bestehenden)
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

        # Scan-Job: Bestehenden nutzen oder neuen erstellen
        if existing_scan_id:
            from uuid import UUID as _UUID
            job = await self._scan_repo.get_by_id(_UUID(existing_scan_id))
            if not job:
                job = ScanJob(target=target, scan_type=scan_type, config={"ports": ports})
                await self._scan_repo.create(job)
        else:
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
                scan_job_id=job.id,
                db=self._db,
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
            result.completed_at = datetime.now(UTC)

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
                description="Vulnerability-Scan mit nuclei auf entdeckte Services",
            ))

        return plan

    def _create_executive_summary(self, recon: ReconResult) -> str:
        """Delegiert an assessment-Modul."""
        from src.orchestrator.assessment import create_executive_summary

        return create_executive_summary(recon)

    def _create_risk_assessment(self, recon: ReconResult) -> str:
        """Delegiert an assessment-Modul."""
        from src.orchestrator.assessment import create_risk_assessment

        return create_risk_assessment(recon)

    def _create_recommendations(self, recon: ReconResult) -> list[str]:
        """Delegiert an assessment-Modul."""
        from src.orchestrator.assessment import create_recommendations

        return create_recommendations(recon)

    async def close(self) -> None:
        """Schließt die DB-Verbindung nur wenn selbst erstellt."""
        if self._db and self._owns_db:
            await self._db.close()

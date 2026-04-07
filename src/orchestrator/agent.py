"""
Orchestrator-Agent — Koordiniert den gesamten Scan-Ablauf.

Erstellt einen Ausführungsplan mit mindestens 2 Phasen,
delegiert an den Recon-Agent und erstellt eine Gesamtbewertung.
Entspricht FA-01 im Lastenheft.

Phasenausführung ist in phase_executor.py ausgelagert.
"""

import time
from uuid import uuid4

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.orchestrator.phase_executor import (
    check_escalation_approval,
    execute_scan_phases,
    handle_scan_failure,
)
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
        self._finding_repo: FindingRepository | None = None
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
        """
        await self._ensure_db()
        start_time = time.monotonic()
        scan_id = str(uuid4())[:8]

        logger.info(
            "Orchestrator startet",
            scan_id=scan_id, target=target, scan_type=scan_type,
        )

        plan = self._create_scan_plan(target, scan_type, ports)
        result = OrchestratorResult(
            scan_id=scan_id, target=target, scan_type=scan_type, plan=plan,
        )

        job = await self._resolve_or_create_job(
            target, scan_type, ports, existing_scan_id, plan,
        )
        await self._log_scan_started(job, target, scan_type, plan, scan_id)

        await self._run_scan_with_error_handling(
            target, ports, plan, job, result, start_time,
        )
        return result

    async def _log_scan_started(
        self, job: ScanJob, target: str, scan_type: str,
        plan: list[ScanPhase], scan_id: str,
    ) -> None:
        """Erstellt den Audit-Log-Eintrag für den Scan-Start."""
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

    async def _run_scan_with_error_handling(
        self, target: str, ports: str, plan: list[ScanPhase],
        job: ScanJob, result: OrchestratorResult, start_time: float,
    ) -> None:
        """Führt den Scan aus — mit Approval-Prüfung und Fehlerbehandlung."""
        try:
            approved = await check_escalation_approval(
                self._db, self._scan_repo, job, self._scope, target, result,
            )
            if not approved:
                return

            await execute_scan_phases(
                target=target, ports=ports, plan=plan, scope=self._scope,
                job=job, runtime=self._runtime, db=self._db, result=result,
                scan_repo=self._scan_repo, audit_repo=self._audit_repo,
                finding_repo=self._finding_repo, start_time=start_time,
            )
        except Exception as error:
            await handle_scan_failure(
                error, plan, job, result,
                self._scan_repo, self._audit_repo, start_time,
            )

    async def _resolve_or_create_job(
        self,
        target: str,
        scan_type: str,
        ports: str,
        existing_scan_id: str | None,
        plan: list[ScanPhase],
    ) -> ScanJob:
        """Löst einen bestehenden Scan-Job auf oder erstellt einen neuen."""
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
        return job

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

    async def close(self) -> None:
        """Schließt die DB-Verbindung nur wenn selbst erstellt."""
        if self._db and self._owns_db:
            await self._db.close()

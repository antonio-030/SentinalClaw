"""
Phase-Executor — Führt die Scan-Phasen des Orchestrators aus.

Extrahiert aus agent.py für bessere Modularität.
Enthält die Phasenausführung, Findings-Persistierung und Approval-Prüfung.
"""

import time
from datetime import UTC, datetime

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.recon.result_types import ReconResult
from src.orchestrator.result_types import OrchestratorResult, ScanPhase
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, FindingRepository, ScanJobRepository
from src.shared.types.models import AuditLogEntry, ScanJob, ScanStatus
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


async def check_escalation_approval(
    db: DatabaseManager,
    scan_repo: ScanJobRepository,
    job: ScanJob,
    scope: PentestScope,
    target: str,
    result: OrchestratorResult,
) -> bool:
    """Prüft ob die Eskalationsstufe genehmigt wurde.

    Gibt True zurück wenn der Scan fortgesetzt werden darf,
    False wenn die Genehmigung fehlt oder abgelehnt wurde.
    """
    if scope.max_escalation_level < 3:
        return True

    from src.shared.approval_service import check_and_request_approval

    approved = await check_and_request_approval(
        db=db,
        scan_job_id=str(job.id),
        tool_name=f"scan_level_{scope.max_escalation_level}",
        target=target,
        escalation_level=scope.max_escalation_level,
        max_allowed_level=scope.max_escalation_level,
    )
    if not approved:
        logger.warning(
            "Scan abgelehnt — Eskalation nicht genehmigt",
            target=target, level=scope.max_escalation_level,
        )
        await scan_repo.update_status(job.id, ScanStatus.FAILED)
        result.executive_summary = (
            "Scan abgebrochen: Eskalationsgenehmigung wurde abgelehnt oder "
            "ist abgelaufen. Starten Sie den Scan mit niedrigerer Stufe "
            "oder holen Sie die Genehmigung ein."
        )
        return False
    return True


async def execute_scan_phases(
    target: str,
    ports: str,
    plan: list[ScanPhase],
    scope: PentestScope,
    job: ScanJob,
    runtime: NemoClawRuntime,
    db: DatabaseManager,
    result: OrchestratorResult,
    scan_repo: ScanJobRepository,
    audit_repo: AuditLogRepository,
    finding_repo: FindingRepository,
    start_time: float,
) -> None:
    """Führt die Multi-Phase Scan-Logik aus und aktualisiert das Ergebnis."""
    recon_result = await _run_multi_phase(
        target, ports, plan, scope, job, runtime, db,
    )

    result.recon_result = recon_result
    result.full_report = recon_result.agent_summary
    result.total_tokens_used = recon_result.total_tokens_used

    await persist_findings(job.id, recon_result, finding_repo, audit_repo)
    _apply_assessment(result, recon_result)

    await _finalize_scan(
        result, recon_result, job, scan_repo, audit_repo, start_time,
    )


async def _run_multi_phase(
    target: str,
    ports: str,
    plan: list[ScanPhase],
    scope: PentestScope,
    job: ScanJob,
    runtime: NemoClawRuntime,
    db: DatabaseManager,
) -> ReconResult:
    """Startet den Multi-Phase Scan und aktualisiert Phasen-Status."""
    from src.orchestrator.multi_phase import run_multi_phase_scan

    for phase in plan:
        phase.status = "running"

    recon_result = await run_multi_phase_scan(
        target=target,
        ports=ports,
        allowed_targets=scope.targets_include,
        max_escalation_level=scope.max_escalation_level,
        scan_job_id=job.id,
        db=db,
        runtime=runtime,
    )

    for phase in plan:
        phase.status = "completed"

    return recon_result


def _apply_assessment(result: OrchestratorResult, recon: ReconResult) -> None:
    """Erstellt Bewertungen und fügt sie dem Ergebnis hinzu."""
    from src.orchestrator.assessment import (
        create_executive_summary,
        create_recommendations,
        create_risk_assessment,
    )

    result.executive_summary = create_executive_summary(recon)
    result.risk_assessment = create_risk_assessment(recon)
    result.recommendations = create_recommendations(recon)


async def _finalize_scan(
    result: OrchestratorResult,
    recon_result: ReconResult,
    job: ScanJob,
    scan_repo: ScanJobRepository,
    audit_repo: AuditLogRepository,
    start_time: float,
) -> None:
    """Schließt den Scan ab — Status, Audit-Log und Logging."""
    duration = time.monotonic() - start_time
    result.total_duration_seconds = duration
    result.completed_at = datetime.now(UTC)

    await scan_repo.update_status(
        job.id, ScanStatus.COMPLETED, tokens_used=recon_result.total_tokens_used
    )

    await audit_repo.create(AuditLogEntry(
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
        scan_id=result.scan_id,
        phases=result.phases_completed,
        hosts=recon_result.total_hosts,
        ports=recon_result.total_open_ports,
        vulns=recon_result.total_vulnerabilities,
        duration_s=round(duration, 1),
    )


async def handle_scan_failure(
    error: Exception,
    plan: list[ScanPhase],
    job: ScanJob,
    result: OrchestratorResult,
    scan_repo: ScanJobRepository,
    audit_repo: AuditLogRepository,
    start_time: float,
) -> None:
    """Behandelt Fehler während der Scan-Ausführung.

    Markiert fehlgeschlagene Phasen, aktualisiert den Job-Status
    und erstellt einen Audit-Log-Eintrag.
    """
    duration = time.monotonic() - start_time
    result.total_duration_seconds = duration

    for phase in plan:
        if phase.status == "running":
            phase.status = "failed"
            phase.error = str(error)

    await scan_repo.update_status(job.id, ScanStatus.FAILED)

    await audit_repo.create(AuditLogEntry(
        action="scan.failed",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"error": str(error)[:500], "duration_s": round(duration, 1)},
        triggered_by="orchestrator",
    ))

    logger.error(
        "Orchestrator fehlgeschlagen",
        scan_id=result.scan_id,
        error=str(error),
        duration_s=round(duration, 1),
    )


async def persist_findings(
    job_id,
    recon_result: ReconResult,
    finding_repo: FindingRepository,
    audit_repo: AuditLogRepository,
) -> None:
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
        await finding_repo.create(finding)

    # Audit-Log: Findings persistiert
    if recon_result.vulnerabilities:
        await audit_repo.create(AuditLogEntry(
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

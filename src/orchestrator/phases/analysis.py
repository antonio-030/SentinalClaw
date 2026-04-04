"""
Phase 4: Analyse — LLM bewertet alle gesammelten Daten.

Kein Tool-Aufruf mehr — nur Claude-Reasoning über alle
Ergebnisse aus Phase 1-3. Erstellt:
- Executive Summary
- Risk Assessment (Top 3 kritischste Probleme)
- Priorisierte Empfehlungen
- Compliance-Relevanz (BSI, ISO 27001)
"""

from uuid import UUID

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.orchestrator.phases.base import PhaseResult
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import ScanPhaseRepository

logger = get_logger(__name__)


async def run_analysis(
    target: str,
    hosts_found: list[dict],
    ports_found: list[dict],
    findings_found: list[dict],
    scan_job_id: UUID,
    db: DatabaseManager,
    runtime: NemoClawRuntime | None = None,
) -> PhaseResult:
    """Phase 4: Abschlussanalyse aller gesammelten Daten.

    Der Agent bekommt KEINE Tools — nur die Ergebnisse aus Phase 1-3
    als Kontext. Er soll rein analytisch arbeiten.
    """
    phase_repo = ScanPhaseRepository(db)

    # Daten für den Analyse-Prompt aufbereiten
    hosts_text = "\n".join(
        f"  - {h['address']} ({h.get('hostname', '')})"
        for h in hosts_found
    ) or "  Keine Hosts entdeckt"

    ports_text = "\n".join(
        f"  - {p['host']}:{p['port']}/{p.get('protocol', 'tcp')} "
        f"{p.get('service', '?')} {p.get('version', '')}"
        for p in ports_found
    ) or "  Keine offenen Ports"

    findings_text = "\n".join(
        f"  - [{f.get('severity', '?').upper()}] {f.get('title', '?')} "
        f"({f.get('cve_id', 'kein CVE')}, CVSS: {f.get('cvss', '?')})"
        for f in findings_found
    ) or "  Keine Schwachstellen gefunden"

    # Statistiken
    severity_counts: dict[str, int] = {}
    for f in findings_found:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    system_prompt = (
        f"You are a senior security analyst for SentinelClaw.\n"
        f"You have NO tools — you analyze data only.\n\n"
        f"Scan target: {target}\n\n"
        f"## Phase 1 Results — Discovered Hosts ({len(hosts_found)}):\n{hosts_text}\n\n"
        f"## Phase 2 Results — Open Ports ({len(ports_found)}):\n{ports_text}\n\n"
        f"## Phase 3 Results — Vulnerabilities ({len(findings_found)}):\n{findings_text}\n\n"
        f"## Severity Distribution:\n"
        f"  Critical: {severity_counts.get('critical', 0)}\n"
        f"  High: {severity_counts.get('high', 0)}\n"
        f"  Medium: {severity_counts.get('medium', 0)}\n"
        f"  Low: {severity_counts.get('low', 0)}\n"
        f"  Info: {severity_counts.get('info', 0)}\n\n"
        f"Provide your analysis in this structure:\n\n"
        f"## Executive Summary\n"
        f"2-3 sentences overall security posture.\n\n"
        f"## Risk Assessment\n"
        f"Top 3 most critical risks with impact analysis.\n\n"
        f"## Recommendations\n"
        f"5 prioritized, actionable remediation steps.\n"
        f"Format: PRIORITY 1 (SOFORT): ..., PRIORITY 2 (7 TAGE): ..., etc.\n\n"
        f"## Compliance Notes\n"
        f"Brief BSI IT-Grundschutz and ISO 27001 relevance.\n\n"
        f"Be concise but thorough. Focus on actionable insights."
    )

    # Phase 4 braucht KEINE Bash-Tools — nur Claude-Reasoning
    # Dafür nutzen wir --allowedTools ohne Bash (kein Tool-Zugriff)
    from src.agents.nemoclaw_runtime import _invoke_claude_agent

    cli_args = [
        "--print",
        "--output-format", "json",
        "--append-system-prompt", system_prompt,
    ]

    # Phase in DB erstellen
    phase_id = await phase_repo.create(
        scan_job_id=scan_job_id,
        phase_number=4,
        name="Analyse & Bewertung",
        description="LLM analysiert alle Ergebnisse und erstellt Bewertung",
    )
    await phase_repo.update_status(phase_id, "running")

    import time
    start = time.monotonic()

    result = PhaseResult(
        phase_name="Analyse & Bewertung",
        phase_number=4,
    )

    try:
        data = await _invoke_claude_agent(
            args=cli_args,
            user_prompt=f"Analyze the security assessment results for {target} and provide your expert analysis.",
            timeout=120,
            runtime=runtime,
        )

        content = data.get("result", data.get("content", ""))
        duration = time.monotonic() - start

        result.raw_output = content
        result.duration_seconds = duration
        result.status = "completed"

        await phase_repo.update_status(
            phase_id, "completed",
            raw_output=content,
            duration_seconds=duration,
            parsed_result={
                "hosts_analyzed": len(hosts_found),
                "ports_analyzed": len(ports_found),
                "findings_analyzed": len(findings_found),
            },
        )

        logger.info(
            "Analyse abgeschlossen",
            duration_s=round(duration, 1),
            output_length=len(content),
        )

    except Exception as error:
        duration = time.monotonic() - start
        result.status = "failed"
        result.error = str(error)
        result.duration_seconds = duration

        await phase_repo.update_status(
            phase_id, "failed",
            error_message=str(error)[:500],
            duration_seconds=duration,
        )

        logger.error("Analyse fehlgeschlagen", error=str(error))

    return result

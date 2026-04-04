"""
Multi-Phase Scan-Executor für den Orchestrator.

Koordiniert 4 Phasen als separate Agent-Aufrufe mit
DB-Persistenz und Ergebnis-Weitergabe zwischen Phasen:

Phase 1: Host Discovery   → Welche Hosts sind aktiv?
Phase 2: Port-Scan        → Welche Ports/Services laufen?
Phase 3: Vuln-Assessment  → Welche Schwachstellen gibt es?
Phase 4: Analyse          → Bewertung und Empfehlungen
"""

import time
from uuid import UUID

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.recon.result_types import (
    DiscoveredHost,
    OpenPort,
    ReconResult,
    VulnerabilityFinding,
)
from src.orchestrator.phases.analysis import run_analysis
from src.orchestrator.phases.host_discovery import run_host_discovery
from src.orchestrator.phases.port_scan import run_port_scan
from src.orchestrator.phases.ssl_analysis import has_https_ports, run_ssl_analysis
from src.orchestrator.phases.vuln_scan import run_vuln_scan
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


async def run_multi_phase_scan(
    target: str,
    ports: str = "1-1000",
    allowed_targets: list[str] | None = None,
    max_escalation_level: int = 2,
    scan_job_id: UUID | None = None,
    db: DatabaseManager | None = None,
    runtime: NemoClawRuntime | None = None,
) -> ReconResult:
    """Führt einen vollständigen 4-Phasen-Scan durch.

    Jede Phase:
    - Ist ein eigenständiger Claude-Agent-Aufruf
    - Bekommt die Ergebnisse der vorherigen Phase als Kontext
    - Speichert ihre Ergebnisse in der Datenbank
    - Kann unabhängig fehlschlagen (nächste Phase läuft trotzdem)
    """
    if allowed_targets is None:
        allowed_targets = [target]

    total_start = time.monotonic()

    # DB erstellen falls nicht übergeben
    from src.shared.config import get_settings
    if db is None:
        db = DatabaseManager(get_settings().db_path)
        await db.initialize()

    # Scan-Job-ID erstellen falls nicht übergeben
    if scan_job_id is None:
        from uuid import uuid4
        scan_job_id = uuid4()

    logger.info(
        "Multi-Phase Scan gestartet",
        target=target,
        phases=4,
        scan_id=str(scan_job_id),
    )

    # ── Phase 1: Host Discovery ────────────────────────────────
    phase1 = await run_host_discovery(
        target=target,
        scan_job_id=scan_job_id,
        db=db,
        runtime=runtime,
        allowed_targets=allowed_targets,
    )
    hosts_found = phase1.hosts_found

    # ── Phase 2: Port-Scan ─────────────────────────────────────
    phase2 = await run_port_scan(
        target=target,
        ports=ports,
        discovered_hosts=hosts_found,
        scan_job_id=scan_job_id,
        db=db,
        runtime=runtime,
        allowed_targets=allowed_targets,
    )
    ports_found = phase2.ports_found

    # ── Phase 3: Vulnerability Assessment ──────────────────────
    phase3_findings: list[dict] = []
    if max_escalation_level >= 2:
        phase3 = await run_vuln_scan(
            target=target,
            ports=ports,
            discovered_hosts=hosts_found,
            ports_found=ports_found,
            scan_job_id=scan_job_id,
            db=db,
            runtime=runtime,
            allowed_targets=allowed_targets,
        )
        phase3_findings = phase3.findings_found
    else:
        logger.info("Phase 3 übersprungen (Eskalationsstufe < 2)")

    # ── Phase 3b: SSL/TLS-Analyse (nur bei HTTPS-Ports) ─────────
    ssl_findings: list[dict] = []
    phase_ssl_completed = False
    if has_https_ports(ports_found):
        phase_ssl = await run_ssl_analysis(
            target=target,
            ports_found=ports_found,
            scan_job_id=scan_job_id,
            db=db,
            runtime=runtime,
            allowed_targets=allowed_targets,
        )
        ssl_findings = phase_ssl.findings_found
        phase_ssl_completed = phase_ssl.status == "completed"
        # SSL-Findings zu den Gesamt-Findings hinzufügen
        phase3_findings.extend(ssl_findings)
    else:
        logger.info("Keine HTTPS-Ports gefunden, SSL-Analyse übersprungen")

    # ── Phase 4: Analyse & Bewertung ───────────────────────────
    phase4 = await run_analysis(
        target=target,
        hosts_found=hosts_found,
        ports_found=ports_found,
        findings_found=phase3_findings,
        scan_job_id=scan_job_id,
        db=db,
        runtime=runtime,
    )

    # ── Gesamtergebnis zusammenbauen ───────────────────────────
    total_duration = time.monotonic() - total_start
    ssl_tokens = phase_ssl.tokens_used if has_https_ports(ports_found) else 0
    total_tokens = (
        phase1.tokens_used + phase2.tokens_used
        + (phase3.tokens_used if max_escalation_level >= 2 else 0)
        + ssl_tokens
        + phase4.tokens_used
    )

    # ReconResult aus den Phase-Ergebnissen bauen
    result = ReconResult(
        target=target,
        discovered_hosts=[
            DiscoveredHost(address=h["address"], hostname=h.get("hostname", ""))
            for h in hosts_found
        ],
        open_ports=[
            OpenPort(
                host=p["host"], port=p["port"],
                protocol=p.get("protocol", "tcp"),
                service=p.get("service", ""),
                version=p.get("version", ""),
            )
            for p in ports_found
        ],
        vulnerabilities=[
            VulnerabilityFinding(
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                cvss_score=f.get("cvss", 0.0),
                cve_id=f.get("cve_id"),
                host=f.get("host", target),
                port=f.get("port"),
            )
            for f in phase3_findings
        ],
        agent_summary=phase4.raw_output or "",
        scan_duration_seconds=total_duration,
        total_tokens_used=total_tokens,
        phases_completed=sum(1 for p in [phase1, phase2, phase4]
                            if p.status == "completed")
            + (1 if max_escalation_level >= 2 and phase3.status == "completed" else 0)
            + (1 if phase_ssl_completed else 0),
    )

    logger.info(
        "Multi-Phase Scan abgeschlossen",
        target=target,
        hosts=result.total_hosts,
        ports=result.total_open_ports,
        vulns=result.total_vulnerabilities,
        phases=result.phases_completed,
        duration_s=round(total_duration, 1),
        tokens=total_tokens,
    )

    return result

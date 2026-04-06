"""
Phase 3: Vulnerability Assessment — Schwachstellen-Scan.

Nutzt nmap NSE-Scripts und (wenn PID-Limit ausreicht) nuclei
um Schwachstellen auf den gefundenen Services zu identifizieren.
Ergebnis: CVEs, CVSS-Scores, Empfehlungen — persistiert als Findings.
"""

import re
from uuid import UUID

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.scan_executor import execute_scan_command
from src.orchestrator.phases.base import PhaseResult, execute_phase
from src.shared.constants.severity import SEVERITY_CVSS_MAP
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import ScanPhaseRepository
from src.shared.repositories import FindingRepository
from src.shared.types.models import Finding, Severity

logger = get_logger(__name__)


async def run_vuln_scan(
    target: str,
    ports: str,
    ports_found: list[dict],
    scan_job_id: UUID,
    db: DatabaseManager,
    runtime: NemoClawRuntime | None = None,
    allowed_targets: list[str] | None = None,
) -> PhaseResult:
    """Phase 3: Vulnerability Assessment.

    Basierend auf den Ergebnissen aus Phase 1+2:
    - Nutzt nmap --script vuln auf die gefundenen Ports
    - Analysiert Service-Versionen auf bekannte CVEs
    - Speichert Findings in der Datenbank
    """
    phase_repo = ScanPhaseRepository(db)
    finding_repo = FindingRepository(db)

    targets_str = ", ".join(allowed_targets or [target])

    # Scan-Tool auf dem Host ausfuehren (Docker-Sandbox)
    scan_output = await execute_scan_command(
        ["nmap", "--script=default,vuln", "-p", ports, "--script-timeout", "30", target],
        timeout=180,
    )

    # Service-Infos fuer den Analyse-Prompt
    services_info = "\n".join(
        f"- {p['host']}:{p['port']}/{p.get('protocol', 'tcp')} "
        f"{p.get('service', '?')} {p.get('version', '')}"
        for p in ports_found
    ) if ports_found else "Keine offenen Ports aus Phase 2"

    system_prompt = (
        f"You are a vulnerability assessment analyst for SentinelClaw.\n"
        f"SECURITY: Only these targets are in scope: {targets_str}\n\n"
        f"Services from Phase 2:\n{services_info}\n\n"
        f"Below is the raw nmap vulnerability scan output.\n"
        f"Analyze it and identify all vulnerabilities.\n\n"
        f"=== NMAP VULN OUTPUT ===\n{scan_output}\n=== END ===\n\n"
        f"For each service, also analyze the version information:\n"
        f"- Check if the version is outdated/EOL\n"
        f"- Identify known CVEs for the specific version\n"
        f"- Assess the CVSS score (0.0-10.0)\n\n"
        f"Report ALL findings in this EXACT format:\n"
        f"FINDING: <severity> | <title> | <host>:<port> | <CVE-ID or none> | <CVSS>\n\n"
        f"Severity must be: CRITICAL, HIGH, MEDIUM, LOW, or INFO\n\n"
        f"End with a RISK ASSESSMENT section."
    )

    result = await execute_phase(
        phase_name="Vulnerability Assessment",
        phase_number=3,
        system_prompt=system_prompt,
        user_prompt=f"Analyze vulnerability scan results for {target}",
        scan_job_id=scan_job_id,
        phase_repo=phase_repo,
        max_turns=3,
        timeout=180,
        runtime=runtime,
    )

    if result.status != "completed" or not result.raw_output:
        return result

    # Findings aus dem Output parsen
    findings = _parse_findings(result.raw_output, target)
    result.findings_found = findings

    # Phase in DB aktualisieren
    phases = await phase_repo.list_by_scan(scan_job_id)
    phase_3_entries = [p for p in phases if p["phase_number"] == 3]
    if phase_3_entries:
        phase_id = UUID(phase_3_entries[-1]["id"])
        await phase_repo.update_status(
            phase_id, "completed",
            findings_found=len(findings),
            parsed_result={"findings": findings},
        )

    # Findings in DB persistieren (nur gueltige Dicts verarbeiten)
    for f in findings:
        if not isinstance(f, dict):
            continue
        severity_str = f.get("severity", "info").lower()
        severity = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }.get(severity_str, Severity.INFO)

        await finding_repo.create(Finding(
            scan_job_id=scan_job_id,
            tool_name=f.get("tool", "nmap-vuln"),
            title=f.get("title", "Unbekannt"),
            severity=severity,
            cvss_score=f.get("cvss", SEVERITY_CVSS_MAP.get(severity_str, 0.0)),
            cve_id=f.get("cve_id"),
            target_host=f.get("host", target),
            target_port=f.get("port"),
            description=f.get("description", ""),
            recommendation=f.get("recommendation", ""),
        ))

    logger.info(
        "Vulnerability Assessment abgeschlossen",
        target=target,
        findings=len(findings),
    )

    return result


def _parse_findings(output: str, default_target: str) -> list[dict]:
    """Extrahiert Findings aus dem Agent-Output."""
    findings: list[dict] = []
    seen_titles: set[str] = set()

    # Pattern 1: Unser vorgegebenes Format
    # "FINDING: CRITICAL | Title | host:port | CVE-ID | CVSS"
    for match in re.finditer(
        r"FINDING:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|\s*(.*?)\s*\|\s*"
        r"(\S+?)(?::(\d+))?\s*\|\s*(\S+)\s*\|\s*([\d.]+)",
        output, re.IGNORECASE,
    ):
        title = match.group(2).strip()
        title_key = title.lower()[:50]
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)

        cve = match.group(5).strip()
        if cve.lower() == "none" or cve == "-":
            cve = None

        findings.append({
            "severity": match.group(1).lower(),
            "title": title,
            "host": match.group(3),
            "port": int(match.group(4)) if match.group(4) else None,
            "cve_id": cve,
            "cvss": float(match.group(6)),
            "tool": "vuln-scan",
        })

    # Pattern 2: Severity-Keyword mit Beschreibung (Fallback)
    for match in re.finditer(
        r"(?:🔴|🟠|🟡|🔵|⚪)?\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*[:\-—]\s*(.+?)(?:\n|$)",
        output, re.IGNORECASE,
    ):
        severity = match.group(1).lower()
        title = match.group(2).strip()
        title = re.sub(r"\*+", "", title).strip()
        title_key = title.lower()[:50]

        if title_key in seen_titles or len(title) < 5:
            continue
        seen_titles.add(title_key)

        # CVE aus der Zeile extrahieren
        cve_match = re.search(r"(CVE-\d{4}-\d{4,})", title, re.IGNORECASE)
        cve = cve_match.group(1).upper() if cve_match else None

        # CVSS aus der Zeile extrahieren
        cvss_match = re.search(r"(\d+\.\d+)", title)
        cvss = float(cvss_match.group(1)) if cvss_match and float(cvss_match.group(1)) <= 10 else None

        findings.append({
            "severity": severity,
            "title": title[:120],
            "host": default_target,
            "port": None,
            "cve_id": cve,
            "cvss": cvss or SEVERITY_CVSS_MAP.get(severity, 0.0),
            "tool": "vuln-scan",
        })

    # Pattern 3: CVEs die in keinem Finding vorkommen
    assigned_cves = {f["cve_id"] for f in findings if f.get("cve_id")}
    for match in re.finditer(r"(CVE-\d{4}-\d{4,})", output, re.IGNORECASE):
        cve = match.group(1).upper()
        if cve not in assigned_cves:
            assigned_cves.add(cve)
            # Kontext extrahieren
            start = max(0, match.start() - 80)
            end = min(len(output), match.end() + 80)
            context = output[start:end].replace("\n", " ").strip()

            findings.append({
                "severity": "high",
                "title": f"Bekannte Schwachstelle: {cve}",
                "host": default_target,
                "port": None,
                "cve_id": cve,
                "cvss": 7.0,
                "tool": "vuln-scan",
                "description": context[:200],
            })

    return findings

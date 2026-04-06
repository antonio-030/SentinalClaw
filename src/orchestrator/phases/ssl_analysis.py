"""
Phase 3b: SSL/TLS-Analyse — Prüfung der TLS-Konfiguration.

Wird nur ausgeführt wenn HTTPS-Ports (443, 8443) in Phase 2
gefunden wurden. Nutzt nmap ssl-enum-ciphers und ssl-cert
Scripts um TLS-Versionen, Zertifikate und Cipher-Suites zu prüfen.

Ergebnis: Findings zu schwachen TLS-Konfigurationen, abgelaufenen
Zertifikaten und fehlenden Security-Headern.
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

# HTTPS-Ports die eine SSL/TLS-Analyse auslösen
HTTPS_PORTS: set[int] = {443, 8443}


def has_https_ports(ports_found: list[dict]) -> bool:
    """Prüft ob HTTPS-Ports in den Phase-2-Ergebnissen vorhanden sind.

    Gibt True zurück wenn mindestens ein Port aus HTTPS_PORTS
    in der Port-Liste gefunden wurde.
    """
    for port_entry in ports_found:
        port_num = port_entry.get("port")
        if port_num and int(port_num) in HTTPS_PORTS:
            return True
    return False


def _collect_https_ports(ports_found: list[dict]) -> dict[str, list[int]]:
    """Sammelt HTTPS-Ports gruppiert nach Host-Adresse.

    Rückgabe: {"10.0.0.1": [443, 8443], "10.0.0.2": [443]}
    """
    host_ports: dict[str, list[int]] = {}
    for port_entry in ports_found:
        port_num = port_entry.get("port")
        if port_num and int(port_num) in HTTPS_PORTS:
            host = port_entry.get("host", port_entry.get("host_address", ""))
            if host:
                host_ports.setdefault(host, []).append(int(port_num))
    return host_ports


async def _build_system_prompt(
    target: str,
    host_ports: dict[str, list[int]],
    allowed_targets: list[str],
) -> str:
    """Erstellt den System-Prompt mit Scan-Ergebnissen fuer den SSL/TLS-Agent."""
    targets_str = ", ".join(allowed_targets)

    # Scan-Ergebnisse sammeln — Scans laufen auf dem Host (Docker-Sandbox)
    scan_results: list[str] = []
    for host, ports in host_ports.items():
        port_str = ",".join(str(p) for p in sorted(ports))
        try:
            output = await execute_scan_command(
                ["nmap", "--script", "ssl-enum-ciphers,ssl-cert", "-p", port_str, host],
                timeout=120,
            )
            scan_results.append(f"=== {host}:{port_str} ===\n{output}")
        except RuntimeError as error:
            scan_results.append(f"=== {host}:{port_str} === FEHLER: {error}")

    scan_output = "\n\n".join(scan_results)

    return (
        f"You are an SSL/TLS analysis agent for SentinelClaw.\n"
        f"SECURITY: Only these targets are in scope: {targets_str}\n\n"
        f"Below is the raw nmap SSL/TLS scan output.\n"
        f"Analyze it for:\n"
        f"1. TLS versions: TLSv1.0 or TLSv1.1 = BAD, TLSv1.2 = OK, TLSv1.3 = GOOD\n"
        f"2. Certificate validity: expiration, self-signed, wrong CN/SAN\n"
        f"3. Weak cipher suites: RC4, DES, 3DES, NULL, export-grade\n\n"
        f"=== NMAP SSL OUTPUT ===\n{scan_output}\n=== END ===\n\n"
        f"Report ALL findings in this EXACT format:\n"
        f"FINDING: <severity> | <title> | <host>:<port> | "
        f"<CVE-ID or none> | <CVSS>\n\n"
        f"Severity must be: CRITICAL, HIGH, MEDIUM, LOW, or INFO\n\n"
        f"End with a TLS RISK ASSESSMENT section."
    )


async def run_ssl_analysis(
    target: str,
    ports_found: list[dict],
    scan_job_id: UUID,
    db: DatabaseManager,
    runtime: NemoClawRuntime | None = None,
    allowed_targets: list[str] | None = None,
) -> PhaseResult:
    """Phase 3b: SSL/TLS-Analyse auf HTTPS-Ports.

    Wird nur aufgerufen wenn has_https_ports() True liefert.
    Prüft TLS-Versionen, Zertifikate und Cipher-Suites.
    Speichert Findings in der Datenbank.
    """
    phase_repo = ScanPhaseRepository(db)
    finding_repo = FindingRepository(db)

    # HTTPS-Ports pro Host sammeln
    host_ports = _collect_https_ports(ports_found)
    if not host_ports:
        logger.info("Keine HTTPS-Ports gefunden, SSL-Analyse übersprungen")
        return PhaseResult(
            phase_name="SSL/TLS Analysis",
            phase_number=4,
            status="skipped",
        )

    all_targets = allowed_targets or [target]
    total_ports = sum(len(p) for p in host_ports.values())

    logger.info(
        "SSL/TLS-Analyse gestartet",
        target=target,
        https_hosts=len(host_ports),
        https_ports=total_ports,
    )

    system_prompt = await _build_system_prompt(target, host_ports, all_targets)

    # Benutzer-Prompt mit konkreten Port-Infos
    port_details = ", ".join(
        f"{host}:{','.join(str(p) for p in pts)}"
        for host, pts in host_ports.items()
    )
    user_prompt = (
        f"Analyze SSL/TLS configuration on HTTPS ports: {port_details}"
    )

    # Phase über die Basis-Funktion ausführen
    result = await execute_phase(
        phase_name="SSL/TLS Analysis",
        phase_number=4,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        scan_job_id=scan_job_id,
        phase_repo=phase_repo,
        max_turns=5,
        timeout=180,
        runtime=runtime,
    )

    if result.status != "completed" or not result.raw_output:
        return result

    # Findings aus dem Output parsen
    findings = _parse_ssl_findings(result.raw_output, target)
    result.findings_found = findings

    # Phase in DB aktualisieren
    phases = await phase_repo.list_by_scan(scan_job_id)
    phase_entries = [p for p in phases if p["name"] == "SSL/TLS Analysis"]
    if phase_entries:
        phase_id = UUID(phase_entries[-1]["id"])
        await phase_repo.update_status(
            phase_id, "completed",
            findings_found=len(findings),
            parsed_result={"findings": findings},
        )

    # Findings in DB persistieren
    for f in findings:
        severity_str = f.get("severity", "info").lower()
        severity = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }.get(severity_str, Severity.INFO)

        await finding_repo.create(Finding(
            scan_job_id=scan_job_id,
            tool_name=f.get("tool", "nmap-ssl"),
            title=f.get("title", "Unknown SSL/TLS Issue"),
            severity=severity,
            cvss_score=f.get("cvss", SEVERITY_CVSS_MAP.get(severity_str, 0.0)),
            cve_id=f.get("cve_id"),
            target_host=f.get("host", target),
            target_port=f.get("port"),
            description=f.get("description", ""),
            recommendation=f.get("recommendation", ""),
        ))

    logger.info(
        "SSL/TLS-Analyse abgeschlossen",
        target=target,
        findings=len(findings),
    )

    return result


def _parse_ssl_findings(output: str, default_target: str) -> list[dict]:
    """Extrahiert SSL/TLS-Findings aus dem Agent-Output."""
    findings: list[dict] = []
    seen_titles: set[str] = set()

    # Primäres Pattern: vorgegebenes FINDING-Format
    for match in re.finditer(
        r"FINDING:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|\s*(.*?)\s*\|\s*"
        r"(\S+?)(?::(\d+))?\s*\|\s*(\S+)\s*\|\s*([\d.]+)",
        output, re.IGNORECASE,
    ):
        title = match.group(2).strip()
        title_key = title.lower()[:60]
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)

        cve = match.group(5).strip()
        if cve.lower() in ("none", "-", "n/a"):
            cve = None

        findings.append({
            "severity": match.group(1).lower(),
            "title": title,
            "host": match.group(3),
            "port": int(match.group(4)) if match.group(4) else 443,
            "cve_id": cve,
            "cvss": float(match.group(6)),
            "tool": "nmap-ssl",
        })

    # Fallback: TLS-spezifische Schlüsselwörter erkennen
    tls_patterns: list[tuple[str, str, str, float]] = [
        (r"TLSv1\.0\s+enabled", "high", "TLSv1.0 Enabled", 7.4),
        (r"TLSv1\.1\s+enabled", "high", "TLSv1.1 Enabled", 7.4),
        (r"SSLv[23]\s+enabled", "critical", "SSLv2/v3 Enabled", 9.8),
        (r"certificate has expired", "critical", "Expired SSL Certificate", 9.1),
        (r"self[- ]signed certificate", "medium", "Self-Signed Certificate", 5.3),
    ]

    for pattern, severity, title, cvss in tls_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            title_key = title.lower()[:60]
            if title_key not in seen_titles:
                seen_titles.add(title_key)
                findings.append({
                    "severity": severity,
                    "title": title,
                    "host": default_target,
                    "port": 443,
                    "cve_id": None,
                    "cvss": cvss,
                    "tool": "nmap-ssl",
                })

    return findings

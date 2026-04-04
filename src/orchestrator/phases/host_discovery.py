"""
Phase 1: Host Discovery — Findet aktive Hosts im Zielnetzwerk.

Nutzt nmap -sn (Ping-Sweep) um zu ermitteln welche Hosts
im angegebenen Netzwerk/CIDR-Range aktiv sind.
Ergebnis wird in DB (discovered_hosts) persistiert.
"""

import re
from uuid import UUID

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import (
    DiscoveredHostRepository,
    ScanPhaseRepository,
)
from src.agents.nemoclaw_runtime import NemoClawRuntime, SANDBOX_CONTAINER
from src.orchestrator.phases.base import PhaseResult, execute_phase

logger = get_logger(__name__)


async def run_host_discovery(
    target: str,
    scan_job_id: UUID,
    db: DatabaseManager,
    runtime: NemoClawRuntime | None = None,
    allowed_targets: list[str] | None = None,
) -> PhaseResult:
    """Phase 1: Entdeckt aktive Hosts im Zielnetzwerk.

    Führt nmap -sn aus, parst die Ergebnisse und speichert
    jeden gefundenen Host in der Datenbank.
    """
    phase_repo = ScanPhaseRepository(db)
    host_repo = DiscoveredHostRepository(db)

    targets_str = ", ".join(allowed_targets or [target])

    system_prompt = (
        f"You are a host discovery scanner for SentinelClaw.\n"
        f"SECURITY: ONLY scan these targets: {targets_str}\n\n"
        f"Run this EXACT command:\n"
        f"docker exec {SANDBOX_CONTAINER} nmap -sn {target}\n\n"
        f"Then list ALL discovered hosts in this EXACT format, one per line:\n"
        f"HOST: <ip_address> <hostname_or_empty>\n\n"
        f"Example:\n"
        f"HOST: 10.10.10.5 webserver.local\n"
        f"HOST: 10.10.10.10\n\n"
        f"End with: TOTAL: <number> hosts found"
    )

    result = await execute_phase(
        phase_name="Host Discovery",
        phase_number=1,
        system_prompt=system_prompt,
        user_prompt=f"Discover all active hosts in {target}",
        scan_job_id=scan_job_id,
        phase_repo=phase_repo,
        max_turns=3,
        timeout=120,
        runtime=runtime,
    )

    if result.status != "completed" or not result.raw_output:
        return result

    # Hosts aus dem Output parsen und in DB speichern
    hosts = _parse_hosts(result.raw_output, target)
    result.hosts_found = hosts

    # Phase in DB mit Host-Anzahl aktualisieren
    phases = await phase_repo.list_by_scan(scan_job_id)
    if phases:
        phase_id = UUID(phases[-1]["id"])
        await phase_repo.update_status(
            phase_id, "completed",
            hosts_found=len(hosts),
            parsed_result={"hosts": hosts},
        )

    # Hosts in DB persistieren
    for host in hosts:
        await host_repo.create(
            scan_job_id=scan_job_id,
            phase_id=phase_id if phases else scan_job_id,
            address=host["address"],
            hostname=host.get("hostname", ""),
        )

    logger.info(
        "Host Discovery abgeschlossen",
        target=target,
        hosts_found=len(hosts),
    )

    return result


def _parse_hosts(output: str, default_target: str) -> list[dict]:
    """Extrahiert Hosts aus dem Agent-Output."""
    hosts: list[dict] = []
    seen: set[str] = set()

    # Pattern 1: Unser vorgegebenes Format "HOST: IP hostname"
    for match in re.finditer(r"HOST:\s+(\d+\.\d+\.\d+\.\d+)\s*(.*)", output):
        ip = match.group(1)
        hostname = match.group(2).strip()
        if ip not in seen:
            seen.add(ip)
            hosts.append({"address": ip, "hostname": hostname})

    # Pattern 2: nmap "Nmap scan report for hostname (IP)"
    for match in re.finditer(
        r"scan report for\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", output, re.IGNORECASE
    ):
        ip = match.group(2)
        hostname = match.group(1)
        if ip not in seen:
            seen.add(ip)
            hosts.append({"address": ip, "hostname": hostname})

    # Pattern 3: nmap "Nmap scan report for IP"
    for match in re.finditer(
        r"scan report for\s+(\d+\.\d+\.\d+\.\d+)", output, re.IGNORECASE
    ):
        ip = match.group(1)
        if ip not in seen:
            seen.add(ip)
            hosts.append({"address": ip, "hostname": ""})

    # Pattern 4: "Host is up" mit IP
    for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*Host is up", output):
        ip = match.group(1)
        if ip not in seen:
            seen.add(ip)
            hosts.append({"address": ip, "hostname": ""})

    # Fallback: Wenn es ein einzelner Host ist (Domain statt CIDR)
    if not hosts and not "/" in default_target:
        hosts.append({"address": default_target, "hostname": default_target})

    return hosts

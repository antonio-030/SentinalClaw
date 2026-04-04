"""
Phase 2: Port-Scan — Service-Erkennung auf entdeckten Hosts.

Scannt jeden Host aus Phase 1 auf offene Ports und identifiziert
laufende Services mit Versionsinformationen.
Ergebnis wird in DB (open_ports) persistiert.
"""

import re
from uuid import UUID

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import (
    OpenPortRepository,
    ScanPhaseRepository,
)
from src.agents.nemoclaw_runtime import NemoClawRuntime, SANDBOX_CONTAINER
from src.orchestrator.phases.base import PhaseResult, execute_phase

logger = get_logger(__name__)


async def run_port_scan(
    target: str,
    ports: str,
    discovered_hosts: list[dict],
    scan_job_id: UUID,
    db: DatabaseManager,
    runtime: NemoClawRuntime | None = None,
    allowed_targets: list[str] | None = None,
) -> PhaseResult:
    """Phase 2: Port-Scan mit Service-Erkennung.

    Nimmt die Hosts aus Phase 1 und scannt die angegebenen Ports.
    Erkennt Services und deren Versionen (-sV -sC).
    """
    phase_repo = ScanPhaseRepository(db)
    port_repo = OpenPortRepository(db)

    targets_str = ", ".join(allowed_targets or [target])

    # Host-Liste für den Prompt aufbereiten
    host_list = ", ".join(h["address"] for h in discovered_hosts) if discovered_hosts else target
    host_info = "\n".join(
        f"- {h['address']} ({h.get('hostname', '')})" for h in discovered_hosts
    ) if discovered_hosts else f"- {target}"

    system_prompt = (
        f"You are a port scanner for SentinelClaw.\n"
        f"SECURITY: ONLY scan these targets: {targets_str}\n\n"
        f"Hosts discovered in Phase 1:\n{host_info}\n\n"
        f"Run this command:\n"
        f"docker exec {SANDBOX_CONTAINER} nmap -sV -sC -p {ports} {host_list}\n\n"
        f"Report ALL open ports in this EXACT format, one per line:\n"
        f"PORT: <host_ip> <port>/<protocol> <state> <service> <version>\n\n"
        f"Example:\n"
        f"PORT: 10.10.10.5 22/tcp open ssh OpenSSH 8.9p1\n"
        f"PORT: 10.10.10.5 80/tcp open http nginx 1.24.0\n\n"
        f"End with: TOTAL: <number> open ports on <number> hosts"
    )

    result = await execute_phase(
        phase_name="Port-Scan",
        phase_number=2,
        system_prompt=system_prompt,
        user_prompt=f"Scan ports {ports} on discovered hosts with service detection",
        scan_job_id=scan_job_id,
        phase_repo=phase_repo,
        max_turns=4,
        timeout=180,
        runtime=runtime,
    )

    if result.status != "completed" or not result.raw_output:
        return result

    # Ports aus dem Output parsen
    ports_found = _parse_ports(result.raw_output, target)
    result.ports_found = ports_found

    # Phase in DB aktualisieren
    phases = await phase_repo.list_by_scan(scan_job_id)
    phase_2_entries = [p for p in phases if p["phase_number"] == 2]
    if phase_2_entries:
        phase_id = UUID(phase_2_entries[-1]["id"])
        await phase_repo.update_status(
            phase_id, "completed",
            ports_found=len(ports_found),
            parsed_result={"ports": ports_found},
        )
    else:
        phase_id = scan_job_id

    # Ports in DB persistieren
    for port_info in ports_found:
        await port_repo.create(
            scan_job_id=scan_job_id,
            phase_id=phase_id,
            host_address=port_info["host"],
            port=port_info["port"],
            protocol=port_info.get("protocol", "tcp"),
            service=port_info.get("service", ""),
            version=port_info.get("version", ""),
        )

    logger.info(
        "Port-Scan abgeschlossen",
        target=target,
        ports_found=len(ports_found),
    )

    return result


def _parse_ports(output: str, default_host: str) -> list[dict]:
    """Extrahiert Port-Informationen aus dem Agent-Output."""
    ports: list[dict] = []
    seen: set[tuple[str, int]] = set()

    # Versuche aktuellen Host zu bestimmen
    current_host = default_host
    host_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", output)
    if host_match:
        current_host = host_match.group(1)

    # Pattern 1: Unser vorgegebenes Format "PORT: host port/proto state service version"
    for match in re.finditer(
        r"PORT:\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)",
        output,
    ):
        host = match.group(1)
        port = int(match.group(2))
        state = match.group(4)
        key = (host, port)
        if key not in seen and state == "open":
            seen.add(key)
            ports.append({
                "host": host, "port": port, "protocol": match.group(3),
                "state": state, "service": match.group(5),
                "version": match.group(6).strip(),
            })

    # Pattern 2: nmap raw "22/tcp open ssh OpenSSH 6.6.1p1"
    for match in re.finditer(
        r"(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*?)(?:\n|$)",
        output,
    ):
        port = int(match.group(1))
        state = match.group(3)
        key = (current_host, port)
        if key not in seen and state == "open":
            seen.add(key)
            ports.append({
                "host": current_host, "port": port, "protocol": match.group(2),
                "state": state, "service": match.group(4),
                "version": match.group(5).strip(),
            })

    # Pattern 3: IP:Port/Proto Format "45.33.32.156:22/tcp ssh OpenSSH"
    for match in re.finditer(
        r"(\d+\.\d+\.\d+\.\d+):(\d{1,5})/(tcp|udp)\s+(\S+)\s*(.*?)(?:\n|$)",
        output,
    ):
        host = match.group(1)
        port = int(match.group(2))
        key = (host, port)
        if key not in seen:
            seen.add(key)
            ports.append({
                "host": host, "port": port, "protocol": match.group(3),
                "state": "open", "service": match.group(4),
                "version": match.group(5).strip(),
            })

    # Pattern 4: Markdown-Tabelle "| 22 | ssh | OpenSSH 6.6.1p1 |"
    for match in re.finditer(
        r"\|\s*(\d{1,5})\s*\|\s*(\w[\w\-]*)\s*\|\s*(.*?)\s*\|",
        output,
    ):
        port = int(match.group(1))
        service = match.group(2).strip()
        version = match.group(3).strip().strip("|").strip()

        if service.lower() in ("port", "dienst", "service", "---", "status", "protocol"):
            continue

        key = (current_host, port)
        if key not in seen:
            seen.add(key)
            ports.append({
                "host": current_host, "port": port, "protocol": "tcp",
                "state": "open", "service": service,
                "version": re.sub(r"\*+", "", version).strip(),
            })

    return ports

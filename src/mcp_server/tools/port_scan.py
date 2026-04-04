"""
MCP-Tool: port_scan — nmap Port-Scan auf Ziel.

Führt einen nmap-Scan im Sandbox-Container aus, parsed die
XML-Ausgabe und gibt strukturiertes JSON zurück.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from src.mcp_server.tools.input_validation import (
    validate_nmap_flags,
    validate_ports,
    validate_target,
)
from src.sandbox.executor import ExecutionResult, SandboxExecutor
from src.shared.logging_setup import get_logger
from src.shared.scope_validator import ScopeValidator
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


@dataclass
class PortInfo:
    """Informationen über einen gefundenen offenen Port."""

    port: int
    protocol: str
    state: str
    service: str
    version: str


@dataclass
class HostResult:
    """Scan-Ergebnis für einen einzelnen Host."""

    address: str
    hostname: str
    state: str
    ports: list[PortInfo]


@dataclass
class PortScanResult:
    """Gesamtergebnis eines Port-Scans."""

    hosts: list[HostResult]
    total_hosts_up: int
    total_open_ports: int
    scan_duration_seconds: float
    raw_output: str
    command_used: str


async def run_port_scan(
    target: str,
    ports: str = "1-1000",
    flags: list[str] | None = None,
    scope: PentestScope | None = None,
    executor: SandboxExecutor | None = None,
    scope_validator: ScopeValidator | None = None,
) -> PortScanResult:
    """Führt einen nmap Port-Scan auf dem Ziel durch.

    1. Validiert alle Eingaben
    2. Prüft ob das Ziel im Scope liegt
    3. Baut den nmap-Befehl parametrisiert zusammen
    4. Führt ihn in der Sandbox aus
    5. Parst die XML-Ausgabe
    6. Gibt strukturiertes Ergebnis zurück
    """
    # Eingaben validieren
    validated_target = validate_target(target)
    validated_ports = validate_ports(ports)
    validated_flags = validate_nmap_flags(flags or ["-sV"])

    # Scope prüfen (wenn Scope definiert)
    if scope and scope_validator:
        result = scope_validator.validate(
            target=validated_target.split(",")[0],
            port=None,
            tool_name="nmap",
            scope=scope,
        )
        if not result.allowed:
            raise PermissionError(f"Scope-Verletzung: {result.reason}")

    # nmap-Befehl parametrisiert zusammenbauen
    # KEIN Shell-String, KEINE Konkatenation mit User-Input
    command = ["nmap"]
    command.extend(validated_flags)
    command.extend(["-p", validated_ports])
    command.extend(["-oX", "-"])  # XML-Ausgabe auf stdout
    command.append(validated_target)

    command_str = " ".join(command)
    logger.info("Port-Scan gestartet", target=validated_target, ports=validated_ports)

    # In der Sandbox ausführen
    sandbox = executor or SandboxExecutor()
    exec_result: ExecutionResult = await sandbox.execute(command)

    if exec_result.exit_code != 0 and not exec_result.stdout:
        raise RuntimeError(
            f"nmap fehlgeschlagen (Exit {exec_result.exit_code}): {exec_result.stderr[:500]}"
        )

    # XML-Ausgabe parsen
    hosts = _parse_nmap_xml(exec_result.stdout)

    total_open = sum(
        len([p for p in host.ports if p.state == "open"])
        for host in hosts
    )

    logger.info(
        "Port-Scan abgeschlossen",
        target=validated_target,
        hosts_up=len(hosts),
        open_ports=total_open,
        duration_s=round(exec_result.duration_seconds, 1),
    )

    return PortScanResult(
        hosts=hosts,
        total_hosts_up=len(hosts),
        total_open_ports=total_open,
        scan_duration_seconds=exec_result.duration_seconds,
        raw_output=exec_result.stdout,
        command_used=command_str,
    )


def _parse_nmap_xml(xml_output: str) -> list[HostResult]:
    """Parst nmap XML-Ausgabe in strukturierte HostResult-Objekte."""
    hosts: list[HostResult] = []

    if not xml_output.strip():
        return hosts

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        logger.warning("nmap XML konnte nicht geparsed werden, versuche Plaintext")
        return hosts

    for host_elem in root.findall(".//host"):
        # Host-Status
        status_elem = host_elem.find("status")
        host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        if host_state != "up":
            continue

        # IP-Adresse
        addr_elem = host_elem.find("address")
        address = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

        # Hostname
        hostname = ""
        hostnames_elem = host_elem.find("hostnames/hostname")
        if hostnames_elem is not None:
            hostname = hostnames_elem.get("name", "")

        # Ports
        ports: list[PortInfo] = []
        for port_elem in host_elem.findall(".//port"):
            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service_name = ""
            service_version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                service_version = f"{product} {version}".strip()

            ports.append(PortInfo(
                port=port_id,
                protocol=protocol,
                state=port_state,
                service=service_name,
                version=service_version,
            ))

        hosts.append(HostResult(
            address=address,
            hostname=hostname,
            state=host_state,
            ports=ports,
        ))

    return hosts

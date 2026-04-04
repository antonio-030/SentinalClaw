"""
SentinelClaw MCP-Server — Tool-Abstraktion für KI-Agenten.

Exponiert die Pentest-Tools (nmap, nuclei) als MCP-Tools.
Der Agent ruft diese Tools über das MCP-Protokoll auf.
Jeder Aufruf wird gegen den Scope validiert und geloggt.
"""

import json

from fastmcp import FastMCP

from src.mcp_server.tools.exec_command import run_exec_command
from src.mcp_server.tools.parse_output import parse_output
from src.mcp_server.tools.port_scan import run_port_scan
from src.mcp_server.tools.vuln_scan import run_vuln_scan
from src.sandbox.executor import SandboxExecutor
from src.shared.config import get_settings
from src.shared.logging_setup import get_logger
from src.shared.scope_validator import ScopeValidator
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


def create_mcp_server() -> FastMCP:
    """Erstellt und konfiguriert den MCP-Server mit allen 4 Tools."""
    get_settings()
    mcp = FastMCP(
        name="SentinelClaw MCP-Server",
        instructions=(
            "SentinelClaw Pentest-Tool-Server. Bietet Port-Scanning (nmap), "
            "Vulnerability-Scanning (nuclei), freie Befehlsausführung und "
            "Output-Parsing als MCP-Tools an. Alle Tools laufen isoliert "
            "in einem Docker-Sandbox-Container."
        ),
    )

    # Gemeinsame Instanzen für alle Tools
    scope_validator = ScopeValidator()
    executor = SandboxExecutor()

    # Scope aus Konfiguration laden
    def _get_current_scope() -> PentestScope:
        """Lädt den aktuellen Scope aus der Konfiguration."""
        current_settings = get_settings()
        return PentestScope(
            targets_include=current_settings.get_allowed_targets_list(),
            max_escalation_level=2,  # Default für PoC
        )

    # ─── Tool 1: port_scan ────────────────────────────────────

    @mcp.tool()
    async def port_scan(
        target: str,
        ports: str = "1-1000",
        flags: str = "-sV",
    ) -> str:
        """Führt einen nmap Port-Scan auf dem Ziel durch.

        Scannt die angegebenen Ports und identifiziert laufende
        Services und deren Versionen.

        Args:
            target: IP-Adresse, CIDR-Range oder Domain des Ziels
            ports: Port-Range (z.B. "80,443" oder "1-1000")
            flags: nmap-Flags als komma-separierter String (z.B. "-sV,-sC")
        """
        flag_list = [f.strip() for f in flags.split(",") if f.strip()]
        scope = _get_current_scope()

        result = await run_port_scan(
            target=target,
            ports=ports,
            flags=flag_list,
            scope=scope,
            executor=executor,
            scope_validator=scope_validator,
        )

        # Strukturiertes Ergebnis als JSON-String zurückgeben
        output = {
            "hosts": [
                {
                    "address": host.address,
                    "hostname": host.hostname,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                        }
                        for p in host.ports
                    ],
                }
                for host in result.hosts
            ],
            "summary": f"{result.total_hosts_up} Hosts, {result.total_open_ports} offene Ports",
            "duration_seconds": round(result.scan_duration_seconds, 1),
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    # ─── Tool 2: vuln_scan ────────────────────────────────────

    @mcp.tool()
    async def vuln_scan(
        target: str,
        templates: str = "cves,vulnerabilities",
    ) -> str:
        """Führt einen nuclei Vulnerability-Scan auf dem Ziel durch.

        Prüft das Ziel auf bekannte Schwachstellen anhand von Templates.

        Args:
            target: IP-Adresse oder Domain des Ziels
            templates: Komma-separierte Template-Kategorien
                       (cves, vulnerabilities, misconfiguration, default-logins, exposures)
        """
        template_list = [t.strip() for t in templates.split(",") if t.strip()]
        scope = _get_current_scope()

        result = await run_vuln_scan(
            target=target,
            templates=template_list,
            scope=scope,
            executor=executor,
            scope_validator=scope_validator,
        )

        output = {
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "host": f.host,
                    "port": f.port,
                    "cve_id": f.cve_id,
                    "description": f.description[:200],
                    "matched_at": f.matched_at,
                }
                for f in result.findings
            ],
            "severity_counts": result.severity_counts,
            "summary": f"{result.total_findings} Findings gefunden",
            "duration_seconds": round(result.scan_duration_seconds, 1),
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    # ─── Tool 3: exec_command ─────────────────────────────────

    @mcp.tool()
    async def exec_command(
        command: str,
        timeout: int = 60,
    ) -> str:
        """Führt einen Befehl in der isolierten Sandbox aus.

        NUR erlaubte Binaries: nmap, nuclei. Andere werden blockiert.

        Args:
            command: Der auszuführende Befehl (z.B. "nmap -sn 10.10.10.0/24")
            timeout: Maximale Ausführungszeit in Sekunden
        """
        # Befehl in Teile aufsplitten (sicher, kein Shell)
        parts = command.split()
        if not parts:
            return json.dumps({"error": "Kein Befehl angegeben"})

        scope = _get_current_scope()

        try:
            result = await run_exec_command(
                command_parts=parts,
                timeout=min(timeout, 600),  # Max 10 Minuten
                scope=scope,
                executor=executor,
                scope_validator=scope_validator,
            )

            return json.dumps({
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "duration_seconds": round(result.duration_seconds, 1),
                "timed_out": result.timed_out,
            }, ensure_ascii=False)
        except PermissionError as error:
            return json.dumps({"error": str(error), "blocked": True})

    # ─── Tool 4: parse_output ─────────────────────────────────

    @mcp.tool()
    async def parse_scan_output(
        raw_output: str,
        output_format: str = "nmap_xml",
    ) -> str:
        """Parst Scan-Rohdaten in strukturiertes JSON.

        Args:
            raw_output: Rohe Scan-Ausgabe
            output_format: Format der Eingabe (nmap_xml, nuclei_jsonl, plaintext)
        """
        result = parse_output(raw_output=raw_output, output_format=output_format)
        return json.dumps(result, indent=2, ensure_ascii=False)

    return mcp

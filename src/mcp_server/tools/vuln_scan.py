"""
MCP-Tool: vuln_scan — nuclei Vulnerability-Scan auf Ziel.

Führt einen nuclei-Scan im Sandbox-Container aus, parsed die
JSONL-Ausgabe und gibt strukturierte Findings zurück.
"""

import json
from dataclasses import dataclass, field

from src.mcp_server.tools.input_validation import (
    validate_nuclei_templates,
    validate_target,
)
from src.sandbox.executor import ExecutionResult, SandboxExecutor
from src.shared.logging_setup import get_logger
from src.shared.scope_validator import ScopeValidator
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


@dataclass
class VulnFinding:
    """Ein einzelner Vulnerability-Fund von nuclei."""

    template_id: str
    name: str
    severity: str  # critical, high, medium, low, info
    description: str
    host: str
    port: int | None
    matched_at: str
    cve_id: str | None
    reference: list[str] = field(default_factory=list)


@dataclass
class VulnScanResult:
    """Gesamtergebnis eines Vulnerability-Scans."""

    findings: list[VulnFinding]
    total_findings: int
    severity_counts: dict[str, int]
    scan_duration_seconds: float
    raw_output: str
    command_used: str


async def run_vuln_scan(
    target: str,
    templates: list[str] | None = None,
    scope: PentestScope | None = None,
    executor: SandboxExecutor | None = None,
    scope_validator: ScopeValidator | None = None,
) -> VulnScanResult:
    """Führt einen nuclei Vulnerability-Scan auf dem Ziel durch.

    1. Validiert Eingaben
    2. Scope-Check
    3. Baut nuclei-Befehl parametrisiert
    4. Führt in Sandbox aus
    5. Parst JSONL-Output
    6. Gibt strukturiertes Ergebnis zurück
    """
    validated_target = validate_target(target)
    validated_templates = validate_nuclei_templates(templates or ["cves", "vulnerabilities"])

    # Scope prüfen
    if scope and scope_validator:
        result = scope_validator.validate(
            target=validated_target.split(",")[0],
            port=None,
            tool_name="nuclei",
            scope=scope,
        )
        if not result.allowed:
            raise PermissionError(f"Scope-Verletzung: {result.reason}")

    # nuclei-Befehl parametrisiert zusammenbauen
    command = ["nuclei"]
    command.extend(["-u", validated_target])
    command.extend(["-t", ",".join(validated_templates)])
    command.append("-jsonl")          # JSONL-Ausgabe
    command.append("-silent")         # Keine Banner-Ausgabe
    command.append("-no-color")       # Keine ANSI-Farben
    command.extend(["-severity", "critical,high,medium,low,info"])

    command_str = " ".join(command)
    logger.info("Vuln-Scan gestartet", target=validated_target, templates=validated_templates)

    # In der Sandbox ausführen
    sandbox = executor or SandboxExecutor()
    exec_result: ExecutionResult = await sandbox.execute(command)

    # nuclei gibt Exit-Code 0 auch wenn Findings gefunden werden
    # und Exit-Code 1 bei Fehlern — aber stderr hat oft Warnungen
    raw_output = exec_result.stdout

    # JSONL-Ausgabe parsen
    findings = _parse_nuclei_jsonl(raw_output)

    # Severity-Zusammenfassung
    severity_counts: dict[str, int] = {}
    for finding in findings:
        sev = finding.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.info(
        "Vuln-Scan abgeschlossen",
        target=validated_target,
        total_findings=len(findings),
        severity_counts=severity_counts,
        duration_s=round(exec_result.duration_seconds, 1),
    )

    return VulnScanResult(
        findings=findings,
        total_findings=len(findings),
        severity_counts=severity_counts,
        scan_duration_seconds=exec_result.duration_seconds,
        raw_output=raw_output,
        command_used=command_str,
    )


def _parse_nuclei_jsonl(raw_output: str) -> list[VulnFinding]:
    """Parst nuclei JSONL-Ausgabe in strukturierte VulnFinding-Objekte."""
    findings: list[VulnFinding] = []

    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        # nuclei JSONL-Format: template-id, info.name, info.severity, etc.
        info = data.get("info", {})
        template_id = data.get("template-id", data.get("templateID", "unknown"))
        name = info.get("name", template_id)
        severity = info.get("severity", "info")
        description = info.get("description", "")

        # Host und Port extrahieren
        host = data.get("host", "")
        matched_at = data.get("matched-at", data.get("matchedAt", host))

        # Port aus matched-at extrahieren wenn möglich (z.B. "https://10.10.10.5:443")
        port = _extract_port_from_url(matched_at)

        # CVE-Referenz extrahieren
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        cve_id = cve_ids[0] if cve_ids else None

        # Referenzen
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        findings.append(VulnFinding(
            template_id=template_id,
            name=name,
            severity=severity,
            description=description,
            host=host,
            port=port,
            matched_at=matched_at,
            cve_id=cve_id,
            reference=references,
        ))

    return findings


def _extract_port_from_url(url: str) -> int | None:
    """Extrahiert den Port aus einer URL oder Host:Port Kombination."""
    if not url:
        return None

    # Format: "https://host:port/path" oder "host:port"
    try:
        if "://" in url:
            host_part = url.split("://", 1)[1].split("/", 1)[0]
        else:
            host_part = url.split("/", 1)[0]

        if ":" in host_part:
            port_str = host_part.rsplit(":", 1)[1]
            port = int(port_str)
            if 1 <= port <= 65535:
                return port
    except (ValueError, IndexError):
        pass

    return None

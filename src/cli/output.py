"""
Ausgabe-Hilfsfunktionen für die SentinelClaw CLI.

Formatiert Scan-Ergebnisse, Findings und Vergleiche
für die Terminal-Ausgabe (Markdown oder JSON).
"""

import json
from uuid import UUID

# Schweregrad-Icons für die Terminal-Ausgabe
SEVERITY_ICONS: dict[str, str] = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f535",
    "info": "\u26aa",
}


def print_result(result, output_format: str) -> None:
    """Gibt das Scan-Ergebnis formatiert aus."""
    if output_format == "json":
        data = {
            "target": result.target,
            "hosts": [
                {"address": h.address, "hostname": h.hostname}
                for h in result.discovered_hosts
            ],
            "open_ports": [
                {
                    "host": p.host,
                    "port": p.port,
                    "service": p.service,
                    "version": p.version,
                }
                for p in result.open_ports
            ],
            "vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity,
                    "cvss": v.cvss_score,
                    "cve": v.cve_id,
                    "host": v.host,
                }
                for v in result.vulnerabilities
            ],
            "summary": {
                "total_hosts": result.total_hosts,
                "total_open_ports": result.total_open_ports,
                "total_vulnerabilities": result.total_vulnerabilities,
                "severity_counts": result.severity_counts,
                "duration_seconds": round(result.scan_duration_seconds, 1),
                "tokens_used": result.total_tokens_used,
            },
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    # Markdown-Ausgabe
    print("=" * 60)
    print(f"  SCAN-ERGEBNIS: {result.target}")
    print("=" * 60)
    print()
    print(f"  Hosts:           {result.total_hosts}")
    print(f"  Offene Ports:    {result.total_open_ports}")
    print(f"  Vulnerabilities: {result.total_vulnerabilities}")
    print(f"  Dauer:           {result.scan_duration_seconds:.1f}s")
    print(f"  Tokens:          {result.total_tokens_used}")
    print()

    if result.open_ports:
        print("  --- Offene Ports ---")
        for p in result.open_ports:
            print(f"  {p.host}:{p.port}/{p.protocol}  {p.service}  {p.version}")
        print()

    if result.vulnerabilities:
        print("  --- Vulnerabilities ---")
        for v in sorted(result.vulnerabilities, key=lambda x: x.cvss_score, reverse=True):
            icon = SEVERITY_ICONS.get(v.severity.lower(), "\u26aa")
            cve = f" ({v.cve_id})" if v.cve_id else ""
            print(f"  {icon} {v.severity.upper():8s} {v.title}{cve}")
            if v.host:
                print(f"                    {v.host}:{v.port or '?'}")
        print()

    if result.agent_summary:
        print("  --- Agent-Zusammenfassung ---")
        # Nur die ersten 1000 Zeichen des Agent-Outputs
        summary = result.agent_summary[:1000]
        for line in summary.split("\n"):
            print(f"  {line}")
        print()

    if result.errors:
        print("  --- Fehler ---")
        for err in result.errors:
            print(f"  \u26a0 {err}")
        print()


def print_findings_json(findings: list) -> None:
    """Gibt Findings als JSON aus."""
    data = [
        {
            "id": str(f.id),
            "scan_job_id": str(f.scan_job_id),
            "title": f.title,
            "severity": f.severity.value,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "host": f.target_host,
            "port": f.target_port,
            "service": f.service,
            "description": f.description,
            "recommendation": f.recommendation,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2, ensure_ascii=False))


def print_findings_table(findings: list) -> None:
    """Gibt Findings als formatierte Tabelle aus."""
    print()
    print("  SentinelClaw \u2014 Findings")
    print("  " + "=" * 75)
    print()

    if not findings:
        print("  Keine Findings gefunden.")
        print()
        return

    # Tabellenkopf
    print(
        f"  {'Severity':<12} {'Title':<30} {'Host:Port':<22} "
        f"{'CVE':<16} {'CVSS':>5}"
    )
    print(f"  {'\u2500' * 85}")

    for finding in findings:
        icon = SEVERITY_ICONS.get(finding.severity.value, "\u26aa")
        sev_label = f"{icon} {finding.severity.value.upper()}"
        title = finding.title[:28] + ".." if len(finding.title) > 30 else finding.title
        port_str = str(finding.target_port) if finding.target_port else "\u2014"
        host_port = f"{finding.target_host}:{port_str}"
        cve = finding.cve_id or "\u2014"
        cvss = f"{finding.cvss_score:.1f}"
        print(f"  {sev_label:<14} {title:<30} {host_port:<22} {cve:<16} {cvss:>5}")

    print()
    print(f"  Gesamt: {len(findings)} Findings")
    print()


def print_compare_json(result, scan_id_a: UUID, scan_id_b: UUID) -> None:
    """Gibt den Vergleich als JSON aus."""
    data = {
        "scan_a": str(scan_id_a),
        "scan_b": str(scan_id_b),
        "new_findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "host": f.target_host,
                "port": f.target_port,
            }
            for f in result.new_findings
        ],
        "fixed_findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "host": f.target_host,
                "port": f.target_port,
            }
            for f in result.fixed_findings
        ],
        "unchanged_findings": len(result.unchanged_findings),
        "new_ports": result.new_ports,
        "closed_ports": result.closed_ports,
    }
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def print_compare_table(result) -> None:
    """Gibt den Scan-Vergleich als formatierte Tabelle aus."""
    print()
    print("  SentinelClaw \u2014 Scan-Vergleich")
    print("  " + "=" * 60)
    print()
    print(result.summary)
    print()

    # Neue Findings detailliert anzeigen
    if result.new_findings:
        print("  --- Neue Findings (nur in Scan B) ---")
        for f in sorted(result.new_findings, key=lambda x: x.cvss_score, reverse=True):
            icon = SEVERITY_ICONS.get(f.severity.value, "\u26aa")
            port_str = f":{f.target_port}" if f.target_port else ""
            cve_str = f" ({f.cve_id})" if f.cve_id else ""
            print(f"  + {icon} {f.severity.value.upper():8s} {f.title}")
            print(f"                      {f.target_host}{port_str}{cve_str}")
        print()

    # Behobene Findings detailliert anzeigen
    if result.fixed_findings:
        print("  --- Behobene Findings (nur in Scan A) ---")
        for f in sorted(result.fixed_findings, key=lambda x: x.cvss_score, reverse=True):
            icon = SEVERITY_ICONS.get(f.severity.value, "\u26aa")
            port_str = f":{f.target_port}" if f.target_port else ""
            print(f"  - {icon} {f.severity.value.upper():8s} {f.title}")
            print(f"                      {f.target_host}{port_str}")
        print()

    # Port-Aenderungen anzeigen
    if result.new_ports:
        print("  --- Neu ge\u00f6ffnete Ports ---")
        for p in result.new_ports:
            host = p.get("host_address", p.get("host", "?"))
            port = p.get("port", "?")
            svc = p.get("service", "")
            print(f"  + {host}:{port}/{p.get('protocol', 'tcp')}  {svc}")
        print()

    if result.closed_ports:
        print("  --- Geschlossene Ports ---")
        for p in result.closed_ports:
            host = p.get("host_address", p.get("host", "?"))
            port = p.get("port", "?")
            svc = p.get("service", "")
            print(f"  - {host}:{port}/{p.get('protocol', 'tcp')}  {svc}")
        print()

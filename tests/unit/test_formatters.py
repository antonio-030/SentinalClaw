"""
Unit-Tests für die Ausgabe-Formatierer.

Prüft format_as_json() und format_as_markdown() mit
verschiedenen ReconResult-Konfigurationen.
"""

import json

from src.agents.recon.result_types import (
    DiscoveredHost,
    OpenPort,
    ReconResult,
    VulnerabilityFinding,
)
from src.shared.formatters import format_as_json, format_as_markdown


def _minimal_result() -> ReconResult:
    """Erstellt ein minimales ReconResult ohne Findings."""
    return ReconResult(target="10.10.10.1")


def _result_mit_findings() -> ReconResult:
    """Erstellt ein ReconResult mit Hosts, Ports und Schwachstellen."""
    return ReconResult(
        target="192.168.1.0/24",
        discovered_hosts=[
            DiscoveredHost(address="192.168.1.1", hostname="router.local"),
            DiscoveredHost(address="192.168.1.10", hostname="server.local"),
        ],
        open_ports=[
            OpenPort(host="192.168.1.1", port=22, service="ssh", version="OpenSSH 8.9"),
            OpenPort(host="192.168.1.1", port=80, service="http", version="nginx 1.24"),
        ],
        vulnerabilities=[
            VulnerabilityFinding(
                title="SSH Weak Algorithms",
                severity="medium",
                cvss_score=5.3,
                host="192.168.1.1",
                port=22,
                cve_id="CVE-2023-12345",
                description="Schwache Algorithmen erlaubt",
                recommendation="Algorithmen aktualisieren",
            ),
            VulnerabilityFinding(
                title="Critical RCE",
                severity="critical",
                cvss_score=9.8,
                host="192.168.1.10",
                port=80,
            ),
        ],
        scan_duration_seconds=12.5,
        total_tokens_used=3500,
        phases_completed=3,
        agent_summary="Scan abgeschlossen.",
    )


def test_format_as_json_ist_valides_json():
    """format_as_json() gibt gültiges JSON zurück."""
    result = _minimal_result()
    output = format_as_json(result)
    parsed = json.loads(output)
    assert parsed["target"] == "10.10.10.1"


def test_format_as_json_enthaelt_alle_felder():
    """JSON-Ausgabe enthält Target, Hosts und Schwachstellen."""
    result = _result_mit_findings()
    parsed = json.loads(format_as_json(result))
    assert parsed["target"] == "192.168.1.0/24"
    assert len(parsed["discovered_hosts"]) == 2
    assert len(parsed["open_ports"]) == 2
    assert len(parsed["vulnerabilities"]) == 2


def test_format_as_json_sortierte_schluessel():
    """JSON-Schlüssel sind alphabetisch sortiert."""
    result = _minimal_result()
    output = format_as_json(result)
    parsed = json.loads(output)
    keys = list(parsed.keys())
    assert keys == sorted(keys)


def test_format_as_markdown_enthaelt_ueberschrift():
    """Markdown-Bericht enthält den Target-Namen als Überschrift."""
    result = _minimal_result()
    markdown = format_as_markdown(result)
    assert "# SentinelClaw Scan Report: 10.10.10.1" in markdown


def test_format_as_markdown_summary_tabelle():
    """Markdown enthält die Summary-Tabelle mit Metriken."""
    result = _result_mit_findings()
    markdown = format_as_markdown(result)
    assert "| Hosts discovered | 2 |" in markdown
    assert "| Open ports | 2 |" in markdown
    assert "| Vulnerabilities | 2 |" in markdown


def test_format_as_markdown_ports_tabelle():
    """Markdown enthält die Port-Tabelle mit Service und Version."""
    result = _result_mit_findings()
    markdown = format_as_markdown(result)
    assert "## Open Ports" in markdown
    assert "ssh" in markdown
    assert "OpenSSH 8.9" in markdown


def test_format_as_markdown_schwachstellen_sortiert():
    """Schwachstellen werden nach Schweregrad sortiert (critical zuerst)."""
    result = _result_mit_findings()
    markdown = format_as_markdown(result)
    # Critical RCE muss vor SSH Weak Algorithms stehen
    critical_pos = markdown.index("Critical RCE")
    medium_pos = markdown.index("SSH Weak Algorithms")
    assert critical_pos < medium_pos


def test_format_as_markdown_cve_in_ueberschrift():
    """CVE-IDs erscheinen in der Schwachstellen-Überschrift."""
    result = _result_mit_findings()
    markdown = format_as_markdown(result)
    assert "CVE-2023-12345" in markdown


def test_format_as_markdown_ohne_findings():
    """Leeres Ergebnis erzeugt Bericht ohne Vulnerability-Sektion."""
    result = _minimal_result()
    markdown = format_as_markdown(result)
    assert "## Vulnerabilities" not in markdown
    assert "## Open Ports" not in markdown


def test_format_as_markdown_agent_summary():
    """Agent-Summary wird im Bericht angezeigt."""
    result = _result_mit_findings()
    markdown = format_as_markdown(result)
    assert "## Agent Summary" in markdown
    assert "Scan abgeschlossen." in markdown


def test_format_as_markdown_footer():
    """Bericht endet mit generiertem Footer."""
    result = _minimal_result()
    markdown = format_as_markdown(result)
    assert "Generated by SentinelClaw" in markdown

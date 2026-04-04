"""
Unit-Tests fuer den Output-Parser (parse_output).

Prueft die korrekte Verarbeitung von nmap-XML, nuclei-JSONL,
Plaintext und den Fehlerfall bei unbekanntem Format.
"""

import json

import pytest

from src.mcp_server.tools.parse_output import parse_output

# ─── nmap XML ─────────────────────────────────────────────────────

# Minimales nmap-XML mit einem Host und zwei Ports
_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="testhost.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_returns_hosts():
    """nmap-Parser gibt Hosts zurueck."""
    result = parse_output(_NMAP_XML, "nmap_xml")
    assert result["format"] == "nmap_xml"
    assert len(result["data"]) == 1


def test_nmap_returns_ports():
    """nmap-Parser gibt Ports pro Host zurueck."""
    result = parse_output(_NMAP_XML, "nmap_xml")
    host = result["data"][0]
    assert len(host["ports"]) == 2
    port_ids = [p["port"] for p in host["ports"]]
    assert 22 in port_ids
    assert 80 in port_ids


def test_nmap_host_address():
    """nmap-Parser extrahiert die Host-Adresse korrekt."""
    result = parse_output(_NMAP_XML, "nmap_xml")
    assert result["data"][0]["address"] == "10.0.0.1"


def test_nmap_summary_contains_counts():
    """nmap-Summary enthaelt Host- und Port-Zaehler."""
    result = parse_output(_NMAP_XML, "nmap_xml")
    assert "1" in result["summary"]  # 1 Host
    assert "2" in result["summary"]  # 2 offene Ports


# ─── nuclei JSONL ────────────────────────────────────────────────

_NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "cve-2024-1234",
        "info": {
            "name": "SQL Injection",
            "severity": "critical",
            "description": "SQL Injection in Login",
            "classification": {"cve-id": ["CVE-2024-1234"]},
        },
        "host": "http://10.0.0.1",
        "matched-at": "http://10.0.0.1/login",
    }),
    json.dumps({
        "template-id": "info-disclosure",
        "info": {
            "name": "Server Header",
            "severity": "info",
            "description": "Server version disclosed",
            "classification": {},
        },
        "host": "http://10.0.0.1",
        "matched-at": "http://10.0.0.1/",
    }),
])


def test_nuclei_returns_findings():
    """nuclei-Parser gibt Findings zurueck."""
    result = parse_output(_NUCLEI_JSONL, "nuclei_jsonl")
    assert result["format"] == "nuclei_jsonl"
    assert len(result["data"]) == 2


def test_nuclei_finding_fields():
    """nuclei-Findings enthalten die erwarteten Felder."""
    result = parse_output(_NUCLEI_JSONL, "nuclei_jsonl")
    # Critical Finding steht zuerst (nach Sortierung)
    critical = result["data"][0]
    assert critical["name"] == "SQL Injection"
    assert critical["severity"] == "critical"
    assert critical["cve_id"] == "CVE-2024-1234"


def test_nuclei_severity_counts():
    """nuclei-Parser zaehlt Schweregrade korrekt."""
    result = parse_output(_NUCLEI_JSONL, "nuclei_jsonl")
    counts = result["severity_counts"]
    assert counts["critical"] == 1
    assert counts["info"] == 1


# ─── Plaintext ────────────────────────────────────────────────────

_PLAINTEXT = "Zeile eins\nZeile zwei\nZeile drei"


def test_plaintext_returns_lines():
    """Plaintext-Parser gibt einzelne Zeilen als Liste zurueck."""
    result = parse_output(_PLAINTEXT, "plaintext")
    assert result["format"] == "plaintext"
    assert len(result["data"]) == 3
    assert result["data"][0] == "Zeile eins"


def test_plaintext_summary():
    """Plaintext-Summary enthaelt die Zeilenanzahl."""
    result = parse_output(_PLAINTEXT, "plaintext")
    assert "3" in result["summary"]


# ─── Unbekanntes Format ──────────────────────────────────────────

def test_unknown_format_raises_value_error():
    """Unbekanntes Format wirft ValueError mit Fehlermeldung."""
    with pytest.raises(ValueError, match="Unbekanntes Format"):
        parse_output("irgendwas", "xml_invalid_format")

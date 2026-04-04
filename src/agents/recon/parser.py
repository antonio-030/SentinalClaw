"""
Parser für Recon-Agent-Output.

Wandelt den Textoutput des Claude-Agents in strukturierte
ReconResult-Objekte um. Erkennt verschiedene Formate:
nmap-Roh-Output, Markdown-Tabellen, Custom-Formate.

Ausgelagert aus recon/agent.py um die 300-Zeilen-Regel einzuhalten.
"""

import re

from src.agents.recon.result_types import (
    DiscoveredHost,
    OpenPort,
    ReconResult,
    VulnerabilityFinding,
)


# ─── Parser: Claude-Output → Strukturierte Ergebnisse ──────────────
#
# Claude gibt Scan-Ergebnisse in verschiedenen Formaten zurück:
# 1. Rohe nmap-Zeilen: "22/tcp open ssh OpenSSH 6.6.1p1"
# 2. Markdown-Tabellen: "| 22 | open | ssh | OpenSSH 6.6.1p1 |"
# 3. Formatierte Listen: "45.33.32.156:22/tcp ssh OpenSSH 6.6.1p1"
# 4. Custom-Format: "OPEN_PORTS: 45.33.32.156:22/tcp ssh ..."
# Der Parser muss alle erkennen.


def parse_agent_output(
    target: str,
    agent_output: str,
    duration: float,
    tokens: int,
    steps: int,
) -> ReconResult:
    """Parst den Textoutput des Claude-Agents in ein ReconResult.

    Erkennt Ports, Hosts und Vulnerabilities aus verschiedenen
    Textformaten die Claude zurückgeben kann.
    """
    result = ReconResult(
        target=target,
        agent_summary=agent_output,
        scan_duration_seconds=duration,
        total_tokens_used=tokens,
        phases_completed=steps,
    )

    if not agent_output:
        result.errors.append("Agent hat keine Ausgabe geliefert")
        return result

    # Alle Parser auf den Text loslassen
    _extract_hosts(agent_output, target, result)
    _extract_ports(agent_output, target, result)
    _extract_vulnerabilities(agent_output, result)

    return result


def _extract_hosts(text: str, default_target: str, result: ReconResult) -> None:
    """Extrahiert Host-Informationen aus dem Agent-Output."""
    seen: set[str] = set()

    # Pattern 1: "Nmap scan report for hostname (IP)"
    for match in re.finditer(
        r"(?:Nmap scan report for|scan report for)\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)",
        text, re.IGNORECASE,
    ):
        ip = match.group(2)
        if ip not in seen:
            seen.add(ip)
            result.discovered_hosts.append(DiscoveredHost(
                address=ip, hostname=match.group(1),
            ))

    # Pattern 2: "Nmap scan report for IP" (ohne Hostname)
    for match in re.finditer(
        r"(?:Nmap scan report for|scan report for)\s+(\d+\.\d+\.\d+\.\d+)",
        text, re.IGNORECASE,
    ):
        ip = match.group(1)
        if ip not in seen:
            seen.add(ip)
            result.discovered_hosts.append(DiscoveredHost(address=ip))

    # Pattern 3: "Host is up" mit IP davor
    for match in re.finditer(
        r"(\d+\.\d+\.\d+\.\d+).*?(?:Host is up|host is up)",
        text,
    ):
        ip = match.group(1)
        if ip not in seen:
            seen.add(ip)
            result.discovered_hosts.append(DiscoveredHost(address=ip))

    # Pattern 4: "HOSTS: N" oder "Discovered Hosts" Bereich mit IPs
    for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", text):
        ip = match.group(1)
        # Nur plausible IPs (nicht 0.0.0.0, nicht 255.255.255.255)
        parts = ip.split(".")
        if all(0 < int(p) < 255 for p in parts) and ip not in seen:
            # Nur wenn nah an einem Host-Kontext (nmap, scan, host, target)
            start = max(0, match.start() - 100)
            context = text[start:match.end() + 50].lower()
            if any(kw in context for kw in ["host", "scan", "nmap", "target", "address", "ip"]):
                seen.add(ip)
                result.discovered_hosts.append(DiscoveredHost(address=ip))


def _extract_ports(text: str, default_target: str, result: ReconResult) -> None:
    """Extrahiert Port-Informationen aus dem Agent-Output.

    Erkennt verschiedene Formate:
    - nmap raw:       22/tcp   open  ssh     OpenSSH 6.6.1p1
    - Markdown table: | 22 | open | ssh | OpenSSH 6.6.1p1 |
    - Custom:         45.33.32.156:22/tcp ssh OpenSSH 6.6.1p1
    - OPEN_PORTS:     host:port/proto service version
    """
    seen: set[tuple[str, int]] = set()

    # Versuche den Host aus dem Kontext zu bestimmen
    # (letzter "scan report for" Host)
    current_host = default_target
    host_match = re.search(
        r"(?:scan report for)\s+\S+\s+\((\d+\.\d+\.\d+\.\d+)\)", text
    )
    if host_match:
        current_host = host_match.group(1)
    else:
        host_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
        if host_match:
            current_host = host_match.group(1)

    # Pattern 1: Rohe nmap-Ausgabe "PORT/PROTO STATE SERVICE VERSION"
    for match in re.finditer(
        r"(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*?)(?:\n|$)",
        text,
    ):
        port = int(match.group(1))
        proto = match.group(2)
        state = match.group(3)
        service = match.group(4)
        version = match.group(5).strip()

        key = (current_host, port)
        if key not in seen and state == "open":
            seen.add(key)
            result.open_ports.append(OpenPort(
                host=current_host, port=port, protocol=proto,
                state=state, service=service, version=version,
            ))

    # Pattern 2: IP:PORT/PROTO format "45.33.32.156:22/tcp ssh OpenSSH"
    for match in re.finditer(
        r"(\d+\.\d+\.\d+\.\d+):(\d{1,5})/(tcp|udp)\s+(\S+)\s*(.*?)(?:\n|$)",
        text,
    ):
        host = match.group(1)
        port = int(match.group(2))
        service = match.group(4)
        version = match.group(5).strip()

        key = (host, port)
        if key not in seen:
            seen.add(key)
            result.open_ports.append(OpenPort(
                host=host, port=port, protocol=match.group(3),
                state="open", service=service, version=version,
            ))

    # Pattern 3: Markdown-Tabelle "| Port | Status | Service | Version |"
    for match in re.finditer(
        r"\|\s*(\d{1,5})\s*\|\s*\**(\w+)\**\s*\|\s*(?:tcp|TCP)?\s*\|?\s*(\w[\w\-]*)\s*\|\s*(.*?)\s*\|",
        text,
    ):
        port = int(match.group(1))
        state = match.group(2).lower().strip("*")
        service = match.group(3).strip()
        version = match.group(4).strip().strip("|").strip()

        key = (current_host, port)
        if key not in seen and state == "open":
            seen.add(key)
            result.open_ports.append(OpenPort(
                host=current_host, port=port, protocol="tcp",
                state="open", service=service, version=version,
            ))

    # Pattern 4: Einfache Tabelle "| 22 | ssh | OpenSSH 6.6.1p1 |"
    for match in re.finditer(
        r"\|\s*(\d{1,5})\s*\|\s*(\w[\w\-]*)\s*\|\s*(.*?)\s*\|",
        text,
    ):
        port = int(match.group(1))
        service = match.group(2).strip()
        version = match.group(3).strip().strip("|").strip()

        # Überspringe Tabellen-Header und Trennzeilen
        if service.lower() in ("port", "dienst", "service", "---", "status"):
            continue

        key = (current_host, port)
        if key not in seen:
            seen.add(key)
            result.open_ports.append(OpenPort(
                host=current_host, port=port, protocol="tcp",
                state="open", service=service, version=version,
            ))

    # Pattern 5: "Port N (SERVICE)" oder "port N/tcp SERVICE"
    for match in re.finditer(
        r"[Pp]ort\s+(\d{1,5})(?:/tcp)?\s*(?:\((\w+)\)|:\s*(\w+))",
        text,
    ):
        port = int(match.group(1))
        service = match.group(2) or match.group(3) or ""

        key = (current_host, port)
        if key not in seen:
            seen.add(key)
            result.open_ports.append(OpenPort(
                host=current_host, port=port, protocol="tcp",
                state="open", service=service.lower(),
            ))


def _extract_vulnerabilities(text: str, result: ReconResult) -> None:
    """Extrahiert Vulnerability-Findings aus dem Agent-Output.

    Erkennt:
    - CRITICAL/HIGH/MEDIUM/LOW Keywords mit Beschreibung
    - CVE-IDs (CVE-YYYY-NNNNN)
    - nuclei-artige Ausgaben [severity] [template-id] ...
    - Markdown mit Icons
    """
    # Alle CVE-IDs sammeln die im Text vorkommen
    cve_ids = set(re.findall(r"(CVE-\d{4}-\d{4,})", text, re.IGNORECASE))

    # Pattern 1: Severity-Keyword gefolgt von Beschreibung
    severity_pattern = re.compile(
        r"(?:🔴|🟠|🟡|🔵|⚪)?\s*"
        r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)"
        r"[\s:—\-]+(.+?)(?:\n|$)",
        re.IGNORECASE | re.MULTILINE,
    )

    seen_titles: set[str] = set()

    for match in severity_pattern.finditer(text):
        severity = match.group(1).lower()
        description = match.group(2).strip()

        # Bereinigen: Markdown-Formatierung entfernen
        title = re.sub(r"\*+", "", description)
        title = re.sub(r"\[.*?\]", "", title)
        title = title.strip("- —:").strip()

        if not title or len(title) < 5:
            continue

        # Kürzen auf maximal 120 Zeichen
        title = title[:120]

        # Duplikate vermeiden
        title_key = title.lower()[:50]
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)

        # CVE zuordnen wenn im gleichen Kontext
        cve_id = None
        cve_in_line = re.search(r"(CVE-\d{4}-\d{4,})", description, re.IGNORECASE)
        if cve_in_line:
            cve_id = cve_in_line.group(1).upper()

        # CVSS-Score schätzen basierend auf Severity
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        cvss = cvss_map.get(severity, 0.0)

        result.vulnerabilities.append(VulnerabilityFinding(
            title=title,
            severity=severity,
            cvss_score=cvss,
            cve_id=cve_id,
        ))

    # Für CVEs die noch keinem Finding zugeordnet sind, eigene Findings erstellen
    assigned_cves = {v.cve_id for v in result.vulnerabilities if v.cve_id}
    for cve in cve_ids:
        cve_upper = cve.upper()
        if cve_upper not in assigned_cves:
            # Kontext um die CVE-Referenz herum extrahieren
            cve_match = re.search(re.escape(cve) + r".*?(?:\n|$)", text, re.IGNORECASE)
            context = cve_match.group(0).strip() if cve_match else cve_upper

            result.vulnerabilities.append(VulnerabilityFinding(
                title=f"Bekannte Schwachstelle: {cve_upper}",
                severity="high",
                cvss_score=7.0,
                cve_id=cve_upper,
                description=context[:200],
            ))

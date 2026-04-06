"""
Kuratierte Registry aller Security-Tools die in der OpenShell-Sandbox
installiert werden können.

NUR diese Tools können über die Web-UI installiert werden —
keine beliebigen Pakete. Jedes Tool hat einen definierten
Installationsbefehl und einen Check-Befehl zur Verifikation.

Installation erfolgt via pip (die Sandbox hat kein root/sudo).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentToolDefinition:
    """Definition eines installierbaren Security-Tools."""

    name: str
    display_name: str
    description: str
    category: str  # reconnaissance | vulnerability | analysis | utility
    install_command: str
    uninstall_command: str
    check_command: str
    install_timeout: int = 120


# Kuratierte Tool-Registry — NUR diese Tools sind erlaubt
AGENT_TOOL_REGISTRY: dict[str, AgentToolDefinition] = {
    tool.name: tool for tool in [
        AgentToolDefinition(
            name="sqlmap",
            display_name="sqlmap",
            description="Automatisierte SQL-Injection-Erkennung und -Exploitation",
            category="vulnerability",
            install_command="pip3 install sqlmap",
            uninstall_command="pip3 uninstall -y sqlmap",
            check_command="sqlmap --version",
        ),
        AgentToolDefinition(
            name="httpie",
            display_name="HTTPie",
            description="Benutzerfreundlicher HTTP-Client für API-Tests und Header-Analyse",
            category="utility",
            install_command="pip3 install httpie",
            uninstall_command="pip3 uninstall -y httpie",
            check_command="http --version",
        ),
        AgentToolDefinition(
            name="python-nmap",
            display_name="python-nmap",
            description="Python-Wrapper für Nmap — Netzwerk-Scanning per Script",
            category="reconnaissance",
            install_command="pip3 install python-nmap",
            uninstall_command="pip3 uninstall -y python-nmap",
            check_command="python3 -c 'import nmap; print(nmap.__version__)'",
        ),
        AgentToolDefinition(
            name="dnspython",
            display_name="dnspython",
            description="Erweiterte DNS-Abfragen — Zone-Transfers, DNSSEC, alle Record-Typen",
            category="reconnaissance",
            install_command="pip3 install dnspython",
            uninstall_command="pip3 uninstall -y dnspython",
            check_command="python3 -c 'import dns; print(dns.version.version)'",
        ),
        AgentToolDefinition(
            name="shodan",
            display_name="Shodan CLI",
            description="Shodan-Suchmaschine für öffentlich erreichbare Geräte und Services",
            category="reconnaissance",
            install_command="pip3 install shodan",
            uninstall_command="pip3 uninstall -y shodan",
            check_command="python3 -c 'import shodan; print(shodan.__version__)'",
        ),
        AgentToolDefinition(
            name="censys",
            display_name="Censys",
            description="Internet-weite Scan-Datenbank — Zertifikate, Hosts, Services",
            category="reconnaissance",
            install_command="pip3 install censys",
            uninstall_command="pip3 uninstall -y censys",
            check_command="python3 -c 'import censys; print(censys.__version__)'",
        ),
        AgentToolDefinition(
            name="requests",
            display_name="Requests",
            description="HTTP-Library für Web-Scraping, API-Tests und Redirect-Analyse",
            category="utility",
            install_command="pip3 install requests",
            uninstall_command="pip3 uninstall -y requests",
            check_command="python3 -c 'import requests; print(requests.__version__)'",
        ),
        AgentToolDefinition(
            name="beautifulsoup4",
            display_name="BeautifulSoup",
            description="HTML/XML-Parser für Web-Content-Analyse und Informationsextraktion",
            category="analysis",
            install_command="pip3 install beautifulsoup4 lxml",
            uninstall_command="pip3 uninstall -y beautifulsoup4 lxml",
            check_command="python3 -c 'import bs4; print(bs4.__version__)'",
        ),
    ]
}

# Basis-Tools die in der Sandbox vorinstalliert sind (nicht installierbar)
PREINSTALLED_TOOLS = frozenset({"curl", "dig", "whois"})


def get_tool(name: str) -> AgentToolDefinition | None:
    """Gibt die Tool-Definition zurück oder None wenn unbekannt."""
    return AGENT_TOOL_REGISTRY.get(name)


def get_all_tool_names() -> frozenset[str]:
    """Alle bekannten Tool-Namen (Registry + vorinstalliert)."""
    return PREINSTALLED_TOOLS | frozenset(AGENT_TOOL_REGISTRY.keys())

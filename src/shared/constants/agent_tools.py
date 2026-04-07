"""
Kuratierte Registry aller Security-Tools für die OpenShell-Sandbox.

NUR diese Tools können über die Web-UI installiert werden.
Stufen: 0=Passiv, 1=Aktiv, 2=Vulnerability, 3=Exploitation

Tool-Definitionen für Stufe 2-3 und Analyse-Utilities befinden sich
in agent_tools_advanced.py und werden hier zur Gesamtregistry zusammengeführt.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentToolDefinition:
    """Definition eines installierbaren Security-Tools."""

    name: str
    display_name: str
    description: str
    category: str  # reconnaissance | vulnerability | analysis | exploitation | utility
    escalation_level: int  # 0-3, korreliert mit Scope-Validator
    install_command: str
    uninstall_command: str
    check_command: str
    install_timeout: int = 120


# --- Stufe 0: Passive Reconnaissance (OSINT) ----------------------------

_RECON_PASSIVE = [
    AgentToolDefinition(
        name="shodan",
        display_name="Shodan CLI",
        description="Suchmaschine für öffentlich erreichbare Geräte und Services",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install shodan",
        uninstall_command="pip3 uninstall -y shodan",
        check_command="python3 -c 'import shodan; print(shodan.__version__)'",
    ),
    AgentToolDefinition(
        name="censys",
        display_name="Censys",
        description="Internet-weite Scan-Datenbank -- Zertifikate, Hosts, Services",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install censys",
        uninstall_command="pip3 uninstall -y censys",
        check_command="python3 -c 'import censys; print(censys.__version__)'",
    ),
    AgentToolDefinition(
        name="theharvester",
        display_name="theHarvester",
        description="E-Mail, Subdomain und Host-Enumeration aus öffentlichen Quellen",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install theHarvester",
        uninstall_command="pip3 uninstall -y theHarvester",
        check_command="theHarvester --help 2>&1 | head -1",
        install_timeout=180,
    ),
    AgentToolDefinition(
        name="sublist3r",
        display_name="Sublist3r",
        description="Subdomain-Enumeration über Suchmaschinen und DNS-Dienste",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install sublist3r",
        uninstall_command="pip3 uninstall -y sublist3r",
        check_command="python3 -c 'import sublist3r; print(\"ok\")'",
    ),
    AgentToolDefinition(
        name="dnspython",
        display_name="dnspython",
        description="Erweiterte DNS-Abfragen -- Zone-Transfers, DNSSEC, alle Record-Typen",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install dnspython",
        uninstall_command="pip3 uninstall -y dnspython",
        check_command="python3 -c 'import dns; print(dns.version.version)'",
    ),
    AgentToolDefinition(
        name="python-whois",
        display_name="python-whois",
        description="Erweiterte WHOIS-Abfragen mit strukturiertem Parsing",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install python-whois",
        uninstall_command="pip3 uninstall -y python-whois",
        check_command="python3 -c 'import whois; print(\"ok\")'",
    ),
    AgentToolDefinition(
        name="holehe",
        display_name="Holehe",
        description="E-Mail-OSINT -- prüft ob eine Adresse bei Diensten registriert ist",
        category="reconnaissance", escalation_level=0,
        install_command="pip3 install holehe",
        uninstall_command="pip3 uninstall -y holehe",
        check_command="holehe --help 2>&1 | head -1",
    ),
]

# --- Stufe 1: Aktive Reconnaissance -------------------------------------

_RECON_ACTIVE = [
    AgentToolDefinition(
        name="wafw00f",
        display_name="wafw00f",
        description="Web Application Firewall Erkennung und Fingerprinting",
        category="reconnaissance", escalation_level=1,
        install_command="pip3 install wafw00f",
        uninstall_command="pip3 uninstall -y wafw00f",
        check_command="wafw00f --version 2>&1 | head -1",
    ),
    AgentToolDefinition(
        name="sslyze",
        display_name="SSLyze",
        description="TLS/SSL-Konfigurationsanalyse -- Cipher-Suites, Zertifikate, Schwächen",
        category="reconnaissance", escalation_level=1,
        install_command="pip3 install sslyze",
        uninstall_command="pip3 uninstall -y sslyze",
        check_command="python3 -c 'import sslyze; print(sslyze.__version__)'",
        install_timeout=180,
    ),
    AgentToolDefinition(
        name="arjun",
        display_name="Arjun",
        description="HTTP-Parameter-Discovery -- findet versteckte GET/POST-Parameter",
        category="reconnaissance", escalation_level=1,
        install_command="pip3 install arjun",
        uninstall_command="pip3 uninstall -y arjun",
        check_command="arjun --help 2>&1 | head -1",
    ),
    AgentToolDefinition(
        name="dirsearch",
        display_name="dirsearch",
        description="Verzeichnis- und Datei-Bruteforce auf Webservern",
        category="reconnaissance", escalation_level=1,
        install_command="pip3 install dirsearch",
        uninstall_command="pip3 uninstall -y dirsearch",
        check_command="dirsearch --version 2>&1 | head -1",
    ),
    AgentToolDefinition(
        name="httpie",
        display_name="HTTPie",
        description="HTTP-Client für API-Tests, Header-Analyse und Redirect-Verfolgung",
        category="utility", escalation_level=1,
        install_command="pip3 install httpie",
        uninstall_command="pip3 uninstall -y httpie",
        check_command="http --version",
    ),
    AgentToolDefinition(
        name="paramiko",
        display_name="Paramiko",
        description="SSH-Protokoll-Library -- Verbindungstests, Cipher-Analyse, Banner-Grabbing",
        category="utility", escalation_level=1,
        install_command="pip3 install paramiko",
        uninstall_command="pip3 uninstall -y paramiko",
        check_command="python3 -c 'import paramiko; print(paramiko.__version__)'",
    ),
]


# --- Gesamtregistry (importiert Stufe 2-3 und Analyse aus advanced-Modul) ---

def _build_registry() -> dict[str, AgentToolDefinition]:
    """Baut die vollständige Tool-Registry aus allen Teilmodulen zusammen."""
    # Zirkuläre Imports vermeiden: Import erst zur Laufzeit
    from src.shared.constants.agent_tools_advanced import (
        ANALYSIS,
        EXPLOITATION,
        VULN_ASSESSMENT,
    )
    return {
        tool.name: tool
        for tool in (
            _RECON_PASSIVE
            + _RECON_ACTIVE
            + VULN_ASSESSMENT
            + EXPLOITATION
            + ANALYSIS
        )
    }


AGENT_TOOL_REGISTRY: dict[str, AgentToolDefinition] = _build_registry()

# Basis-Tools die im Sandbox-Container vorinstalliert sind
PREINSTALLED_TOOLS = frozenset({
    # Stufe 0: Passiv
    "curl", "dig", "whois", "jq", "wget",
    # Stufe 1: Aktive Scans
    "nmap", "dirb", "sslscan", "netcat", "socat",
    # Stufe 2: Vulnerability Assessment
    "nuclei", "nikto",
    # Stufe 3: Exploitation
    "hydra", "john", "hashcat", "msfconsole", "msfvenom",
    # Stufe 4: Post-Exploitation
    "linpeas", "chisel", "pwncat-cs",
    # Python + vorinstallierte Libraries
    "python3", "impacket", "paramiko",
})


def get_tool(name: str) -> AgentToolDefinition | None:
    """Gibt die Tool-Definition zurück oder None wenn unbekannt."""
    return AGENT_TOOL_REGISTRY.get(name)


def get_all_tool_names() -> frozenset[str]:
    """Alle bekannten Tool-Namen (Registry + vorinstalliert)."""
    return PREINSTALLED_TOOLS | frozenset(AGENT_TOOL_REGISTRY.keys())


def get_tools_by_escalation(max_level: int) -> list[AgentToolDefinition]:
    """Gibt alle Tools zurück die bis zur angegebenen Eskalationsstufe erlaubt sind."""
    return [t for t in AGENT_TOOL_REGISTRY.values() if t.escalation_level <= max_level]

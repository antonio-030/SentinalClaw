"""
Erweiterte Security-Tools: Stufe 2 (Vulnerability Assessment),
Stufe 3 (Exploitation) und Analyse-Utilities.

Wird von agent_tools.py importiert und in die Gesamtregistry integriert.
"""

from src.shared.constants.agent_tools import AgentToolDefinition

# --- Stufe 2: Vulnerability Assessment ----------------------------------

VULN_ASSESSMENT = [
    AgentToolDefinition(
        name="wapiti",
        display_name="Wapiti",
        description="Web-Vulnerability-Scanner -- XSS, SQLi, SSRF, Command Injection",
        category="vulnerability", escalation_level=2,
        install_command="pip3 install wapiti3",
        uninstall_command="pip3 uninstall -y wapiti3",
        check_command="wapiti --version 2>&1 | head -1",
        install_timeout=180,
    ),
    AgentToolDefinition(
        name="python-nmap",
        display_name="python-nmap",
        description="Python-Wrapper für Nmap -- Netzwerk-Scanning per Script",
        category="vulnerability", escalation_level=2,
        install_command="pip3 install python-nmap",
        uninstall_command="pip3 uninstall -y python-nmap",
        check_command="python3 -c 'import nmap; print(nmap.__version__)'",
    ),
    AgentToolDefinition(
        name="pyjwt",
        display_name="PyJWT",
        description="JWT-Token-Analyse -- Dekodierung, Signatur-Prüfung, Schwachstellen-Check",
        category="vulnerability", escalation_level=2,
        install_command="pip3 install pyjwt[crypto]",
        uninstall_command="pip3 uninstall -y pyjwt",
        check_command="python3 -c 'import jwt; print(jwt.__version__)'",
    ),
    AgentToolDefinition(
        name="tlsx",
        display_name="tlsx (Python)",
        description="TLS-Grabber -- extrahiert Zertifikatsketten, Cipher, JARM-Fingerprints",
        category="vulnerability", escalation_level=2,
        install_command="pip3 install tlsx",
        uninstall_command="pip3 uninstall -y tlsx",
        check_command="python3 -c 'import tlsx; print(\"ok\")'",
    ),
]

# --- Stufe 3: Exploitation (erfordert Genehmigung) ----------------------

EXPLOITATION = [
    AgentToolDefinition(
        name="sqlmap",
        display_name="sqlmap",
        description="Automatisierte SQL-Injection-Erkennung und -Exploitation",
        category="exploitation", escalation_level=3,
        install_command="pip3 install sqlmap",
        uninstall_command="pip3 uninstall -y sqlmap",
        check_command="sqlmap --version",
    ),
    AgentToolDefinition(
        name="impacket",
        display_name="Impacket",
        description="Netzwerk-Protokoll-Toolkit -- SMB, LDAP, Kerberos, NTLM-Angriffe",
        category="exploitation", escalation_level=3,
        install_command="pip3 install impacket",
        uninstall_command="pip3 uninstall -y impacket",
        check_command="python3 -c 'import impacket; print(impacket.version.VER_MINOR)'",
        install_timeout=180,
    ),
    AgentToolDefinition(
        name="crackmapexec",
        display_name="CrackMapExec",
        description="Post-Exploitation-Framework -- SMB, WinRM, SSH, LDAP, MSSQL",
        category="exploitation", escalation_level=3,
        install_command="pip3 install crackmapexec",
        uninstall_command="pip3 uninstall -y crackmapexec",
        check_command="crackmapexec --version 2>&1 | head -1",
        install_timeout=240,
    ),
]

# --- Analyse-Utilities --------------------------------------------------

ANALYSIS = [
    AgentToolDefinition(
        name="requests",
        display_name="Requests",
        description="HTTP-Library für Web-Scraping, API-Tests und Redirect-Analyse",
        category="utility", escalation_level=0,
        install_command="pip3 install requests",
        uninstall_command="pip3 uninstall -y requests",
        check_command="python3 -c 'import requests; print(requests.__version__)'",
    ),
    AgentToolDefinition(
        name="beautifulsoup4",
        display_name="BeautifulSoup",
        description="HTML/XML-Parser für Web-Content-Analyse und Informationsextraktion",
        category="analysis", escalation_level=0,
        install_command="pip3 install beautifulsoup4 lxml",
        uninstall_command="pip3 uninstall -y beautifulsoup4 lxml",
        check_command="python3 -c 'import bs4; print(bs4.__version__)'",
    ),
    AgentToolDefinition(
        name="pycryptodome",
        display_name="PyCryptodome",
        description="Kryptographie-Library -- Hash-Analyse, Cipher-Tests, Key-Generierung",
        category="analysis", escalation_level=1,
        install_command="pip3 install pycryptodome",
        uninstall_command="pip3 uninstall -y pycryptodome",
        check_command="python3 -c 'import Crypto; print(Crypto.__version__)'",
    ),
    AgentToolDefinition(
        name="jq",
        display_name="jq (Python)",
        description="JSON-Prozessor für strukturierte API-Response-Analyse",
        category="utility", escalation_level=0,
        install_command="pip3 install jq",
        uninstall_command="pip3 uninstall -y jq",
        check_command="python3 -c 'import jq; print(\"ok\")'",
    ),
]

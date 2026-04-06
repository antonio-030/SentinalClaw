"""
Zentrale Default-Werte für SentinelClaw.

Alle konfigurierbaren Werte haben hier einen Default.
Im produktiven Betrieb werden sie über Umgebungsvariablen
oder die Web-UI überschrieben.
"""

# --- LLM-Provider ---
DEFAULT_LLM_PROVIDER = "claude"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-20250514"
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEFAULT_LLM_MAX_TOKENS_PER_SCAN = 50_000
DEFAULT_LLM_MONTHLY_TOKEN_LIMIT = 1_000_000

# --- MCP-Server ---
DEFAULT_MCP_PORT = 8080
DEFAULT_MCP_HOST = "0.0.0.0"

# --- Scan-Konfiguration ---
DEFAULT_SANDBOX_TIMEOUT_SECONDS = 300
DEFAULT_MAX_CONCURRENT_SCANS = 1
DEFAULT_SCAN_PORT_RANGE = "1-1000"

# --- Sandbox / Docker ---
DEFAULT_SANDBOX_IMAGE = "sentinelclaw/sandbox:latest"
DEFAULT_SANDBOX_MEMORY_LIMIT = "2g"
DEFAULT_SANDBOX_CPU_LIMIT = 2.0
DEFAULT_SANDBOX_PID_LIMIT = 256

# --- Logging ---
DEFAULT_LOG_LEVEL = "INFO"

# --- Sicherheit ---
# Nur diese Binaries dürfen im Sandbox-Container ausgeführt werden
ALLOWED_SANDBOX_BINARIES = frozenset({"nmap", "nuclei", "curl", "dig", "whois"})

# --- Agent Tool-Bridge ---
# Maximale Tool-Aufrufe pro Chat-Turn (verhindert Endlosschleifen)
MAX_TOOL_CALLS_PER_TURN = 10

# Maximale Zeichenlaenge pro Tool-Ergebnis
MAX_TOOL_OUTPUT_LENGTH = 15_000

# Standard-Timeouts pro Tool in Sekunden
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap": 120,
    "nuclei": 180,
    "curl": 30,
    "dig": 15,
    "whois": 15,
}

# Nmap-Flags die erlaubt sind (Allowlist statt Blocklist)
ALLOWED_NMAP_FLAGS = frozenset({
    "-sn", "-sS", "-sT", "-sV", "-sC", "-sU",
    "-O", "-A", "-Pn", "-p", "-oX", "-oN", "-oG",
    "--top-ports", "--open", "--reason", "--version-intensity",
    "-T0", "-T1", "-T2", "-T3", "-T4",
})

# Nuclei-Template-Kategorien die erlaubt sind
ALLOWED_NUCLEI_TEMPLATES = frozenset({
    "cves", "vulnerabilities", "misconfiguration",
    "default-logins", "exposures", "technologies",
})

# IP-Ranges die standardmäßig NICHT gescannt werden dürfen
# (können in der Konfiguration explizit freigeschaltet werden)
FORBIDDEN_IP_RANGES = [
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
]

# Regex-Pattern für Secret-Erkennung im Logging
SECRET_PATTERNS = [
    r"sk-ant-[a-zA-Z0-9_-]+",
    r"sk-proj-[a-zA-Z0-9_-]+",
    r"api[_-]?key[:\s=]+\S+",
    r"password[:\s=]+\S+",
    r"-----BEGIN.*PRIVATE KEY-----",
]

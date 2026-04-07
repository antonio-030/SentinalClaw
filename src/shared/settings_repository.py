"""
Repository für systemweite Einstellungen.

Speichert und lädt Konfigurationswerte aus der system_settings-Tabelle.
Idempotentes Seeding sorgt dafür, dass Defaults beim Start vorhanden sind.
"""

from datetime import UTC, datetime

import aiosqlite

from src.shared.constants.defaults import (
    DEFAULT_LLM_MAX_TOKENS_PER_SCAN,
    DEFAULT_LLM_MONTHLY_TOKEN_LIMIT,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_MAX_CONCURRENT_SCANS,
    DEFAULT_SANDBOX_CPU_LIMIT,
    DEFAULT_SANDBOX_MEMORY_LIMIT,
    DEFAULT_SANDBOX_PID_LIMIT,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
    DEFAULT_SCAN_PORT_RANGE,
    MAX_TOOL_CALLS_PER_TURN,
    MAX_TOOL_OUTPUT_LENGTH,
    TOOL_TIMEOUTS,
)
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


# Definiert alle Einstellungen mit Kategorie, Typ, Label und Default
_SEED_DEFINITIONS: list[dict] = [
    # --- Tool-Timeouts ---
    {"key": "timeout_nmap", "value": str(TOOL_TIMEOUTS["nmap"]),
     "category": "tool_timeouts", "value_type": "int",
     "label": "Nmap Timeout (s)", "description": "Maximale Laufzeit für Nmap-Scans"},
    {"key": "timeout_nuclei", "value": str(TOOL_TIMEOUTS["nuclei"]),
     "category": "tool_timeouts", "value_type": "int",
     "label": "Nuclei Timeout (s)", "description": "Maximale Laufzeit für Nuclei-Scans"},
    {"key": "timeout_curl", "value": str(TOOL_TIMEOUTS["curl"]),
     "category": "tool_timeouts", "value_type": "int",
     "label": "cURL Timeout (s)", "description": "Maximale Laufzeit für cURL-Anfragen"},
    {"key": "timeout_dig", "value": str(TOOL_TIMEOUTS["dig"]),
     "category": "tool_timeouts", "value_type": "int",
     "label": "dig Timeout (s)", "description": "Maximale Laufzeit für DNS-Abfragen"},
    {"key": "timeout_whois", "value": str(TOOL_TIMEOUTS["whois"]),
     "category": "tool_timeouts", "value_type": "int",
     "label": "whois Timeout (s)", "description": "Maximale Laufzeit für WHOIS-Abfragen"},
    # --- Agent ---
    {"key": "max_tool_calls_per_turn", "value": str(MAX_TOOL_CALLS_PER_TURN),
     "category": "agent", "value_type": "int",
     "label": "Max Tool-Aufrufe pro Turn", "description": "Verhindert Endlosschleifen"},
    {"key": "max_tool_output_length", "value": str(MAX_TOOL_OUTPUT_LENGTH),
     "category": "agent", "value_type": "int",
     "label": "Max Tool-Output (Zeichen)",
     "description": "Maximale Zeichenlänge pro Tool-Ergebnis"},
    # --- Sandbox ---
    {"key": "sandbox_memory_limit", "value": DEFAULT_SANDBOX_MEMORY_LIMIT,
     "category": "sandbox", "value_type": "string",
     "label": "Memory-Limit", "description": "Docker-Memory-Limit (z.B. 2g, 512m)"},
    {"key": "sandbox_cpu_limit", "value": str(DEFAULT_SANDBOX_CPU_LIMIT),
     "category": "sandbox", "value_type": "float",
     "label": "CPU-Limit", "description": "Maximale CPU-Kerne (0.5 – 8.0)"},
    {"key": "sandbox_pid_limit", "value": str(DEFAULT_SANDBOX_PID_LIMIT),
     "category": "sandbox", "value_type": "int",
     "label": "PID-Limit", "description": "Maximale Prozessanzahl im Container"},
    {"key": "sandbox_timeout", "value": str(DEFAULT_SANDBOX_TIMEOUT_SECONDS),
     "category": "sandbox", "value_type": "int",
     "label": "Sandbox Timeout (s)", "description": "Maximale Laufzeit des Containers"},
    # --- Scan ---
    {"key": "max_concurrent_scans", "value": str(DEFAULT_MAX_CONCURRENT_SCANS),
     "category": "scan", "value_type": "int",
     "label": "Max parallele Scans", "description": "Gleichzeitig laufende Scans"},
    {"key": "default_port_range", "value": DEFAULT_SCAN_PORT_RANGE,
     "category": "scan", "value_type": "string",
     "label": "Standard-Portbereich", "description": "Standard-Ports wenn kein Profil gewählt"},
    # --- LLM ---
    {"key": "llm_timeout", "value": str(DEFAULT_LLM_TIMEOUT_SECONDS),
     "category": "llm", "value_type": "int",
     "label": "LLM Timeout (s)", "description": "Maximale Wartezeit auf LLM-Antwort"},
    {"key": "llm_max_tokens_per_scan", "value": str(DEFAULT_LLM_MAX_TOKENS_PER_SCAN),
     "category": "llm", "value_type": "int",
     "label": "Max Tokens pro Scan", "description": "Token-Budget pro Scan-Durchlauf"},
    {"key": "llm_monthly_token_limit", "value": str(DEFAULT_LLM_MONTHLY_TOKEN_LIMIT),
     "category": "llm", "value_type": "int",
     "label": "Monatliches Token-Limit", "description": "Maximale Tokens pro Monat"},
    # --- Security ---
    {"key": "jwt_token_expiry_minutes", "value": "1440",
     "category": "security", "value_type": "int",
     "label": "JWT Token-Gültigkeit (Min.)",
     "description": "Session-Dauer bis Re-Login nötig (1440=24h)"},
    {"key": "mfa_session_expiry_minutes", "value": "5",
     "category": "security", "value_type": "int",
     "label": "MFA-Session Timeout (Min.)",
     "description": "Zeit für MFA-Code nach Passwort-Login"},
    {"key": "login_rate_limit_window", "value": "300",
     "category": "security", "value_type": "int",
     "label": "Login-Sperre Zeitfenster (s)",
     "description": "Zeitraum für Login-Versuche (Standard: 5 Min)"},
    {"key": "rate_limit_general", "value": "60",
     "category": "security", "value_type": "int",
     "label": "API Rate-Limit (Req/Min)",
     "description": "Max API-Anfragen pro Minute pro IP"},
    {"key": "rate_limit_scans", "value": "10",
     "category": "security", "value_type": "int",
     "label": "Scan Rate-Limit (Req/Min)",
     "description": "Max Scan-Starts pro Minute"},
    {"key": "rate_limit_chat", "value": "20",
     "category": "security", "value_type": "int",
     "label": "Chat Rate-Limit (Req/Min)",
     "description": "Max Chat-Nachrichten pro Minute"},
    # --- Watchdog ---
    {"key": "watchdog_check_interval", "value": "10",
     "category": "watchdog", "value_type": "int",
     "label": "Prüfintervall (s)",
     "description": "Watchdog-Prüfzyklus"},
    {"key": "watchdog_max_health_failures", "value": "3",
     "category": "watchdog", "value_type": "int",
     "label": "Max Health-Fehler",
     "description": "Fehler bis Kill-Switch ausgelöst wird"},
    {"key": "watchdog_max_scan_duration", "value": "600",
     "category": "watchdog", "value_type": "int",
     "label": "Max Scan-Dauer (s)",
     "description": "Hängende Scans werden abgebrochen"},
    # --- Agent (Erweiterung) ---
    {"key": "chat_history_limit", "value": "20",
     "category": "agent", "value_type": "int",
     "label": "Chat-History Nachrichten",
     "description": "Kontextfenster für den Agent"},
    {"key": "agent_max_escalation_level", "value": "2",
     "category": "agent", "value_type": "int",
     "label": "Max Eskalationsstufe (global)",
     "description": "Höchste erlaubte Stufe: 0=Passiv, 1=Aktiv, 2=Vuln, 3=Exploit, 4=Post-Exploit"},
    {"key": "agent_allowed_binaries", "value": (
         "curl,dig,whois,nmap,nuclei,nikto,dirb,sslscan,netcat,socat,"
         "hydra,john,hashcat,msfconsole,msfvenom,chisel,python3,wget,jq"
     ),
     "category": "agent", "value_type": "string",
     "label": "Erlaubte Sandbox-Binaries",
     "description": "Komma-getrennte Liste der Binaries die der Agent ausführen darf"},
    {"key": "agent_blocked_binaries", "value": "pip,pip3,apt,apt-get,npm,yarn,brew,cargo,gem",
     "category": "agent", "value_type": "string",
     "label": "Blockierte Binaries",
     "description": "Diese Befehle darf der Agent NIEMALS ausführen (Paketmanager)"},
    {"key": "agent_tool_install_role", "value": "security_lead",
     "category": "agent", "value_type": "string",
     "label": "Rolle für Tool-Installation",
     "description": "Mindest-Rolle: viewer, analyst, security_lead, org_admin, system_admin"},
    {"key": "agent_approval_required_level", "value": "3",
     "category": "agent", "value_type": "int",
     "label": "Genehmigung ab Stufe",
     "description": "Ab dieser Eskalationsstufe muss ein Admin genehmigen (0=immer, 5=nie)"},
    {"key": "agent_forbidden_actions", "value": (
         "denial_of_service,ransomware,data_exfiltration_bulk,"
         "persistence_without_roe,attack_third_party"
     ),
     "category": "agent", "value_type": "string",
     "label": "Verbotene Aktionen",
     "description": "Immer blockiert — unabhängig von Eskalationsstufe"},
    {"key": "agent_auto_install_enabled", "value": "false",
     "category": "agent", "value_type": "boolean",
     "label": "Agent darf Tools installieren",
     "description": "Wenn deaktiviert: Nur Admin kann Tools über die UI installieren"},
    {"key": "approval_timeout_seconds", "value": "300",
     "category": "agent", "value_type": "int",
     "label": "Genehmigung-Timeout (s)",
     "description": "Wartezeit auf Genehmigung bevor Stufe 3+ Tool übersprungen wird"},
    {"key": "token_budget_warning_threshold", "value": "0.8",
     "category": "agent", "value_type": "float",
     "label": "Token-Budget Warnschwelle",
     "description": "Warnung bei diesem Anteil des Budgets (0.0 – 1.0)"},
    # --- Security (Erweiterung) ---
    {"key": "cookie_max_age_seconds", "value": "3600",
     "category": "security", "value_type": "int",
     "label": "Cookie-Gültigkeit (s)",
     "description": "Lebensdauer der Auth-Cookies (3600 = 1 Stunde)"},
    {"key": "session_inactivity_minutes", "value": "30",
     "category": "security", "value_type": "int",
     "label": "Inaktivitäts-Timeout (Min.)",
     "description": "Automatischer Logout nach N Minuten ohne Aktivität"},
    # --- Watchdog (Erweiterung) ---
    {"key": "watchdog_health_check_url", "value": "http://localhost:8080/health",
     "category": "watchdog", "value_type": "string",
     "label": "Health-Check URL",
     "description": "URL die der Watchdog regelmäßig prüft"},
    {"key": "watchdog_webhook_url", "value": "",
     "category": "watchdog", "value_type": "string",
     "label": "Webhook-URL für Kill-Benachrichtigung",
     "description": "POST-Endpoint der bei Kill-Switch-Aktivierung benachrichtigt wird (leer = deaktiviert)"},
    # --- Backup ---
    {"key": "backup_retention_days", "value": "30",
     "category": "backup", "value_type": "int",
     "label": "Backup-Aufbewahrung (Tage)",
     "description": "Backups älter als N Tage werden automatisch gelöscht"},
    # --- NemoClaw / OpenShell (aus NemoClaw-Doku) ---
    {"key": "nemoclaw_gateway_name", "value": "nemoclaw",
     "category": "nemoclaw", "value_type": "string",
     "label": "OpenShell Gateway-Name",
     "description": "Name des NemoClaw-Gateways für SSH-Proxy-Verbindungen"},
    {"key": "nemoclaw_sandbox_name", "value": "my-assistant",
     "category": "nemoclaw", "value_type": "string",
     "label": "OpenShell Sandbox-Name",
     "description": "Name der OpenShell-Sandbox in der der Agent läuft"},
    {"key": "nemoclaw_agent_timeout", "value": "600",
     "category": "nemoclaw", "value_type": "int",
     "label": "Agent-Timeout (s)",
     "description": "Maximale Laufzeit eines Agent-Aufrufs in der Sandbox"},
    {"key": "nemoclaw_process_limit", "value": "512",
     "category": "nemoclaw", "value_type": "int",
     "label": "Prozess-Limit (ulimit)",
     "description": "Max. Prozesse in der Sandbox (Fork-Bomb-Schutz). Siehe: NemoClaw Sandbox Hardening → ulimit -u"},
    {"key": "nemoclaw_read_only_fs", "value": "true",
     "category": "nemoclaw", "value_type": "boolean",
     "label": "Read-Only Dateisystem",
     "description": "Sandbox-Root als Read-Only mounten (nur /sandbox und /tmp beschreibbar)"},
    {"key": "nemoclaw_tmpfs_size_mb", "value": "64",
     "category": "nemoclaw", "value_type": "int",
     "label": "tmpfs Größe (MB)",
     "description": "Größe des beschreibbaren /tmp Verzeichnisses in der Sandbox"},
    {"key": "nemoclaw_cap_drop_all", "value": "true",
     "category": "nemoclaw", "value_type": "boolean",
     "label": "Alle Capabilities entfernen",
     "description": "cap_drop=ALL — nur NET_BIND_SERVICE wird zurückgegeben. Siehe: NemoClaw Security → Capability Drops"},
    {"key": "nemoclaw_no_new_privileges", "value": "true",
     "category": "nemoclaw", "value_type": "boolean",
     "label": "Keine neuen Privilegien",
     "description": "Verhindert Privilege Escalation über setuid-Binaries. Siehe: NemoClaw Security → No New Privileges Flag"},
    {"key": "nemoclaw_network_policy", "value": "deny_by_default",
     "category": "nemoclaw", "value_type": "string",
     "label": "Netzwerk-Policy",
     "description": "deny_by_default = nur explizit freigegebene Endpoints erreichbar. Siehe: NemoClaw → Network Policy"},
    {"key": "nemoclaw_inference_provider", "value": "anthropic",
     "category": "nemoclaw", "value_type": "string",
     "label": "Inference-Provider",
     "description": "LLM-Provider in der Sandbox: anthropic, openai, nvidia, ollama, compatible"},
    {"key": "nemoclaw_writable_paths", "value": "/sandbox,/tmp",
     "category": "nemoclaw", "value_type": "string",
     "label": "Beschreibbare Pfade",
     "description": "Komma-getrennte Liste der Pfade die in der Sandbox beschreibbar sind"},
    {"key": "nemoclaw_credential_isolation", "value": "true",
     "category": "nemoclaw", "value_type": "boolean",
     "label": "Credential-Isolation",
     "description": "API-Keys werden nie an die Sandbox übergeben — nur über Gateway-Proxy. Siehe: NemoClaw Security → Credential Isolation"},
    # --- Phasen ---
    {"key": "phase_host_discovery_timeout", "value": "60",
     "category": "phases", "value_type": "int",
     "label": "Host-Discovery Timeout (s)",
     "description": "Max Laufzeit Host-Discovery"},
    {"key": "phase_port_scan_timeout", "value": "60",
     "category": "phases", "value_type": "int",
     "label": "Port-Scan Timeout (s)",
     "description": "Max Laufzeit Port-Scan"},
    {"key": "phase_vuln_scan_timeout", "value": "180",
     "category": "phases", "value_type": "int",
     "label": "Vuln-Scan Timeout (s)",
     "description": "Max Laufzeit Vulnerability-Scan"},
    {"key": "phase_analysis_timeout", "value": "120",
     "category": "phases", "value_type": "int",
     "label": "Analyse Timeout (s)",
     "description": "Max Laufzeit Analyse-Phase"},
]


class SettingsRepository:
    """CRUD für systemweite Einstellungen."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def get_all(self) -> list[dict]:
        """Lädt alle Einstellungen."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings ORDER BY category, key"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_by_category(self, category: str) -> list[dict]:
        """Lädt Einstellungen einer Kategorie."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings WHERE category = ? ORDER BY key",
            (category,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get(self, key: str) -> dict | None:
        """Lädt eine einzelne Einstellung."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def update(self, key: str, value: str, updated_by: str) -> bool:
        """Aktualisiert eine Einstellung. Gibt False zurück wenn Key nicht existiert."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()
        result = await conn.execute(
            "UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? "
            "WHERE key = ?",
            (value, updated_by, now, key),
        )
        await conn.commit()
        return result.rowcount > 0

    async def batch_update(
        self, updates: dict[str, str], updated_by: str
    ) -> int:
        """Aktualisiert mehrere Einstellungen. Gibt Anzahl geänderter Werte zurück."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()
        changed = 0
        for key, value in updates.items():
            result = await conn.execute(
                "UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? "
                "WHERE key = ?",
                (value, updated_by, now, key),
            )
            changed += result.rowcount
        await conn.commit()
        return changed


async def seed_defaults(db: DatabaseManager) -> int:
    """Fügt Standard-Einstellungen ein, überspringt bereits vorhandene Keys."""
    conn = await db.get_connection()
    now = datetime.now(UTC).isoformat()
    inserted = 0

    for defn in _SEED_DEFINITIONS:
        cursor = await conn.execute(
            "SELECT 1 FROM system_settings WHERE key = ?", (defn["key"],)
        )
        if await cursor.fetchone() is None:
            await conn.execute(
                "INSERT INTO system_settings (key, value, category, value_type, "
                "label, description, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    defn["key"], defn["value"], defn["category"], defn["value_type"],
                    defn["label"], defn["description"], "system", now,
                ),
            )
            inserted += 1

    await conn.commit()
    if inserted:
        logger.info("Standard-Einstellungen gesät", count=inserted)
    return inserted

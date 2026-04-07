"""
Zentrale Konfiguration für SentinelClaw.

Alle Einstellungen werden über Umgebungsvariablen geladen.
Pydantic-Settings validiert Typen und setzt Defaults.
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.shared.constants.defaults import (
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_LLM_MAX_TOKENS_PER_SCAN,
    DEFAULT_LLM_MONTHLY_TOKEN_LIMIT,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_CONCURRENT_SCANS,
    DEFAULT_MCP_HOST,
    DEFAULT_MCP_PORT,
    DEFAULT_SANDBOX_CPU_LIMIT,
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_SANDBOX_MEMORY_LIMIT,
    DEFAULT_SANDBOX_PID_LIMIT,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
)


class Settings(BaseSettings):
    """Konfiguration aus Umgebungsvariablen mit SENTINEL_* Prefix."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- LLM-Provider ---
    llm_provider: Literal["claude", "claude-abo", "azure", "ollama"] = Field(
        default="claude-abo",
        description="LLM-Provider: claude-abo (CLI/Abo), claude (API-Key), azure, ollama",
    )
    claude_api_key: str = Field(
        default="",
        description="Anthropic API Key (nur bei Provider=claude)",
    )
    claude_model: str = Field(
        default=DEFAULT_CLAUDE_MODEL,
        description="Claude-Modell für Analyse",
    )
    llm_timeout: int = Field(
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
        ge=10,
        le=600,
        description="LLM-Request-Timeout in Sekunden",
    )
    llm_max_tokens_per_scan: int = Field(
        default=DEFAULT_LLM_MAX_TOKENS_PER_SCAN,
        ge=1000,
        description="Maximales Token-Budget pro Scan",
    )
    llm_monthly_token_limit: int = Field(
        default=DEFAULT_LLM_MONTHLY_TOKEN_LIMIT,
        ge=1000,
        description="Monatliches Token-Limit",
    )

    # --- Azure OpenAI (nur bei Provider=azure) ---
    azure_endpoint: str = Field(
        default="",
        description="Azure OpenAI Endpoint URL",
    )
    azure_api_key: str = Field(
        default="",
        description="Azure OpenAI API Key",
    )
    azure_deployment: str = Field(
        default="gpt-4o",
        description="Azure OpenAI Deployment Name",
    )
    azure_api_version: str = Field(
        default="2024-08-01-preview",
        description="Azure OpenAI API Version",
    )

    # --- Ollama (nur bei Provider=ollama) ---
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama Server URL",
    )
    ollama_model: str = Field(
        default="llama3.1:70b",
        description="Ollama-Modell",
    )

    # --- Scan-Konfiguration ---
    allowed_targets: str = Field(
        default="",
        description="Komma-separierte Liste erlaubter Scan-Ziele (CIDR oder Domain)",
    )
    sandbox_timeout: int = Field(
        default=DEFAULT_SANDBOX_TIMEOUT_SECONDS,
        ge=10,
        le=3600,
        description="Max. Tool-Laufzeit in Sekunden",
    )
    max_concurrent_scans: int = Field(
        default=DEFAULT_MAX_CONCURRENT_SCANS,
        ge=1,
        le=10,
        description="Maximale gleichzeitige Scans",
    )

    # --- Logging ---
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default=DEFAULT_LOG_LEVEL,
        description="Log-Verbosity",
    )

    # --- MCP-Server ---
    mcp_port: int = Field(
        default=DEFAULT_MCP_PORT,
        ge=1024,
        le=65535,
        description="MCP-Server Port",
    )
    mcp_host: str = Field(
        default=DEFAULT_MCP_HOST,
        description="MCP-Server Host",
    )

    # --- Docker / Sandbox ---
    sandbox_image: str = Field(
        default=DEFAULT_SANDBOX_IMAGE,
        description="Docker-Image für die Sandbox",
    )
    sandbox_memory_limit: str = Field(
        default=DEFAULT_SANDBOX_MEMORY_LIMIT,
        description="RAM-Limit für Sandbox-Container",
    )
    sandbox_cpu_limit: float = Field(
        default=DEFAULT_SANDBOX_CPU_LIMIT,
        ge=0.5,
        le=8.0,
        description="CPU-Limit für Sandbox-Container",
    )
    sandbox_pid_limit: int = Field(
        default=DEFAULT_SANDBOX_PID_LIMIT,
        ge=10,
        le=500,
        description="Max. Prozesse im Sandbox-Container",
    )

    # --- NemoClaw / OpenShell ---
    openshell_gateway_name: str = Field(
        default="nemoclaw",
        description="OpenShell Gateway-Name",
    )
    openshell_sandbox_name: str = Field(
        default="my-assistant",
        description="OpenShell Sandbox-Name",
    )
    openclaw_agent_id: str = Field(
        default="main",
        description="OpenClaw Agent-ID innerhalb der Sandbox",
    )
    openclaw_agent_timeout: int = Field(
        default=600,
        ge=10,
        le=1800,
        description="Timeout für OpenClaw Agent-Aufrufe in Sekunden",
    )
    openclaw_anthropic_token: str = Field(
        default="",
        description="Auth-Token für den OpenClaw-Agent (aus 'claude setup-token')",
    )

    # --- Chat-Agent ---
    chat_prompt_file: str = Field(
        default="",
        description="Pfad zu einer Datei mit alternativem Chat-System-Prompt "
                    "(leer = Standard-Prompt). Fuer iteratives Prompt-Testing.",
    )

    # --- CORS ---
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173",
        description="Komma-separierte CORS-Origins",
    )

    # --- Sicherheit / Auth ---
    jwt_secret: str = Field(
        default="",
        description="JWT-Geheimschluessel (Pflicht in Produktion)",
    )
    debug: bool = Field(
        default=True,
        description="Debug-Modus — API-Docs nur wenn True",
    )
    login_rate_limit_attempts: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Max. fehlgeschlagene Logins pro IP in 5 Minuten",
    )

    # --- Datenbank ---
    db_type: Literal["sqlite", "postgresql"] = Field(
        default="sqlite",
        description="Datenbank-Backend: sqlite (PoC) oder postgresql (Produktion)",
    )
    db_path: Path = Field(
        default=Path("data/sentinelclaw.db"),
        description="Pfad zur SQLite-Datenbank (nur bei db_type=sqlite)",
    )
    db_host: str = Field(
        default="localhost",
        description="PostgreSQL-Host (nur bei db_type=postgresql)",
    )
    db_port: int = Field(
        default=5432,
        ge=1,
        le=65535,
        description="PostgreSQL-Port",
    )
    db_name: str = Field(
        default="sentinelclaw",
        description="PostgreSQL-Datenbankname",
    )
    db_user: str = Field(
        default="sentinel",
        description="PostgreSQL-Benutzer",
    )
    db_password: str = Field(
        default="",
        description="PostgreSQL-Passwort",
    )

    def get_db_dsn(self) -> str:
        """Erstellt den PostgreSQL-Connection-String."""
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @field_validator("allowed_targets")
    @classmethod
    def parse_allowed_targets(cls, value: str) -> str:
        """Validiert dass Targets nicht leer sind wenn gesetzt."""
        return value.strip()

    def get_allowed_targets_list(self) -> list[str]:
        """Gibt die erlaubten Ziele als Liste zurück."""
        if not self.allowed_targets:
            return []
        return [target.strip() for target in self.allowed_targets.split(",") if target.strip()]

    def has_claude_key(self) -> bool:
        """Prüft ob ein Claude API-Key konfiguriert ist."""
        return bool(self.claude_api_key) and self.claude_api_key != "sk-ant-DEIN_KEY_HIER"


# Singleton-Instanz — wird einmal geladen und überall genutzt
_settings: Settings | None = None


def get_settings() -> Settings:
    """Gibt die Konfiguration zurück (Singleton, lazy-loaded)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Lädt die Konfiguration neu (z.B. nach .env-Änderung)."""
    global _settings
    _settings = Settings()
    return _settings

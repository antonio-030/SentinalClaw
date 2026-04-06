"""
LLM-Provider-Factory für SentinelClaw.

Der primäre LLM-Zugang läuft über NemoClaw/OpenClaw — der Provider
(Claude, Azure, Ollama) wird im NemoClaw-Gateway konfiguriert
(OpenShell Privacy-Router). SentinelClaw ruft nur die OpenClaw-API auf.

Für direkten API-Zugriff (ohne NemoClaw) stehen zusätzlich bereit:
- Claude API (Anthropic, braucht SENTINEL_CLAUDE_API_KEY)
- Azure OpenAI (braucht SENTINEL_AZURE_ENDPOINT + KEY)
- Ollama (braucht SENTINEL_OLLAMA_BASE_URL)
"""

from src.shared.config import get_settings
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


# ─── Provider-Factory ──────────────────────────────────────────────


def create_llm_provider():
    """Erstellt den passenden LLM-Provider basierend auf der Konfiguration.

    Unterstützte Provider (SENTINEL_LLM_PROVIDER):
    - nemoclaw  → NemoClaw/OpenClaw (Standard, Provider im Gateway konfiguriert)
    - claude    → Anthropic API direkt (SENTINEL_CLAUDE_API_KEY nötig)
    - azure     → Azure OpenAI (SENTINEL_AZURE_ENDPOINT + KEY nötig)
    - ollama    → Lokaler Ollama-Server (SENTINEL_OLLAMA_BASE_URL)
    """
    settings = get_settings()
    provider = settings.llm_provider

    # NemoClaw/OpenClaw — Standard, LLM-Provider im Gateway konfiguriert
    if provider in ("nemoclaw", "claude-abo"):
        logger.info("LLM-Provider: NemoClaw/OpenClaw (Gateway-Routing)")
        return None  # NemoClaw nutzt run_agent() direkt

    # Azure OpenAI — DSGVO-konform in EU-Region
    if provider == "azure":
        from src.agents.azure_provider import AzureOpenAIProvider

        logger.info(
            "LLM-Provider: Azure OpenAI",
            deployment=settings.azure_deployment,
        )
        return AzureOpenAIProvider()

    # Ollama — lokaler LLM-Server für maximale Datensouveränität
    if provider == "ollama":
        from src.agents.ollama_provider import OllamaProvider

        logger.info(
            "LLM-Provider: Ollama (lokal)",
            model=settings.ollama_model,
        )
        return OllamaProvider()

    # Claude API direkt (braucht API-Key)
    if provider == "claude" and settings.has_claude_key():
        from src.agents.claude_api_provider import ClaudeApiProvider

        logger.info("LLM-Provider: Claude API (API-Key)")
        return ClaudeApiProvider()

    # Fallback: NemoClaw
    logger.info("LLM-Provider: NemoClaw/OpenClaw (Fallback)")
    return None

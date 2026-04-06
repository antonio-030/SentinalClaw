"""
Claude LLM-Provider für SentinelClaw.

Zwei Betriebsmodi:
1. claude-abo: Nutzt die Claude Code CLI (kein API-Key nötig, Abo reicht)
2. claude-api: Nutzt die Anthropic API direkt (separater API-Key nötig)

Der claude-abo-Modus funktioniert über den `claude` CLI-Befehl der
auf dem System installiert ist und die OAuth-Credentials aus ~/.claude/
nutzt. Kein separater API-Key, keine separaten Kosten.
"""

import asyncio
import json
import shutil
from typing import Any

from src.shared.config import get_settings
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import (
    LlmMessage,
    LlmResponse,
    ToolDefinition,
)

logger = get_logger(__name__)


# ─── Hilfsfunktionen ───────────────────────────────────────────────


async def _invoke_claude_cli(
    args: list[str],
    input_text: str,
    timeout: float = 300,
    cwd: str = "/tmp",
) -> str:
    """Startet die Claude CLI als Subprocess und gibt stdout zurück.

    Die CLI authentifiziert sich automatisch über die OAuth-Tokens
    in ~/.claude/ — kein API-Key nötig.
    """
    binary_path = shutil.which("claude")
    if not binary_path:
        raise RuntimeError(
            "Claude CLI nicht gefunden. Bitte installieren: "
            "https://docs.anthropic.com/en/docs/claude-code"
        )

    full_args = [binary_path, *args]

    logger.debug("Claude CLI Aufruf", args=args, input_length=len(input_text))

    process = await asyncio.create_subprocess_exec(
        *full_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=input_text.encode("utf-8")),
            timeout=timeout,
        )
    except TimeoutError as exc:
        process.kill()
        raise RuntimeError(f"Claude CLI Timeout nach {timeout}s") from exc

    if process.returncode != 0:
        error_msg = stderr.decode("utf-8", errors="replace").strip()
        logger.error(
            "Claude CLI Fehler",
            exit_code=process.returncode,
            error=error_msg[:500],
        )
        raise RuntimeError(f"Claude CLI fehlgeschlagen (Exit {process.returncode}): {error_msg}")

    return stdout.decode("utf-8").strip()


def _parse_cli_json_output(raw: str) -> dict[str, Any]:
    """Parst die JSON-Ausgabe der Claude CLI.

    Die CLI gibt mit --output-format json ein JSON-Objekt zurück das
    den Antworttext, Token-Verbrauch und Session-ID enthält.
    """
    if not raw:
        return {"result": "", "total_tokens": 0}

    try:
        data = json.loads(raw)
        return data
    except json.JSONDecodeError:
        # Falls die Ausgabe kein JSON ist, als Plaintext behandeln
        return {"result": raw, "total_tokens": 0}


def _estimate_tokens_from_json(data: dict[str, Any]) -> int:
    """Extrahiert oder schätzt den Token-Verbrauch aus der CLI-Ausgabe."""
    # Exakte Werte wenn vorhanden (Claude CLI mit --output-format json)
    usage = data.get("usage", {})
    if usage:
        return (
            usage.get("input_tokens", 0)
            + usage.get("output_tokens", 0)
            + usage.get("cache_read_input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
        )

    # Kostenschätzung als Fallback (~100k Tokens pro Dollar)
    cost_usd = data.get("cost_usd", 0)
    if cost_usd and cost_usd > 0:
        return int(cost_usd * 100_000)

    # Wortbasierte Schätzung als letzter Ausweg (~1.3 Tokens pro Wort)
    text = data.get("result", "")
    return int(len(text.split()) * 1.3)


# ─── Claude-Abo Provider (CLI-basiert) ─────────────────────────────


class ClaudeAboProvider:
    """LLM-Provider der Claude über die Claude Code CLI nutzt.

    Authentifiziert sich über das bestehende Claude Code Abo —
    kein separater API-Key nötig. Die CLI nutzt die OAuth-Tokens
    aus ~/.claude/ automatisch.

    Für einfache Completions: --print --output-format json
    Für Agent-Modus mit Tools: --print --output-format json --allowedTools
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._timeout = settings.llm_timeout
        self._session_id: str | None = None

    async def send_messages(
        self,
        messages: list[LlmMessage],
        tools: list[ToolDefinition] | None = None,
        max_tokens: int = 4096,
    ) -> LlmResponse:
        """Sendet Nachrichten an Claude über die CLI."""
        # System-Prompt und User-Nachrichten extrahieren
        system_prompt = ""
        user_parts: list[str] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            elif msg.role == "user":
                user_parts.append(msg.content)
            elif msg.role == "tool":
                # Tool-Ergebnisse als Kontext anfügen
                for result in msg.tool_results:
                    user_parts.append(
                        f"[Tool-Ergebnis von {result.call_id}]:\n{result.output}"
                    )
            elif msg.role == "assistant":
                user_parts.append(f"[Vorherige Antwort]:\n{msg.content}")

        # Prompt zusammenbauen
        full_prompt = ""
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n---\n\n"
        full_prompt += "\n\n".join(user_parts)

        # CLI-Argumente zusammenbauen
        cli_args = ["--print", "--output-format", "json"]

        # System-Prompt als append-system-prompt wenn vorhanden
        if system_prompt:
            cli_args.extend(["--append-system-prompt", system_prompt])
            # Dann nur User-Nachrichten als Input
            full_prompt = "\n\n".join(user_parts)

        # Resume für Cache-Sharing zwischen Aufrufen
        if self._session_id:
            cli_args.extend(["--resume", self._session_id])

        # CLI aufrufen
        raw = await _invoke_claude_cli(
            args=cli_args,
            input_text=full_prompt,
            timeout=self._timeout,
        )

        # Antwort parsen
        data = _parse_cli_json_output(raw)
        total_tokens = _estimate_tokens_from_json(data)

        # Session-ID für Cache-Sharing merken
        session_id = data.get("session_id")
        if session_id:
            self._session_id = session_id

        # Antworttext extrahieren
        content = data.get("result", "")
        if not content:
            content = data.get("content", "")
        if not content and isinstance(data, str):
            content = data

        logger.info(
            "Claude-Abo Antwort",
            tokens=total_tokens,
            session_id=self._session_id,
            content_length=len(content),
        )

        return LlmResponse(
            content=content,
            tool_calls=[],  # Bei CLI-Modus keine Tool-Calls — der Agent-Loop macht das
            stop_reason="end_turn",
            prompt_tokens=total_tokens // 2,  # Schätzung
            completion_tokens=total_tokens // 2,
        )

    async def check_availability(self) -> bool:
        """Prüft ob die Claude CLI verfügbar und authentifiziert ist."""
        try:
            binary_path = shutil.which("claude")
            if not binary_path:
                logger.error("Claude CLI nicht auf PATH gefunden")
                return False

            raw = await _invoke_claude_cli(
                args=["--print", "--output-format", "json"],
                input_text="Antworte nur mit: ok",
                timeout=30,
            )
            return bool(raw)
        except Exception as error:
            logger.error("Claude CLI nicht verfügbar", error=str(error))
            return False


# ─── Provider-Factory ──────────────────────────────────────────────


def create_llm_provider() -> "ClaudeAboProvider":
    """Erstellt den passenden LLM-Provider basierend auf der Konfiguration.

    Unterstützte Provider (SENTINEL_LLM_PROVIDER):
    - claude-abo  → Claude Code CLI (Abo, kein API-Key nötig)
    - claude      → Anthropic API direkt (SENTINEL_CLAUDE_API_KEY nötig)
    - azure       → Azure OpenAI (SENTINEL_AZURE_ENDPOINT + KEY nötig)
    - ollama      → Lokaler Ollama-Server (SENTINEL_OLLAMA_BASE_URL)
    """
    settings = get_settings()
    provider = settings.llm_provider

    # Azure OpenAI — DSGVO-konform in EU-Region
    if provider == "azure":
        from src.agents.azure_provider import AzureOpenAIProvider

        logger.info("LLM-Provider: Azure OpenAI", deployment=settings.azure_deployment)
        return AzureOpenAIProvider()

    # Ollama — lokaler LLM-Server für maximale Datensouveränität
    if provider == "ollama":
        from src.agents.ollama_provider import OllamaProvider

        logger.info("LLM-Provider: Ollama (lokal)", model=settings.ollama_model)
        return OllamaProvider()

    # Explizit claude-abo gewählt
    if provider == "claude-abo":
        logger.info("LLM-Provider: Claude Code CLI (Abo)")
        return ClaudeAboProvider()

    # Claude mit API-Key — lazily importiert um zirkuläre Imports zu vermeiden
    if settings.has_claude_key():
        from src.agents.claude_api_provider import ClaudeApiProvider

        logger.info("LLM-Provider: Claude API (API-Key)")
        return ClaudeApiProvider()

    # Kein API-Key → versuche CLI
    logger.info("LLM-Provider: Claude Code CLI (kein API-Key konfiguriert, nutze Abo)")
    return ClaudeAboProvider()

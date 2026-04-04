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
    ToolCallRequest,
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
    except TimeoutError:
        process.kill()
        raise RuntimeError(f"Claude CLI Timeout nach {timeout}s")

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


# ─── Claude-API Provider (API-Key-basiert) ─────────────────────────


class ClaudeApiProvider:
    """LLM-Provider der Claude über die Anthropic API nutzt.

    Braucht einen separaten API-Key (SENTINEL_CLAUDE_API_KEY).
    Für Kunden die keinen CLI-Zugang haben oder die API bevorzugen.
    """

    def __init__(self) -> None:
        import anthropic

        settings = get_settings()
        self._client = anthropic.AsyncAnthropic(api_key=settings.claude_api_key)
        self._model = settings.claude_model
        self._timeout = settings.llm_timeout

    async def send_messages(
        self,
        messages: list[LlmMessage],
        tools: list[ToolDefinition] | None = None,
        max_tokens: int = 4096,
    ) -> LlmResponse:
        """Sendet Nachrichten an Claude über die Anthropic API."""

        system_prompt = ""
        api_messages: list[dict] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
                continue

            if msg.role == "tool":
                for result in msg.tool_results:
                    api_messages.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": result.call_id,
                            "content": result.output,
                            "is_error": result.is_error,
                        }],
                    })
                continue

            if msg.role == "assistant" and msg.tool_calls:
                content_blocks: list[dict] = []
                if msg.content:
                    content_blocks.append({"type": "text", "text": msg.content})
                for call in msg.tool_calls:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": call.call_id,
                        "name": call.tool_name,
                        "input": call.arguments,
                    })
                api_messages.append({"role": "assistant", "content": content_blocks})
                continue

            api_messages.append({"role": msg.role, "content": msg.content})

        kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": api_messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]

        response = await self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_calls: list[ToolCallRequest] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCallRequest(
                    tool_name=block.name,
                    arguments=block.input,
                    call_id=block.id,
                ))

        return LlmResponse(
            content="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "end_turn",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
        )

    async def check_availability(self) -> bool:
        """Prüft ob die Claude API erreichbar ist."""
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            return response.stop_reason is not None
        except Exception as error:
            logger.error("Claude API nicht erreichbar", error=str(error))
            return False


# ─── Provider-Factory ──────────────────────────────────────────────


def create_llm_provider() -> ClaudeAboProvider | ClaudeApiProvider:
    """Erstellt den passenden LLM-Provider basierend auf der Konfiguration.

    Logik:
    - SENTINEL_LLM_PROVIDER=claude-abo → Claude Code CLI (Abo, kein API-Key)
    - SENTINEL_LLM_PROVIDER=claude → Wenn API-Key vorhanden: API, sonst: CLI
    - Expliziter API-Key vorhanden → API-Provider
    - Kein API-Key → Abo-Provider (CLI)
    """
    settings = get_settings()

    # Explizit claude-abo gewählt
    if settings.llm_provider == "claude-abo":
        logger.info("LLM-Provider: Claude Code CLI (Abo)")
        return ClaudeAboProvider()

    # Claude mit API-Key
    if settings.has_claude_key():
        logger.info("LLM-Provider: Claude API (API-Key)")
        return ClaudeApiProvider()

    # Kein API-Key → versuche CLI
    logger.info("LLM-Provider: Claude Code CLI (kein API-Key konfiguriert, nutze Abo)")
    return ClaudeAboProvider()

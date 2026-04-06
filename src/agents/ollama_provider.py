"""
Ollama Provider für SentinelClaw.

Lokaler LLM-Provider für maximale Datensouveränität.
Kommuniziert via HTTP mit dem Ollama-Server.
"""

import json

import httpx

from src.shared.config import get_settings
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import (
    LlmMessage,
    LlmResponse,
    ToolCallRequest,
    ToolDefinition,
)

logger = get_logger(__name__)

# Grobe Schätzung: ~1.3 Tokens pro Wort für die Token-Zählung
TOKENS_PER_WORD_ESTIMATE = 1.3


class OllamaProvider:
    """LLM-Provider der einen lokalen Ollama-Server nutzt.

    Alle Daten bleiben lokal — kein Cloud-Zugriff nötig.
    Kommuniziert über die Ollama REST API (/api/chat).
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._base_url = settings.ollama_base_url.rstrip("/")
        self._model = settings.ollama_model
        self._timeout = float(settings.llm_timeout)

    async def send_messages(
        self,
        messages: list[LlmMessage],
        tools: list[ToolDefinition] | None = None,
        max_tokens: int = 4096,
    ) -> LlmResponse:
        """Sendet Nachrichten an den Ollama-Server und gibt die Antwort zurück."""
        api_messages = _convert_messages(messages)

        payload: dict = {
            "model": self._model,
            "messages": api_messages,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }

        # Ollama unterstützt Tools im OpenAI-kompatiblen Format
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                }
                for tool in tools
            ]

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        return _parse_response(data)

    async def check_availability(self) -> bool:
        """Prüft ob der Ollama-Server erreichbar ist und Modelle bereitstellt."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self._base_url}/api/tags")
                response.raise_for_status()
                data = response.json()
                models = data.get("models", [])
                logger.info(
                    "Ollama verfügbar",
                    model_count=len(models),
                    base_url=self._base_url,
                )
                return len(models) > 0
        except httpx.HTTPError as error:
            logger.error("Ollama nicht erreichbar", error=str(error))
            return False


# ─── Hilfsfunktionen ───────────────────────────────────────────────


def _convert_messages(messages: list[LlmMessage]) -> list[dict]:
    """Konvertiert interne Nachrichten ins Ollama-Chat-Format."""
    api_messages: list[dict] = []

    for msg in messages:
        if msg.role == "tool":
            for result in msg.tool_results:
                api_messages.append({
                    "role": "tool",
                    "content": result.output,
                })
            continue

        # Assistant-Nachricht mit Tool-Calls im Ollama-Format
        if msg.role == "assistant" and msg.tool_calls:
            tool_calls_formatted = [
                {
                    "function": {
                        "name": call.tool_name,
                        "arguments": call.arguments,
                    },
                }
                for call in msg.tool_calls
            ]
            api_messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": tool_calls_formatted,
            })
            continue

        api_messages.append({"role": msg.role, "content": msg.content})

    return api_messages


def _parse_response(data: dict) -> LlmResponse:
    """Parst die Ollama-Antwort in das interne Format."""
    message = data.get("message", {})
    content = message.get("content", "")

    # Tool-Calls aus der Ollama-Antwort extrahieren
    tool_calls: list[ToolCallRequest] = []
    raw_tool_calls = message.get("tool_calls", [])
    for index, tool_call in enumerate(raw_tool_calls):
        function_data = tool_call.get("function", {})
        arguments = function_data.get("arguments", {})
        # Ollama gibt arguments manchmal als String zurück
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        tool_calls.append(ToolCallRequest(
            tool_name=function_data.get("name", ""),
            arguments=arguments,
            call_id=f"ollama-call-{index}",
        ))

    # Ollama liefert keine exakten Token-Zahlen — wir schätzen
    prompt_tokens = _estimate_tokens(
        " ".join(m.get("content", "") for m in data.get("messages", []))
    )
    completion_tokens = _estimate_tokens(content)

    # Wenn eval_count verfügbar ist (manche Ollama-Versionen), nutzen
    if "eval_count" in data:
        completion_tokens = data["eval_count"]
    if "prompt_eval_count" in data:
        prompt_tokens = data["prompt_eval_count"]

    done_reason = data.get("done_reason", "stop")
    return LlmResponse(
        content=content,
        tool_calls=tool_calls,
        stop_reason=done_reason,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def _estimate_tokens(text: str) -> int:
    """Schätzt die Token-Anzahl basierend auf der Wortanzahl."""
    if not text:
        return 0
    return int(len(text.split()) * TOKENS_PER_WORD_ESTIMATE)

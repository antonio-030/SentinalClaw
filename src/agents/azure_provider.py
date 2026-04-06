"""
Azure OpenAI Provider für SentinelClaw.

Nutzt das openai Python-Package mit Azure-spezifischer Konfiguration.
DSGVO-konform: Daten bleiben in der EU-Region.
"""

from src.shared.config import get_settings
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import (
    LlmMessage,
    LlmResponse,
    ToolCallRequest,
    ToolDefinition,
)

logger = get_logger(__name__)

# Timeout-Konstanten für Azure API-Aufrufe (in Sekunden)
AZURE_CONNECT_TIMEOUT = 10
AZURE_AVAILABILITY_MAX_TOKENS = 10


class AzureOpenAIProvider:
    """LLM-Provider der Azure OpenAI nutzt.

    Braucht SENTINEL_AZURE_ENDPOINT, SENTINEL_AZURE_API_KEY und
    SENTINEL_AZURE_DEPLOYMENT. Daten verbleiben in der konfigurierten
    Azure-Region (EU für DSGVO-Konformität).
    """

    def __init__(self) -> None:
        import openai

        settings = get_settings()
        self._client = openai.AsyncAzureOpenAI(
            azure_endpoint=settings.azure_endpoint,
            api_key=settings.azure_api_key,
            api_version=settings.azure_api_version,
            timeout=float(settings.llm_timeout),
        )
        self._deployment = settings.azure_deployment
        self._timeout = settings.llm_timeout

    async def send_messages(
        self,
        messages: list[LlmMessage],
        tools: list[ToolDefinition] | None = None,
        max_tokens: int = 4096,
    ) -> LlmResponse:
        """Sendet Nachrichten an Azure OpenAI und gibt die Antwort zurück."""
        api_messages = _convert_messages(messages)
        kwargs: dict = {
            "model": self._deployment,
            "max_tokens": max_tokens,
            "messages": api_messages,
        }

        # Tool-Definitionen im OpenAI Function-Calling-Format
        if tools:
            kwargs["tools"] = [
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

        response = await self._client.chat.completions.create(**kwargs)
        return _parse_response(response)

    async def check_availability(self) -> bool:
        """Prüft ob der Azure OpenAI Endpoint erreichbar ist."""
        try:
            response = await self._client.chat.completions.create(
                model=self._deployment,
                max_tokens=AZURE_AVAILABILITY_MAX_TOKENS,
                messages=[{"role": "user", "content": "ping"}],
            )
            return response.choices is not None and len(response.choices) > 0
        except Exception as error:
            logger.error("Azure OpenAI nicht erreichbar", error=str(error))
            return False


# ─── Hilfsfunktionen ───────────────────────────────────────────────


def _convert_messages(messages: list[LlmMessage]) -> list[dict]:
    """Konvertiert interne Nachrichten ins OpenAI-API-Format."""
    api_messages: list[dict] = []

    for msg in messages:
        if msg.role == "system":
            api_messages.append({"role": "system", "content": msg.content})
            continue

        if msg.role == "tool":
            for result in msg.tool_results:
                api_messages.append({
                    "role": "tool",
                    "tool_call_id": result.call_id,
                    "content": result.output,
                })
            continue

        # Assistant-Nachricht mit Tool-Calls
        if msg.role == "assistant" and msg.tool_calls:
            tool_calls_formatted = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {
                        "name": call.tool_name,
                        "arguments": _serialize_arguments(call.arguments),
                    },
                }
                for call in msg.tool_calls
            ]
            api_messages.append({
                "role": "assistant",
                "content": msg.content or None,
                "tool_calls": tool_calls_formatted,
            })
            continue

        api_messages.append({"role": msg.role, "content": msg.content})

    return api_messages


def _serialize_arguments(arguments: dict) -> str:
    """Serialisiert Tool-Argumente zu JSON-String (OpenAI-Format)."""
    import json

    return json.dumps(arguments, ensure_ascii=False)


def _parse_response(response: object) -> LlmResponse:
    """Parst die Azure OpenAI Antwort in das interne Format."""
    import json

    choice = response.choices[0]  # type: ignore[attr-defined]
    message = choice.message

    # Text-Inhalt extrahieren
    content = message.content or ""

    # Tool-Calls extrahieren falls vorhanden
    tool_calls: list[ToolCallRequest] = []
    if message.tool_calls:
        for tool_call in message.tool_calls:
            arguments = json.loads(tool_call.function.arguments)
            tool_calls.append(ToolCallRequest(
                tool_name=tool_call.function.name,
                arguments=arguments,
                call_id=tool_call.id,
            ))

    usage = response.usage  # type: ignore[attr-defined]
    return LlmResponse(
        content=content,
        tool_calls=tool_calls,
        stop_reason=choice.finish_reason or "stop",
        prompt_tokens=usage.prompt_tokens if usage else 0,
        completion_tokens=usage.completion_tokens if usage else 0,
    )

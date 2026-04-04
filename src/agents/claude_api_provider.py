"""
Claude API Provider für SentinelClaw.

Nutzt die Anthropic API direkt (separater API-Key nötig).
Ausgelagert aus llm_provider.py um die 300-Zeilen-Regel einzuhalten.
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

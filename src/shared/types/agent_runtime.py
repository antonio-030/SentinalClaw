"""
Abstrakte Interfaces für die Agent-Runtime.

Definiert die Verträge zwischen SentinelClaw und der Agent-Runtime
(NemoClaw/OpenClaw). Alle konkreten Implementierungen müssen diese
Protocols erfüllen.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ToolDefinition:
    """Beschreibung eines Tools das dem Agent zur Verfügung steht."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class ToolCallRequest:
    """Anfrage des Agents ein Tool auszuführen."""

    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class ToolCallResult:
    """Ergebnis einer Tool-Ausführung."""

    call_id: str
    output: str
    is_error: bool = False


@dataclass
class LlmMessage:
    """Eine Nachricht im LLM-Konversationsverlauf."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    tool_results: list[ToolCallResult] = field(default_factory=list)


@dataclass
class LlmResponse:
    """Antwort vom LLM-Provider."""

    content: str
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    stop_reason: str = "end_turn"
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class AgentResult:
    """Endergebnis eines Agent-Durchlaufs."""

    final_output: str
    tool_calls_made: list[dict[str, Any]] = field(default_factory=list)
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    steps_taken: int = 0
    session_id: str | None = None


@dataclass(frozen=True)
class OpenClawConfig:
    """Konfiguration fuer die OpenClaw-Verbindung via OpenShell."""

    gateway_name: str = "nemoclaw"
    sandbox_name: str = "my-assistant"
    agent_id: str = "main"
    agent_timeout: int = 300
    ssh_timeout: int = 10


@runtime_checkable
class LlmProvider(Protocol):
    """Interface für LLM-Provider (Claude, Azure, Ollama)."""

    async def send_messages(
        self,
        messages: list[LlmMessage],
        tools: list[ToolDefinition] | None = None,
        max_tokens: int = 4096,
    ) -> LlmResponse:
        """Sendet Nachrichten an das LLM und gibt die Antwort zurück."""
        ...

    async def check_availability(self) -> bool:
        """Prüft ob der LLM-Provider erreichbar ist."""
        ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Interface für die Ausführung von Tools (MCP-Server)."""

    async def execute_tool(self, request: ToolCallRequest) -> ToolCallResult:
        """Führt ein Tool aus und gibt das Ergebnis zurück."""
        ...

    def get_available_tools(self) -> list[ToolDefinition]:
        """Gibt die Liste aller verfügbaren Tools zurück."""
        ...


@runtime_checkable
class AgentRuntime(Protocol):
    """Interface für die Agent-Runtime (NemoClaw/OpenClaw).

    Die Runtime führt den Agent-Loop aus: LLM-Aufruf → Tool-Calls →
    Ergebnis zurück → nächster LLM-Aufruf → ... bis der Agent fertig ist.
    """

    async def run_agent(
        self,
        system_prompt: str,
        user_message: str,
        tools: list[ToolDefinition],
        tool_executor: ToolExecutor,
        max_iterations: int = 20,
    ) -> AgentResult:
        """Startet den Agent-Loop bis der Agent seine Aufgabe abgeschlossen hat."""
        ...

    async def stop(self) -> None:
        """Stoppt den laufenden Agent sofort."""
        ...

"""
Graceful Degradation für den Chat-Agent.

Wird aktiviert wenn NemoClaw nicht verfügbar ist. Wählt automatisch
den besten verfügbaren Fallback-Provider (Claude API, Azure, Ollama)
und loggt die Degradation als Audit-Event.
"""

from datetime import UTC, datetime

from src.agents.chat_system_prompt import load_system_prompt
from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Typ-Alias (gleich wie in chat_agent.py)
ToolStep = dict[str, str | int | bool]

# Gecachter Fallback-Provider (einmal erstellt, wiederverwendet)
_fallback_provider: object | None = None


async def try_init_nemoclaw(
    runtime_ref: NemoClawRuntime | None,
) -> tuple[NemoClawRuntime | None, str | None]:
    """Versucht NemoClaw zu initialisieren.

    Gibt (runtime, None) zurück wenn alles ok ist,
    oder (None, Fehlerbeschreibung) bei Problemen.
    """
    # Verfügbarkeit prüfen (gecacht, 30 Sekunden TTL)
    availability = NemoClawRuntime.check_availability()
    if not availability.get("available", False):
        return None, availability.get("reason", "NemoClaw nicht verfügbar")

    if runtime_ref is None:
        try:
            runtime_ref = NemoClawRuntime()
        except Exception as error:
            return None, f"NemoClaw-Initialisierung fehlgeschlagen: {error}"

    return runtime_ref, None


def get_fallback_provider() -> tuple[object | None, str]:
    """Gibt den konfigurierten Fallback-Provider und dessen Namen zurück.

    Nutzt die Provider-Factory aus llm_provider.py.
    Gibt (None, 'keiner') zurück wenn kein Provider verfügbar ist.
    """
    global _fallback_provider

    if _fallback_provider is not None:
        from src.shared.config import get_settings
        return _fallback_provider, get_settings().llm_provider

    from src.agents.llm_provider import create_llm_provider
    from src.shared.config import get_settings
    settings = get_settings()

    provider = create_llm_provider()
    if provider is not None:
        _fallback_provider = provider
        return provider, settings.llm_provider

    # Kein Provider konfiguriert — verfügbare Provider durchgehen
    for name, factory in _PROVIDER_FACTORIES:
        try:
            candidate = factory()
            if candidate is not None:
                _fallback_provider = candidate
                return candidate, name
        except Exception:  # noqa: S110, S112
            continue

    return None, "keiner"


def _try_create_claude_provider() -> object | None:
    """Versucht den Claude API Provider zu erstellen."""
    from src.shared.config import get_settings
    settings = get_settings()
    if settings.has_claude_key():
        from src.agents.claude_api_provider import ClaudeApiProvider
        return ClaudeApiProvider()
    return None


def _try_create_ollama_provider() -> object | None:
    """Versucht den Ollama Provider zu erstellen."""
    from src.agents.ollama_provider import OllamaProvider
    return OllamaProvider()


# Provider-Reihenfolge für automatische Erkennung
_PROVIDER_FACTORIES: list[tuple[str, object]] = [
    ("claude", _try_create_claude_provider),
    ("ollama", _try_create_ollama_provider),
]


async def log_fallback_event(nemoclaw_error: str, fallback_provider: str) -> None:
    """Schreibt ein Audit-Event für die Fallback-Aktivierung."""
    try:
        from src.api.server import get_db
        from src.shared.repositories import AuditLogRepository
        from src.shared.types.models import AuditLogEntry

        db = await get_db()
        repo = AuditLogRepository(db)
        await repo.create(AuditLogEntry(
            action="nemoclaw_fallback",
            resource_type="system",
            details={
                "nemoclaw_error": nemoclaw_error[:500],
                "fallback_provider": fallback_provider,
                "timestamp": datetime.now(UTC).isoformat(),
            },
            triggered_by="system",
        ))
    except Exception as audit_error:
        # Audit-Fehler darf den Fallback nicht blockieren
        logger.warning("Audit-Event konnte nicht geschrieben werden", error=str(audit_error))

    logger.warning(
        "NemoClaw Fallback aktiviert",
        nemoclaw_error=nemoclaw_error,
        fallback_provider=fallback_provider,
    )


async def run_fallback_inference(
    provider: object,
    messages: list[dict[str, str]],
    session_id: str,
) -> tuple[str, list[ToolStep]]:
    """Führt Inference über den Fallback-Provider durch.

    Nutzt send_messages() des Providers direkt (ohne Sandbox-Isolation).
    Tool-Ausführung ist im Fallback-Modus NICHT verfügbar.
    """
    from src.shared.types.agent_runtime import LlmMessage

    system_prompt = load_system_prompt()

    # Messages ins LlmMessage-Format konvertieren
    llm_messages: list[LlmMessage] = [
        LlmMessage(role="system", content=system_prompt),
    ]
    for msg in messages:
        llm_messages.append(LlmMessage(role=msg["role"], content=msg["content"]))

    response = await provider.send_messages(llm_messages)  # type: ignore[union-attr]
    return response.content, []

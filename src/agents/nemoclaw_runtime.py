"""
NemoClaw Agent-Runtime für SentinelClaw.

Nutzt die NemoClaw OpenShell-Sandbox (Landlock + seccomp + netns) als
isolierte Ausführungsumgebung. Führt den OpenClaw-Agent 'sentinelclaw'
in der Sandbox aus. Der LLM-Provider ist über den OpenShell Gateway
konfigurierbar (Claude, Azure, Ollama, NVIDIA NIM).

Architektur:
  SentinelClaw API → SSH → NemoClaw-Sandbox → OpenClaw Agent → LLM-Provider
"""

import asyncio
import shlex
from uuid import uuid4

from src.shared.config import get_settings
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import AgentResult, OpenClawConfig

logger = get_logger(__name__)


def _build_ssh_command(config: OpenClawConfig) -> list[str]:
    """Baut den SSH-Befehl für die Verbindung zur OpenShell-Sandbox."""
    proxy_cmd = (
        f"openshell ssh-proxy "
        f"--gateway-name {config.gateway_name} "
        f"--name {config.sandbox_name}"
    )
    return [
        "ssh",
        "-o", f"ProxyCommand={proxy_cmd}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", f"ConnectTimeout={config.ssh_timeout}",
        f"sandbox@openshell-{config.sandbox_name}",
    ]


# OpenClaw Agent-Definition (JSON für --agents Flag)
_AGENT_DEF = (
    '{"sentinelclaw":{'
    '"description":"SentinelClaw Security-Analyst für Penetration-Tests",'
    '"prompt":"Du arbeitest als Security-Assistent in der SentinelClaw-Plattform. '
    'Wenn nach Tools gefragt, liste NUR die Security-Tools aus der AGENT.md auf. '
    'Erwähne NIEMALS interne Tools (Read, Write, Edit, Bash, Glob, Grep, etc.). '
    'Antworte auf Deutsch mit Markdown."}}'
)


def _build_cli_command(
    system_prompt: str,
    user_message: str,
) -> str:
    """Baut den OpenClaw Agent-Befehl für die Sandbox.

    Nutzt den 'sentinelclaw' Agent mit AGENT.md als Projektkontext.
    Der system_prompt wird als --append-system-prompt übergeben
    (dynamische Tool-Liste, autorisierte Ziele).
    """
    escaped_prompt = shlex.quote(system_prompt)
    escaped_message = shlex.quote(user_message)

    return (
        f"cd /sandbox && "
        f"claude --print "
        f"--agent sentinelclaw "
        f"--agents {shlex.quote(_AGENT_DEF)} "
        f"--append-system-prompt-file /sandbox/AGENT.md "
        f"--allowedTools 'Bash(*)' "
        f"-p {escaped_message}"
    )


class NemoClawRuntime:
    """Agent-Runtime basierend auf NemoClaw/OpenShell.

    Führt den OpenClaw-Agent 'sentinelclaw' in der isolierten
    OpenShell-Sandbox aus. Die Sandbox bietet Landlock + seccomp +
    netns Isolation. Der LLM-Provider ist über den OpenShell
    Gateway konfigurierbar.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._config = OpenClawConfig(
            gateway_name=settings.openshell_gateway_name,
            sandbox_name=settings.openshell_sandbox_name,
            agent_id=settings.openclaw_agent_id,
            agent_timeout=settings.openclaw_agent_timeout,
        )
        self._current_process: asyncio.subprocess.Process | None = None

    async def run_agent(
        self,
        system_prompt: str,
        user_message: str = "",
        tools: list | None = None,
        tool_executor: object | None = None,
        max_iterations: int = 20,
        session_id: str | None = None,
        messages: list[dict[str, str]] | None = None,
    ) -> AgentResult:
        """Führt den OpenClaw-Agent in der NemoClaw-Sandbox aus.

        Jeder Aufruf ist eine frische Session (kein akkumulierter Kontext).
        Chat-History wird über den user_message-Parameter mitgesendet.
        """
        if KillSwitch().is_active():
            raise RuntimeError("Kill-Switch ist aktiv")

        if not session_id:
            session_id = f"sc-{uuid4().hex[:8]}"

        # User-Nachricht zusammenbauen (ggf. mit History)
        full_message = _build_user_message(user_message, messages)

        # OpenClaw Agent-Befehl in der Sandbox ausführen
        cli_cmd = _build_cli_command(system_prompt, full_message)
        ssh_args = _build_ssh_command(self._config)

        logger.info(
            "NemoClaw Inference gestartet",
            sandbox=self._config.sandbox_name,
            session_id=session_id,
        )

        process = await asyncio.create_subprocess_exec(
            *ssh_args, cli_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._current_process = process

        try:
            total_timeout = self._config.agent_timeout + 30
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=total_timeout,
            )
        except TimeoutError:
            process.kill()
            raise RuntimeError(
                f"NemoClaw Inference Timeout nach {self._config.agent_timeout}s"
            )
        finally:
            self._current_process = None

        text = stdout.decode("utf-8", errors="replace").strip()

        if not text:
            err = stderr.decode("utf-8", errors="replace").strip()
            if process.returncode != 0:
                raise RuntimeError(f"NemoClaw Fehler: {err[:300]}")
            raise RuntimeError("NemoClaw: Keine Antwort erhalten")

        logger.info(
            "NemoClaw Inference abgeschlossen",
            session_id=session_id,
            content_length=len(text),
        )

        return AgentResult(
            final_output=text,
            steps_taken=0,
            session_id=session_id,
        )

    async def stop(self) -> None:
        """Stoppt den laufenden Agent und aktiviert den Kill-Switch."""
        KillSwitch().activate(
            triggered_by="NemoClawRuntime.stop()",
            reason="Agent wurde manuell gestoppt",
        )
        if self._current_process is not None:
            try:
                self._current_process.kill()
            except ProcessLookupError:
                pass
            self._current_process = None

    async def check_sandbox_status(self) -> dict:
        """Prüft den Status der OpenShell-Sandbox."""
        ssh_args = _build_ssh_command(self._config)
        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_args, "echo OK",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            ok = stdout.decode().strip() == "OK"
            return {"status": "ready" if ok else "error"}
        except Exception as error:
            return {"status": "unreachable", "error": str(error)}

    @property
    def is_openclaw_native(self) -> bool:
        """Echte NemoClaw/OpenShell Integration."""
        return True


def _build_user_message(
    current_message: str,
    messages: list[dict[str, str]] | None,
) -> str:
    """Baut die User-Nachricht mit optionaler Chat-History.

    Da der OpenClaw-Agent im --print Modus nur eine einzige
    Nachricht akzeptiert, wird die History als Kontext-Block
    vorangestellt.
    """
    if not messages:
        return current_message

    # Letzte Nachricht ist die aktuelle User-Nachricht
    # Die vorherigen sind History-Kontext
    history_parts: list[str] = []
    for msg in messages[:-1]:
        role = "User" if msg["role"] == "user" else "Agent"
        history_parts.append(f"[{role}]: {msg['content']}")

    if not history_parts:
        return current_message

    history_block = "\n".join(history_parts)
    return (
        f"[Bisheriger Chat-Verlauf]\n{history_block}\n\n"
        f"[Aktuelle Nachricht]\n{current_message}"
    )

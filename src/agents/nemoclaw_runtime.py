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
import shutil
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


# OpenClaw Agent-Definition für den sentinelclaw-Agent
_AGENT_CONFIG = {
    "name": "sentinelclaw",
    "description": "SentinelClaw Security-Analyst für Penetration-Tests",
    "prompt": (
        "Du arbeitest als Security-Assistent in der SentinelClaw-Plattform. "
        "Wenn nach Tools gefragt, liste NUR die Security-Tools aus der AGENT.md auf. "
        "Antworte auf Deutsch mit Markdown."
    ),
    "allowed_tools": ["bash"],
}


def _build_cli_command(
    system_prompt: str,
    user_message: str,
) -> str:
    """Baut den OpenClaw Agent-Befehl für die NemoClaw-Sandbox.

    Nutzt den OpenClaw-Agent 'sentinelclaw' in der OpenShell-Sandbox.
    Der LLM-Provider wird über den NemoClaw-Gateway konfiguriert
    (Privacy-Router: Claude, Azure, Ollama).
    """
    escaped_message = shlex.quote(user_message)

    return (
        f"cd /sandbox && "
        f"openclaw run "
        f"--agent sentinelclaw "
        f"--system-prompt-file /sandbox/AGENT.md "
        f"--tools bash "
        f"--output text "
        f"-- {escaped_message}"
    )


class NemoClawRuntime:
    """Agent-Runtime: OpenClaw in NemoClaw/OpenShell-Sandbox."""

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
        """Führt OpenClaw-Agent aus. Streamt stdout live über WebSocket."""
        if KillSwitch().is_active():
            raise RuntimeError("Kill-Switch ist aktiv")

        # Verfügbarkeit prüfen
        status = self.check_availability()
        use_docker_fallback = not status["available"]

        from src.shared.config import get_settings
        if use_docker_fallback and not get_settings().debug:
            raise RuntimeError(f"NemoClaw nicht verfügbar: {status['reason']}")

        if not session_id:
            session_id = f"sc-{uuid4().hex[:8]}"

        full_message = _build_user_message(user_message, messages)

        if use_docker_fallback:
            # Dev-Fallback: Claude API direkt nutzen (ohne NemoClaw/OpenClaw)
            logger.info("NemoClaw Fallback: Claude API direkt", session_id=session_id)
            return await self._fallback_claude_api(system_prompt, full_message, session_id)
        else:
            # Produktion: OpenClaw via NemoClaw/OpenShell SSH
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

        # Streaming: stdout Zeile für Zeile lesen und live pushen
        lines: list[str] = []
        try:
            total_timeout = self._config.agent_timeout + 30
            lines = await asyncio.wait_for(
                self._stream_output(process, session_id),
                timeout=total_timeout,
            )
        except TimeoutError:
            process.kill()
            raise RuntimeError(
                f"NemoClaw Inference Timeout nach {self._config.agent_timeout}s"
            )
        finally:
            self._current_process = None

        text = "\n".join(lines).strip()

        if not text:
            err = ""
            if process.stderr:
                raw = await process.stderr.read()
                err = raw.decode("utf-8", errors="replace").strip()
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

    async def _fallback_claude_api(
        self, system_prompt: str, user_message: str, session_id: str,
    ) -> AgentResult:
        """Dev-Fallback: Claude API direkt nutzen wenn NemoClaw nicht da."""
        try:
            from src.agents.claude_api_provider import ClaudeApiProvider
            provider = ClaudeApiProvider()
        except Exception as err:
            raise RuntimeError(
                "NemoClaw nicht verfügbar und Claude API-Fallback fehlgeschlagen. "
                "Setze SENTINEL_CLAUDE_API_KEY in .env oder installiere NemoClaw."
            ) from err

        from src.shared.types.agent_runtime import LlmMessage
        messages = [
            LlmMessage(role="system", content=system_prompt),
            LlmMessage(role="user", content=user_message),
        ]
        response = await provider.send_messages(messages)
        return AgentResult(
            final_output=response.content,
            steps_taken=0,
            session_id=session_id,
        )

    async def _stream_output(
        self, process: asyncio.subprocess.Process, session_id: str,
    ) -> list[str]:
        """Liest stdout zeilenweise und pusht live über WebSocket."""
        lines: list[str] = []
        assert process.stdout is not None
        try:
            from src.api.websocket_manager import ws_manager
        except Exception:
            ws_manager = None  # type: ignore[assignment]
        while True:
            raw_line = await process.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            lines.append(line)

            # Live-Push über WebSocket wenn verfügbar
            if ws_manager is None:
                continue

            try:
                # Tool-Erkennung: Bash-Befehle und deren Output
                if line.startswith("$ ") or line.startswith("❯ "):
                    await ws_manager.broadcast("agent_step", {
                        "type": "tool_start",
                        "tool": "bash",
                        "command": line[2:][:200],
                    })
                elif line.startswith("✓") or line.startswith("✅"):
                    await ws_manager.broadcast("agent_step", {
                        "type": "tool_result",
                        "tool": "bash",
                        "success": True,
                        "output_preview": line[:200],
                    })
                elif line.startswith("✗") or line.startswith("❌"):
                    await ws_manager.broadcast("agent_step", {
                        "type": "tool_result",
                        "tool": "bash",
                        "success": False,
                        "output_preview": line[:200],
                    })
                elif len(lines) % 10 == 0:
                    # Alle 10 Zeilen ein Thinking-Update
                    await ws_manager.broadcast("agent_step", {
                        "type": "thinking",
                        "message": f"Agent arbeitet... ({len(lines)} Zeilen)",
                    })
            except Exception:
                pass  # WS-Push Fehler ignorieren

        # Warten bis Prozess beendet
        await process.wait()
        return lines

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

    @staticmethod
    def check_availability() -> dict:
        """Prüft ob die NemoClaw/OpenShell-Infrastruktur verfügbar ist."""
        result: dict = {"available": False, "reason": "", "details": {}}

        # 1. openshell CLI vorhanden?
        openshell_path = shutil.which("openshell")
        result["details"]["openshell_cli"] = openshell_path is not None
        if not openshell_path:
            result["reason"] = (
                "openshell CLI nicht installiert. "
                "Installiere NemoClaw: pip install nemoclaw"
            )
            return result

        # 2. openclaw CLI vorhanden?
        openclaw_path = shutil.which("openclaw")
        result["details"]["openclaw_cli"] = openclaw_path is not None
        if not openclaw_path:
            result["reason"] = (
                "openclaw CLI nicht installiert. "
                "Installiere OpenClaw: pip install openclaw"
            )
            return result

        result["available"] = True
        result["reason"] = "Bereit"
        return result

    @property
    def is_openclaw_native(self) -> bool:
        """Echte NemoClaw/OpenShell Integration."""
        return True


def _build_user_message(
    current_message: str, messages: list[dict[str, str]] | None,
) -> str:
    """Baut User-Nachricht mit optionaler Chat-History als Kontext-Block."""
    if not messages:
        return current_message
    parts = []
    for msg in messages[:-1]:
        role = "User" if msg["role"] == "user" else "Agent"
        parts.append(f"[{role}]: {msg['content']}")
    if not parts:
        return current_message
    return f"[Chat-Verlauf]\n{chr(10).join(parts)}\n\n[Nachricht]\n{current_message}"

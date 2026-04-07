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
import shutil
import time
from uuid import uuid4

from src.agents.nemoclaw_commands import (
    build_cli_command,
    build_ssh_command,
    build_user_message,
    push_ws_line_event,
)
from src.shared.config import get_settings
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import AgentResult, OpenClawConfig

logger = get_logger(__name__)


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

        if not session_id:
            session_id = f"sc-{uuid4().hex[:8]}"

        full_message = build_user_message(user_message, messages)
        cli_cmd = build_cli_command(system_prompt, full_message, session_id)
        ssh_args = build_ssh_command(self._config)

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

        # Parallelen Log-Tail starten für Live-Monitoring
        from src.agents.sandbox_log_stream import stream_sandbox_logs
        log_task = asyncio.create_task(
            stream_sandbox_logs(self._config.sandbox_name)
        )

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
            log_task.cancel()  # Log-Tail stoppen wenn Agent fertig

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
            from src.agents.sandbox_log_stream import _ANSI_RE
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            line = _ANSI_RE.sub("", line)
            lines.append(line)

            # Live-Push über WebSocket wenn verfügbar
            if ws_manager is None:
                continue

            try:
                push_ws_line_event(ws_manager, line, len(lines))
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
        ssh_args = build_ssh_command(self._config)
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

    # Cache für Verfügbarkeitsprüfung (Klassen-Variablen)
    _availability_cache: dict | None = None
    _availability_cache_timestamp: float = 0.0
    _AVAILABILITY_CACHE_TTL: float = 30.0  # Sekunden

    @classmethod
    def check_availability(cls) -> dict:
        """Prüft ob die NemoClaw/OpenShell-Infrastruktur verfügbar ist.

        Ergebnis wird für 30 Sekunden gecacht um wiederholte
        Aufrufe (Health-Checks, Status-Endpoint) performant zu halten.
        """
        now = time.monotonic()
        if (
            cls._availability_cache is not None
            and (now - cls._availability_cache_timestamp) < cls._AVAILABILITY_CACHE_TTL
        ):
            return cls._availability_cache

        result = cls._run_availability_checks()
        cls._availability_cache = result
        cls._availability_cache_timestamp = now
        return result

    @classmethod
    def _run_availability_checks(cls) -> dict:
        """Führt die eigentlichen Verfügbarkeitsprüfungen durch."""
        result: dict = {
            "available": False,
            "reason": "",
            "details": {},
            "last_check": time.time(),
        }

        # 1. openshell CLI vorhanden?
        openshell_path = shutil.which("openshell")
        result["details"]["openshell_cli"] = openshell_path is not None
        if not openshell_path:
            result["reason"] = (
                "openshell CLI nicht installiert. "
                "Installiere NemoClaw: pip install nemoclaw"
            )
            logger.debug("NemoClaw: openshell Binary nicht gefunden")
            return result

        # 2. OpenClaw Agent-Runtime prüfen (claude lokal ODER in Sandbox)
        claude_path = shutil.which("claude")
        result["details"]["openclaw_runtime"] = claude_path is not None

        # 3. SSH-Konnektivität testen (echo-Ping mit Timeout)
        ssh_ok, ssh_error = cls._test_ssh_connectivity()
        result["details"]["ssh_connectivity"] = ssh_ok
        if not ssh_ok:
            result["reason"] = f"SSH-Verbindung fehlgeschlagen: {ssh_error}"
            logger.warning(
                "NemoClaw: SSH-Konnektivitätstest fehlgeschlagen",
                error=ssh_error,
            )
            return result

        result["available"] = True
        result["reason"] = "Bereit"
        logger.debug("NemoClaw: Verfügbarkeitsprüfung erfolgreich")
        return result

    @staticmethod
    def _test_ssh_connectivity() -> tuple[bool, str]:
        """Testet Gateway-Konnektivität via openshell status.

        Synchroner Subprocess-Aufruf mit 5 Sekunden Timeout.
        Gibt (True, '') bei Erfolg oder (False, Fehlerbeschreibung) zurück.
        """
        import subprocess

        try:
            completed = subprocess.run(
                ["openshell", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if completed.returncode == 0 and "Connected" in completed.stdout:
                return True, ""

            # Fehlermeldung aus stderr oder Returncode ableiten
            stderr = completed.stderr.strip()[:200]
            if "connection refused" in stderr.lower():
                return False, "Verbindung abgelehnt (Gateway nicht erreichbar)"
            if "timeout" in stderr.lower():
                return False, "SSH-Timeout (Gateway antwortet nicht)"
            return False, stderr or f"Exit-Code {completed.returncode}"

        except subprocess.TimeoutExpired:
            return False, "SSH-Timeout nach 5 Sekunden"
        except FileNotFoundError:
            return False, "openshell Binary nicht ausführbar"
        except OSError as error:
            return False, f"OS-Fehler: {error}"

    @property
    def is_openclaw_native(self) -> bool:
        """Echte NemoClaw/OpenShell Integration."""
        return True

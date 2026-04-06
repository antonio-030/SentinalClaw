"""
Sandbox-Executor — Führt Befehle sicher im Docker-Container aus.

Alle Tool-Aufrufe (nmap, nuclei, etc.) laufen über dieses Modul.
Kein subprocess.run mit User-Input, kein Shell=True, nur
parametrisierte Docker-API-Aufrufe.
"""

import asyncio
from dataclasses import dataclass

import docker.errors

import docker
from src.shared.config import get_settings
from src.shared.constants.defaults import ALLOWED_SANDBOX_BINARIES
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass
class ExecutionResult:
    """Ergebnis einer Befehlsausführung in der Sandbox."""

    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    timed_out: bool = False


class SandboxExecutor:
    """Führt Befehle im isolierten Sandbox-Container aus.

    Nutzt die Docker-API (nicht subprocess!) um Befehle im
    Sandbox-Container auszuführen. Der Container läuft bereits
    (via docker compose) und wird per docker exec angesprochen.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = docker.from_env()
        self._container_name = "sentinelclaw-sandbox"

    async def execute(
        self,
        command: list[str],
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Führt einen Befehl im Sandbox-Container aus.

        Das Command wird als Liste übergeben (parametrisiert).
        KEIN Shell-String, KEINE String-Konkatenation.
        """
        if not command:
            raise ValueError("Leeres Command übergeben")

        # Kill-Switch-Prüfung vor jeder Tool-Ausführung
        if KillSwitch().is_active():
            raise RuntimeError("Kill-Switch aktiv — Tool-Ausführung blockiert")

        # Prüfe ob das Binary in der Allowlist ist
        binary = command[0]
        if binary not in ALLOWED_SANDBOX_BINARIES:
            raise PermissionError(
                f"Binary '{binary}' ist nicht erlaubt. "
                f"Erlaubt: {', '.join(sorted(ALLOWED_SANDBOX_BINARIES))}"
            )

        effective_timeout = timeout or self._settings.sandbox_timeout

        logger.info(
            "Sandbox-Befehl",
            binary=binary,
            arg_count=len(command) - 1,
            timeout=effective_timeout,
        )

        # Docker exec im Threadpool ausführen (docker-py ist synchron)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._execute_sync,
            command,
            effective_timeout,
        )

    def _execute_sync(
        self,
        command: list[str],
        timeout: int,
    ) -> ExecutionResult:
        """Synchrone Ausführung — wird im Threadpool aufgerufen."""
        import time

        start_time = time.monotonic()

        try:
            container = self._client.containers.get(self._container_name)
        except docker.errors.NotFound:
            raise RuntimeError(
                f"Sandbox-Container '{self._container_name}' nicht gefunden. "
                "Bitte 'docker compose up sandbox' ausführen."
            )

        try:
            # Docker exec — parametrisiert, kein Shell
            exec_result = container.exec_run(
                cmd=command,
                stdout=True,
                stderr=True,
                demux=True,
                user="scanner",
            )

            duration = time.monotonic() - start_time

            stdout_raw = exec_result.output[0] if exec_result.output[0] else b""
            stderr_raw = exec_result.output[1] if exec_result.output[1] else b""

            result = ExecutionResult(
                stdout=stdout_raw.decode("utf-8", errors="replace"),
                stderr=stderr_raw.decode("utf-8", errors="replace"),
                exit_code=exec_result.exit_code,
                duration_seconds=duration,
                timed_out=False,
            )

            logger.info(
                "Sandbox-Befehl abgeschlossen",
                binary=command[0],
                exit_code=result.exit_code,
                duration_s=round(result.duration_seconds, 1),
                stdout_lines=result.stdout.count("\n"),
            )

            return result

        except Exception as error:
            duration = time.monotonic() - start_time
            logger.error(
                "Sandbox-Befehl fehlgeschlagen",
                binary=command[0],
                error=str(error),
                duration_s=round(duration, 1),
            )
            return ExecutionResult(
                stdout="",
                stderr=str(error),
                exit_code=-1,
                duration_seconds=duration,
                timed_out="timeout" in str(error).lower(),
            )

    def is_sandbox_running(self) -> bool:
        """Prüft ob der Sandbox-Container läuft."""
        try:
            container = self._client.containers.get(self._container_name)
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    def get_sandbox_info(self) -> dict:
        """Gibt Informationen über den Sandbox-Container zurück."""
        try:
            container = self._client.containers.get(self._container_name)
            return {
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "unknown",
            }
        except docker.errors.NotFound:
            return {"name": self._container_name, "status": "not_found", "image": "n/a"}

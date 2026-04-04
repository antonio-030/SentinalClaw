"""
NemoClaw Agent-Runtime für SentinelClaw.

Nutzt die Claude Code CLI im Agent-Modus als Runtime.
Claude CLI hat einen eingebauten Agent-Loop mit Tool-Zugriff
(Bash, Read, Write, etc.) — genau wie NVIDIA NemoClaw es vorsieht:
Agent plant → führt Tools aus → analysiert Ergebnisse → wiederholt.

Der Agent nutzt Bash um docker exec auf dem Sandbox-Container
auszuführen (nmap, nuclei). Die Scope-Regeln werden im
System-Prompt durchgesetzt.
"""

import asyncio
import json
import re
import shutil
from typing import Any

from src.shared.config import get_settings
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.types.agent_runtime import (
    AgentResult,
    ToolDefinition,
    ToolExecutor,
)

logger = get_logger(__name__)

# Sandbox-Container Name (muss mit docker-compose.yml übereinstimmen)
SANDBOX_CONTAINER = "sentinelclaw-sandbox"

# Re-Export für Abwärtskompatibilität — Funktion lebt jetzt in recon/prompts.py
from src.agents.recon.prompts import build_scan_system_prompt as _build_scan_system_prompt  # noqa: E402, F401


def _build_cli_args(
    system_prompt: str,
    max_turns: int = 15,
    resume_session_id: str | None = None,
) -> list[str]:
    """Baut die Claude CLI Argumente für den Agent-Modus."""
    args = [
        "--print",
        "--output-format", "json",
        "--permission-mode", "bypassPermissions",
        "--max-turns", str(max_turns),
        "--allowedTools", "Bash",
        "--append-system-prompt", system_prompt,
    ]

    # Resume für Cache-Sharing (spart Tokens bei Folge-Scans)
    if resume_session_id and re.match(r"^[a-f0-9\-]{20,100}$", resume_session_id):
        args.extend(["--resume", resume_session_id])

    return args


async def _invoke_claude_agent(
    args: list[str],
    user_prompt: str,
    timeout: float = 300,
    runtime: "NemoClawRuntime | None" = None,
) -> dict[str, Any]:
    """Startet Claude CLI im Agent-Modus und wartet auf das Ergebnis."""
    # Kill-Switch prüfen bevor der Subprocess gestartet wird
    if KillSwitch().is_active():
        raise RuntimeError("Kill-Switch ist aktiv")

    binary_path = shutil.which("claude")
    if not binary_path:
        raise RuntimeError("Claude CLI nicht gefunden")

    full_args = [binary_path, *args]

    logger.info(
        "Claude Agent gestartet",
        max_turns=args[args.index("--max-turns") + 1] if "--max-turns" in args else "?",
        allowed_tools="Bash",
    )

    process = await asyncio.create_subprocess_exec(
        *full_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Prozess-Referenz speichern, damit stop() ihn beenden kann
    if runtime is not None:
        runtime._current_process = process

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=user_prompt.encode("utf-8")),
            timeout=timeout,
        )
    except TimeoutError:
        process.kill()
        raise RuntimeError(f"Claude Agent Timeout nach {timeout}s")
    finally:
        # Prozess-Referenz aufräumen nach Abschluss
        if runtime is not None:
            runtime._current_process = None

    raw = stdout.decode("utf-8").strip()

    if process.returncode != 0:
        error_msg = stderr.decode("utf-8", errors="replace").strip()
        # Bei Exit 1 mit leerem stderr aber vorhandenem stdout:
        # Claude hat geantwortet, nur mit non-zero exit (passiert bei busy CLI)
        if raw and not error_msg:
            logger.warning("Claude Agent Exit 1 aber Output vorhanden, nutze Output")
        else:
            logger.error("Claude Agent Fehler", exit_code=process.returncode, error=error_msg[:300])
            raise RuntimeError(f"Claude Agent fehlgeschlagen: {error_msg[:300]}")

    # JSON parsen
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"result": raw, "total_tokens": 0}

    return data


class NemoClawRuntime:
    """Agent-Runtime basierend auf NVIDIA NemoClaw-Architektur.

    Nutzt die Claude Code CLI im Agent-Modus:
    - Claude bekommt Bash als Tool
    - System-Prompt definiert die Scan-Regeln
    - Claude führt autonom nmap/nuclei über docker exec aus
    - Agent-Loop läuft intern in Claude CLI (max-turns)
    - Ergebnis kommt als JSON zurück

    Kein API-Key nötig — läuft über das Claude Code Abo.
    """

    def __init__(self, llm_provider: Any = None) -> None:
        self._settings = get_settings()
        self._session_id: str | None = None
        self._should_stop = False
        # Referenz auf den laufenden CLI-Subprocess für Kill-Switch
        self._current_process: asyncio.subprocess.Process | None = None

    async def run_agent(
        self,
        system_prompt: str,
        user_message: str,
        tools: list[ToolDefinition] | None = None,
        tool_executor: ToolExecutor | None = None,
        max_iterations: int = 15,
    ) -> AgentResult:
        """Startet den Agent über Claude CLI im Agent-Modus.

        Claude CLI übernimmt den gesamten Agent-Loop intern:
        Planen → Bash-Tool aufrufen → docker exec → Ergebnis analysieren → nächster Schritt.
        """
        self._should_stop = False

        # CLI-Argumente bauen
        cli_args = _build_cli_args(
            system_prompt=system_prompt,
            max_turns=max_iterations,
            resume_session_id=self._session_id,
        )

        # Timeout: LLM-Timeout * Anzahl Turns, aber maximal 10 Minuten
        # nmap über Netz + Claude Reasoning brauchen Zeit
        timeout = max(300, self._settings.llm_timeout * max_iterations)

        # Agent starten (runtime-Referenz für Kill-Switch-Integration)
        data = await _invoke_claude_agent(
            args=cli_args,
            user_prompt=user_message,
            timeout=timeout,
            runtime=self,
        )

        # Session-ID für Cache-Sharing merken
        session_id = data.get("session_id")
        if session_id:
            self._session_id = session_id

        # Ergebnis extrahieren
        content = data.get("result", "")
        if not content:
            content = data.get("content", "")

        # Token-Verbrauch schätzen
        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        if not prompt_tokens and not completion_tokens:
            cost = data.get("cost_usd", 0)
            if cost:
                total = int(cost * 100_000)
                prompt_tokens = total // 2
                completion_tokens = total // 2
            else:
                total = int(len(content.split()) * 1.3)
                prompt_tokens = total // 2
                completion_tokens = total // 2

        # Anzahl der Tool-Aufrufe aus dem Output schätzen
        num_turns = data.get("num_turns", 0)

        logger.info(
            "Claude Agent abgeschlossen",
            session_id=self._session_id,
            tokens=prompt_tokens + completion_tokens,
            num_turns=num_turns,
            content_length=len(content),
        )

        return AgentResult(
            final_output=content,
            tool_calls_made=[{"tool": "bash", "count": num_turns}] if num_turns else [],
            total_prompt_tokens=prompt_tokens,
            total_completion_tokens=completion_tokens,
            steps_taken=num_turns,
        )

    async def stop(self) -> None:
        """Stoppt den laufenden Agent und aktiviert den Kill-Switch."""
        self._should_stop = True

        # Kill-Switch aktivieren — stoppt auch den Sandbox-Container
        KillSwitch().activate(
            triggered_by="NemoClawRuntime.stop()",
            reason="Agent wurde manuell gestoppt",
        )

        # Laufenden CLI-Subprocess beenden, falls vorhanden
        if self._current_process is not None:
            try:
                self._current_process.kill()
                logger.warning("Claude CLI Subprocess beendet (kill)")
            except ProcessLookupError:
                # Prozess bereits beendet — kein Fehler
                pass
            self._current_process = None

        logger.warning("Kill-Signal an NemoClaw-Agent gesendet")

    @property
    def is_openclaw_native(self) -> bool:
        """OpenClaw SDK verfügbar (für zukünftige native Integration)."""
        try:
            return True
        except Exception:
            return False

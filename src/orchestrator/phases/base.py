"""
Basis-Funktion für alle Scan-Phasen.

Jede Phase ist ein eigenständiger Agent-Aufruf über die
NemoClaw-Runtime (OpenClaw in OpenShell-Sandbox) mit eigener
DB-Persistenz, Fehlerbehandlung und Ergebnis-Parsing.
"""

import time
from dataclasses import dataclass, field
from uuid import UUID

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import ScanPhaseRepository

logger = get_logger(__name__)


@dataclass
class PhaseResult:
    """Ergebnis einer einzelnen Scan-Phase."""

    phase_name: str
    phase_number: int
    status: str = "pending"  # pending, running, completed, failed, skipped
    raw_output: str = ""
    duration_seconds: float = 0.0
    tokens_used: int = 0
    hosts_found: list[dict] = field(default_factory=list)
    ports_found: list[dict] = field(default_factory=list)
    findings_found: list[dict] = field(default_factory=list)
    error: str | None = None


async def execute_phase(
    phase_name: str,
    phase_number: int,
    system_prompt: str,
    user_prompt: str,
    scan_job_id: UUID,
    phase_repo: ScanPhaseRepository,
    max_turns: int = 5,
    timeout: float = 180,
    runtime: NemoClawRuntime | None = None,
    session_id: str | None = None,
) -> PhaseResult:
    """Fuehrt eine Scan-Phase aus mit DB-Tracking.

    1. Erstellt Phase-Eintrag in DB (status: running)
    2. Ruft OpenClaw-Agent in der NemoClaw-Sandbox auf
    3. Speichert Ergebnis in DB (status: completed/failed)
    4. Gibt PhaseResult zurueck
    """
    result = PhaseResult(
        phase_name=phase_name,
        phase_number=phase_number,
    )

    # Phase in DB erstellen
    phase_id = await phase_repo.create(
        scan_job_id=scan_job_id,
        phase_number=phase_number,
        name=phase_name,
        description=user_prompt[:200],
    )

    # Status: running
    await phase_repo.update_status(phase_id, "running")
    result.status = "running"
    start_time = time.monotonic()

    logger.info(
        "Phase gestartet",
        phase=phase_name,
        number=phase_number,
        scan_id=str(scan_job_id),
    )

    # Kill-Switch-Prüfung vor der eigentlichen Ausführung
    if KillSwitch().is_active():
        logger.warning(
            "Kill-Switch aktiv — Phase übersprungen",
            phase=phase_name,
            scan_id=str(scan_job_id),
        )
        result.status = "skipped"
        result.error = "Kill-Switch aktiv — Phase nicht ausgeführt"
        await phase_repo.update_status(
            phase_id,
            status="skipped",
            error_message="Kill-Switch aktiv",
        )
        return result

    try:
        # OpenClaw Agent in der NemoClaw-Sandbox aufrufen
        if runtime is None:
            runtime = NemoClawRuntime()

        agent_result = await runtime.run_agent(
            system_prompt=system_prompt,
            user_message=user_prompt,
            max_iterations=max_turns,
            session_id=session_id or f"sc-scan-{str(scan_job_id)[:8]}-p{phase_number}",
        )

        content = agent_result.final_output
        duration = time.monotonic() - start_time

        result.raw_output = content
        result.duration_seconds = duration
        result.tokens_used = agent_result.total_prompt_tokens + agent_result.total_completion_tokens
        result.status = "completed"

        # Phase in DB aktualisieren
        await phase_repo.update_status(
            phase_id,
            status="completed",
            raw_output=content,
            duration_seconds=duration,
        )

        logger.info(
            "Phase abgeschlossen",
            phase=phase_name,
            duration_s=round(duration, 1),
            output_length=len(content),
        )

    except Exception as error:
        duration = time.monotonic() - start_time
        result.status = "failed"
        result.error = str(error)
        result.duration_seconds = duration

        await phase_repo.update_status(
            phase_id,
            status="failed",
            error_message=str(error)[:500],
            duration_seconds=duration,
        )

        logger.error(
            "Phase fehlgeschlagen",
            phase=phase_name,
            error=str(error),
            duration_s=round(duration, 1),
        )

    return result

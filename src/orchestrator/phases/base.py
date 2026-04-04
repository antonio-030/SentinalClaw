"""
Basis-Klasse für alle Scan-Phasen.

Jede Phase ist ein eigenständiger Agent-Aufruf mit eigener
DB-Persistenz, Fehlerbehandlung und Ergebnis-Parsing.
"""

import time
from dataclasses import dataclass, field
from uuid import UUID

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import (
    DiscoveredHostRepository,
    OpenPortRepository,
    ScanPhaseRepository,
)
from src.agents.nemoclaw_runtime import (
    NemoClawRuntime,
    SANDBOX_CONTAINER,
    _build_cli_args,
    _invoke_claude_agent,
)

logger = get_logger(__name__)


@dataclass
class PhaseResult:
    """Ergebnis einer einzelnen Scan-Phase."""

    phase_name: str
    phase_number: int
    status: str = "pending"  # pending, running, completed, failed
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
) -> PhaseResult:
    """Führt eine Scan-Phase aus mit DB-Tracking.

    1. Erstellt Phase-Eintrag in DB (status: running)
    2. Führt Claude-Agent-Aufruf aus
    3. Speichert Ergebnis in DB (status: completed/failed)
    4. Gibt PhaseResult zurück
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

    try:
        # Claude-Agent-Aufruf
        cli_args = _build_cli_args(
            system_prompt=system_prompt,
            max_turns=max_turns,
        )

        data = await _invoke_claude_agent(
            args=cli_args,
            user_prompt=user_prompt,
            timeout=timeout,
            runtime=runtime,
        )

        content = data.get("result", data.get("content", ""))
        num_turns = data.get("num_turns", 0)
        duration = time.monotonic() - start_time

        result.raw_output = content
        result.duration_seconds = duration
        result.tokens_used = num_turns * 5000
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

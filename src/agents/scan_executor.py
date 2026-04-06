"""
Scan-Tool-Executor für SentinelClaw (Fallback).

Führt Scan-Befehle im Docker-Sandbox-Container aus. Der primäre
Pfad nutzt OpenClaw in der NemoClaw-Sandbox direkt. Dieser Executor
ist der Fallback für den Docker-Container (sentinelclaw-sandbox).
"""

import asyncio

from src.shared.constants.defaults import ALLOWED_SANDBOX_BINARIES, TOOL_TIMEOUTS
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Docker-Container fuer Scan-Tools
SANDBOX_CONTAINER = "sentinelclaw-sandbox"


async def execute_scan_command(
    command_parts: list[str],
    timeout: int | None = None,
) -> str:
    """Fuehrt einen Scan-Befehl im Docker-Sandbox-Container aus.

    Validiert dass nur erlaubte Binaries ausgefuehrt werden.
    Gibt stdout zurueck, loggt stderr als Warnung.
    """
    if not command_parts:
        raise ValueError("Leerer Scan-Befehl")

    # Binary gegen Allowlist pruefen, Timeout aus Tool-Tabelle
    binary = command_parts[0]
    if timeout is None:
        timeout = TOOL_TIMEOUTS.get(binary, 120)
    if binary not in ALLOWED_SANDBOX_BINARIES:
        raise ValueError(
            f"Binary '{binary}' nicht erlaubt. "
            f"Erlaubt: {', '.join(sorted(ALLOWED_SANDBOX_BINARIES))}"
        )

    # Tools die ein Ziel brauchen: mindestens ein Argument pruefen
    tools_requiring_target = {"nmap", "nuclei", "curl", "dig", "whois"}
    if binary in tools_requiring_target and len(command_parts) < 2:
        raise ValueError(
            f"'{binary}' braucht mindestens ein Argument (Ziel/URL/Domain)"
        )

    # docker exec Befehl zusammenbauen
    full_command = ["docker", "exec", SANDBOX_CONTAINER, *command_parts]

    logger.info(
        "Scan-Befehl ausfuehren",
        binary=binary,
        container=SANDBOX_CONTAINER,
        args=command_parts[1:5],  # Erste 5 Argumente loggen
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()

        if err:
            logger.debug("Scan-Befehl stderr", binary=binary, stderr=err[:200])

        if proc.returncode != 0 and not out:
            raise RuntimeError(f"Scan fehlgeschlagen (Exit {proc.returncode}): {err[:300]}")

        logger.info(
            "Scan-Befehl abgeschlossen",
            binary=binary,
            output_length=len(out),
            exit_code=proc.returncode,
        )

        return out

    except TimeoutError:
        raise RuntimeError(f"Scan-Befehl Timeout nach {timeout}s: {' '.join(command_parts[:3])}")

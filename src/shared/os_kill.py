"""
OS-Level Kill für SentinelClaw (Kill-Pfad 4).

Letzter Fallback: Beendet Scanner-Prozesse direkt auf OS-Ebene
und entfernt alle SentinelClaw-Container mit Gewalt. Wird nur
aufgerufen wenn alle anderen Kill-Pfade versagt haben.

WICHTIG: Kein shell=True, alle Aufrufe parametrisiert.
"""

import asyncio
import subprocess

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Prozesse die bei einem OS-Kill beendet werden (nur Scanner-Binaries)
_SCANNER_PROCESSES = ["nmap", "nuclei", "curl", "nikto", "sslscan"]

# Präfix für Docker-Container die entfernt werden
_CONTAINER_PREFIX = "sentinelclaw-"


async def kill_scanner_processes() -> int:
    """Beendet alle Scanner-Prozesse auf OS-Ebene mit SIGKILL.

    Gibt die Anzahl erfolgreich beendeter Prozess-Gruppen zurück.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _kill_processes_sync)


def _kill_processes_sync() -> int:
    """Beendet Scanner-Prozesse synchron (parametrisiert, kein shell=True)."""
    killed_count = 0
    for process_name in _SCANNER_PROCESSES:
        try:
            result = subprocess.run(
                ["pkill", "-9", process_name],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                killed_count += 1
                logger.info("process_killed", process=process_name)
            # returncode 1 = kein Prozess gefunden (normal)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("pkill_failed", process=process_name, error=str(exc))

    logger.info("os_kill_completed", killed_groups=killed_count)
    return killed_count


async def force_remove_containers() -> int:
    """Entfernt alle SentinelClaw-Container mit Gewalt.

    Nutzt die Docker-API (nicht subprocess) um Container zu finden
    und zu entfernen. Gibt die Anzahl entfernter Container zurück.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _remove_containers_sync)


def _remove_containers_sync() -> int:
    """Entfernt Container synchron über die Docker-API."""
    removed = 0
    try:
        import docker as docker_lib
        client = docker_lib.from_env()

        # Alle Container mit dem SentinelClaw-Präfix finden
        containers = client.containers.list(all=True)
        for container in containers:
            if container.name and container.name.startswith(_CONTAINER_PREFIX):
                try:
                    container.remove(force=True)
                    removed += 1
                    logger.info(
                        "container_force_removed",
                        container=container.name,
                    )
                except Exception as exc:
                    logger.warning(
                        "container_remove_failed",
                        container=container.name,
                        error=str(exc),
                    )
    except Exception as exc:
        logger.warning("docker_unavailable_for_kill", error=str(exc))

    logger.info("force_remove_completed", containers_removed=removed)
    return removed

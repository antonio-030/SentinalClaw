"""
Infrastruktur-Prüfungen für SentinelClaw.

Zentrale Funktionen um die Verfügbarkeit von Docker, Sandbox
und anderen Abhängigkeiten zu prüfen. Werden vor Scan-Start
und in Health-Checks verwendet.
"""

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Container-Name für die Scan-Sandbox
SANDBOX_CONTAINER_NAME = "sentinelclaw-sandbox"


async def check_docker_ready() -> tuple[bool, str]:
    """Prüft ob Docker-Daemon erreichbar ist."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        client.ping()
        return True, "Docker erreichbar"
    except Exception as error:
        return False, f"Docker nicht erreichbar: {error}"


async def check_sandbox_running() -> tuple[bool, str]:
    """Prüft ob der Sandbox-Container läuft."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        container = client.containers.get(SANDBOX_CONTAINER_NAME)
        if container.status == "running":
            return True, "Sandbox läuft"
        return False, (
            f"Sandbox-Container Status: {container.status}. "
            "Starte mit: docker compose up -d sandbox"
        )
    except Exception:
        return False, (
            "Sandbox-Container nicht gefunden. "
            "Erstelle mit: docker compose up -d sandbox"
        )

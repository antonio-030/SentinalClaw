"""
Netzwerk-Kill für SentinelClaw (Kill-Pfad 3).

Blockiert allen ausgehenden Traffic der Sandbox über Docker-Netzwerk-Disconnect
und iptables DROP-Regeln auf das Scan-Subnet. Alle Funktionen fangen Fehler ab
und crashen niemals — der Kill-Pfad muss immer durchlaufen.
"""

import asyncio
import subprocess

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Docker-Netzwerke die beim Kill getrennt werden müssen
_SCAN_NETWORKS = ["sentinel-scanning", "sentinel-internal"]

# Container-Name (muss mit docker-compose übereinstimmen)
_SANDBOX_CONTAINER = "sentinelclaw-sandbox"


async def block_scanning_network() -> bool:
    """Blockiert das Scan-Netzwerk vollständig.

    Schritt 1: Docker-Netzwerk-Disconnect für alle Scan-Netzwerke.
    Schritt 2: iptables DROP-Regel auf das Scan-Subnet als zusätzliche Absicherung.

    Gibt True zurück wenn mindestens ein Disconnect erfolgreich war.
    """
    loop = asyncio.get_event_loop()
    success = await loop.run_in_executor(None, _disconnect_all_networks)

    # iptables als zusätzliche Absicherung (benötigt root-Rechte)
    iptables_ok = await loop.run_in_executor(None, _apply_iptables_drop)
    if iptables_ok:
        logger.info("iptables_drop_applied")

    return success


def _disconnect_all_networks() -> bool:
    """Trennt den Sandbox-Container von allen Scan-Netzwerken (synchron)."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        container = client.containers.get(_SANDBOX_CONTAINER)
        disconnected = 0

        for net_name in _SCAN_NETWORKS:
            try:
                network = client.networks.get(net_name)
                network.disconnect(container, force=True)
                disconnected += 1
                logger.info("network_killed", network=net_name)
            except Exception as exc:
                logger.debug("network_kill_skip", network=net_name, error=str(exc))

        return disconnected > 0
    except Exception as exc:
        logger.warning("network_kill_failed", error=str(exc))
        return False


def _apply_iptables_drop() -> bool:
    """Setzt iptables DROP-Regel für das Scan-Subnet (benötigt root)."""
    try:
        # Docker-Bridge-Subnet für sentinel-scanning ermitteln und blockieren
        result = subprocess.run(
            ["iptables", "-I", "FORWARD", "-o", "br-sentinel-scanning",
             "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("iptables_not_available", error=str(exc))
        return False


async def verify_network_blocked() -> bool:
    """Prüft ob der Sandbox-Container kein Netzwerk mehr hat.

    Gibt True zurück wenn der Container keine Netzwerke hat oder nicht existiert.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_no_networks)


def _check_no_networks() -> bool:
    """Prüft synchron ob der Container netzwerklos ist."""
    try:
        import docker as docker_lib
        client = docker_lib.from_env()
        container = client.containers.get(_SANDBOX_CONTAINER)
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        connected = [n for n in networks if n != "none"]
        if connected:
            logger.warning("container_still_connected", networks=connected)
            return False
        return True
    except Exception:
        # Container existiert nicht — Netzwerk ist damit blockiert
        return True


async def get_network_status() -> dict:
    """Gibt den Netzwerkstatus aller relevanten Docker-Netzwerke zurück."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _collect_network_status)


def _collect_network_status() -> dict:
    """Sammelt Netzwerk-Informationen synchron."""
    status: dict = {"networks": {}, "container_connected": False}
    try:
        import docker as docker_lib
        client = docker_lib.from_env()

        for net_name in _SCAN_NETWORKS:
            try:
                network = client.networks.get(net_name)
                containers = list(network.attrs.get("Containers", {}).keys())
                status["networks"][net_name] = {
                    "exists": True,
                    "connected_containers": len(containers),
                }
            except Exception:
                status["networks"][net_name] = {"exists": False, "connected_containers": 0}

        # Prüfe ob der Sandbox-Container verbunden ist
        try:
            container = client.containers.get(_SANDBOX_CONTAINER)
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            status["container_connected"] = any(
                n in networks for n in _SCAN_NETWORKS
            )
        except Exception:
            status["container_connected"] = False

    except Exception as exc:
        logger.debug("network_status_error", error=str(exc))
        status["error"] = str(exc)

    return status

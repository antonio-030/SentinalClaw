"""Startup-Aufgaben für den SentinelClaw API-Server.

Enthält alle Initialisierungslogik die beim Serverstart
im Lifespan-Context ausgeführt wird.
"""

from datetime import UTC, datetime

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


async def run_startup_tasks(db: DatabaseManager, settings: object) -> None:
    """Führt alle Startup-Aufgaben nach DB-Init und Migrationen aus."""
    from src.shared.auth import (
        ensure_default_admin,
        validate_jwt_secret_for_production,
    )
    from src.shared.token_blacklist import token_blacklist

    await ensure_default_admin(db)
    validate_jwt_secret_for_production(settings.debug)

    # Token-Blacklist aus DB laden (für serverseitiges Logout über Neustarts)
    await token_blacklist.load_from_db(db)
    await token_blacklist.cleanup_expired(db)

    # Auto-Backup beim Start
    await _run_auto_backup(db)

    # DSGVO: Aufbewahrungsfristen durchsetzen
    from src.shared.retention_service import run_retention_cleanup
    await run_retention_cleanup(db)

    # Hängende Scans aufräumen
    await cleanup_stuck_scans(db)

    # Kill-Switch zurücksetzen falls noch aktiv
    _reset_kill_switch_if_active()

    # Seed-Daten in die DB schreiben
    await _seed_data(db)

    # Produktions-Anforderungen prüfen
    if not settings.debug:
        enforce_production_requirements(settings)

    # Sandbox und NemoClaw prüfen
    await ensure_sandbox_running()
    check_nemoclaw_on_startup()

    # Agent-Konfiguration in Sandbox synchronisieren
    await sync_sandbox_config_on_startup()


async def _run_auto_backup(db: DatabaseManager) -> None:
    """Erstellt Auto-Backup und räumt alte Backups auf."""
    try:
        from src.shared.backup_service import cleanup_old_backups, create_backup
        await create_backup(db)
        cleanup_old_backups(max_age_days=30)
    except Exception as backup_err:
        logger.warning("Auto-Backup fehlgeschlagen", error=str(backup_err))


def _reset_kill_switch_if_active() -> None:
    """Setzt Kill-Switch zurück falls er vom letzten Lauf noch aktiv ist."""
    from src.shared.kill_switch import KillSwitch
    if KillSwitch().is_active():
        KillSwitch().reset()
        logger.info("Kill-Switch zurückgesetzt (war aktiv vom letzten Lauf)")


async def _seed_data(db: DatabaseManager) -> None:
    """Schreibt Standard-Einstellungen und Builtin-Profile in die DB."""
    from src.shared.profile_repository import seed_builtin_profiles
    from src.shared.settings_repository import seed_defaults
    from src.shared.settings_service import init_settings_service

    await seed_defaults(db)
    await seed_builtin_profiles(db)
    init_settings_service(db)


def check_nemoclaw_on_startup() -> None:
    """Prüft NemoClaw-Verfügbarkeit beim Server-Start.

    Loggt eine Warnung wenn NemoClaw nicht erreichbar ist.
    Blockiert den Start NICHT — Graceful Degradation greift zur Laufzeit.
    """
    try:
        from src.agents.nemoclaw_runtime import NemoClawRuntime
        status = NemoClawRuntime.check_availability()
        if status.get("available", False):
            logger.info(
                "NemoClaw verfügbar",
                details=status.get("details", {}),
            )
        else:
            logger.warning(
                "NemoClaw beim Start NICHT verfügbar — "
                "Fallback-Provider wird bei Bedarf genutzt",
                reason=status.get("reason", "unbekannt"),
                details=status.get("details", {}),
            )
    except Exception as error:
        logger.warning(
            "NemoClaw Startup-Check fehlgeschlagen",
            error=str(error),
        )


async def ensure_sandbox_running() -> None:
    """Startet den Sandbox-Container falls er gestoppt ist.

    Nach einem Neustart wird kurz gewartet damit der Container
    SSH-Verbindungen annehmen kann, bevor der Config-Sync läuft.
    """
    try:
        import asyncio

        import docker as docker_lib
        client = docker_lib.from_env()
        try:
            container = client.containers.get("sentinelclaw-sandbox")
            if container.status != "running":
                container.start()
                logger.info("Sandbox-Container automatisch gestartet")
                # Warten bis Container bereit ist für SSH
                await asyncio.sleep(3)
            else:
                logger.info("Sandbox-Container laeuft bereits")
        except docker_lib.errors.NotFound:
            logger.warning("Sandbox-Container nicht gefunden")
    except Exception as e:
        logger.debug("Sandbox-Auto-Start fehlgeschlagen", error=str(e))


async def sync_sandbox_config_on_startup() -> None:
    """Synchronisiert AGENT.md in die Sandbox beim Server-Start.

    Stellt sicher dass die Agent-Konfiguration nach jedem
    Neustart (Server oder Sandbox-Container) aktuell ist.
    """
    try:
        from src.api.whitelist_routes import _sync_sandbox_agent_config
        await _sync_sandbox_agent_config()
        logger.info("Sandbox Agent-Konfiguration synchronisiert (Startup)")
    except Exception as error:
        logger.warning(
            "Sandbox-Sync beim Start fehlgeschlagen — "
            "wird beim nächsten Whitelist-Update nachgeholt",
            error=str(error),
        )


def enforce_production_requirements(settings: object) -> None:
    """Prüft Produktionsanforderungen beim Start."""
    from src.shared.auth import _DEFAULT_DEV_SECRET, SECRET_KEY

    errors: list[str] = []
    if SECRET_KEY == _DEFAULT_DEV_SECRET:
        errors.append(
            "SENTINEL_JWT_SECRET nicht gesetzt (Dev-Default ist unsicher)"
        )
    if not settings.db_path.parent.exists():
        errors.append(
            f"DB-Verzeichnis existiert nicht: {settings.db_path.parent}"
        )
    if errors:
        for err in errors:
            logger.error("Produktions-Anforderung nicht erfüllt", detail=err)
        raise RuntimeError(
            f"Server kann nicht im Produktionsmodus starten. "
            f"{len(errors)} Anforderung(en) nicht erfüllt."
        )
    logger.info("Alle Produktions-Anforderungen erfüllt")


async def cleanup_stuck_scans(db: DatabaseManager) -> int:
    """Markiert Scans die >10min 'running' sind als 'failed'."""
    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus

    repo = ScanJobRepository(db)
    running = await repo.list_by_status(ScanStatus.RUNNING)
    cleaned = 0

    for scan in running:
        if scan.started_at:
            elapsed = (datetime.now(UTC) - scan.started_at).total_seconds()
            if elapsed > 600:  # 10 Minuten
                await repo.update_status(scan.id, ScanStatus.FAILED)
                logger.warning(
                    "Hängenden Scan aufgeräumt",
                    scan_id=str(scan.id),
                    target=scan.target,
                    elapsed_s=int(elapsed),
                )
                cleaned += 1

    if cleaned:
        logger.info(f"{cleaned} hängende Scans aufgeräumt")
    return cleaned

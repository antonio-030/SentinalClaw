"""
Watchdog-Service fuer SentinelClaw.

Unabhaengiger Ueberwachungsprozess der bei Anomalien automatisch den
Kill-Switch ausloest. Prueft alle 10 Sekunden: Scan-Timeouts, Sandbox-
Gesundheit, App-Health-Checks, Kill-Vervollstaendigung.
Siehe docs/KILL_SWITCH.md Abschnitt 7.
"""

import asyncio
import subprocess
from datetime import UTC, datetime

from docker.errors import DockerException, NotFound
from docker.models.containers import Container

import docker
from src.shared.config import Settings, get_settings
from src.shared.database import DatabaseManager
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.repositories import ScanJobRepository
from src.shared.types.models import ScanJob, ScanStatus

# Modulweiter Logger
logger = get_logger(__name__)

# Container-Name — muss mit docker-compose.yml uebereinstimmen
_SANDBOX_CONTAINER_NAME = "sentinelclaw-sandbox"

# Health-Check-Endpunkt des MCP-Servers
_HEALTH_URL = "http://localhost:8080/health"


class Watchdog:
    """Ueberwacht SentinelClaw und loest bei Anomalien Kill-Pfad 2 aus."""

    CHECK_INTERVAL: int = 10          # Pruefintervall in Sekunden
    MAX_HEALTH_FAILURES: int = 3      # Aufeinanderfolgende Fehler bis Kill
    DEFAULT_MAX_SCAN_DURATION: int = 600  # Max. Scan-Dauer (Sekunden)

    def __init__(self) -> None:
        self._health_failures: int = 0
        self._running: bool = True
        self._settings: Settings = get_settings()
        self._db: DatabaseManager | None = None
        self._scan_repo: ScanJobRepository | None = None
        self._docker_client: docker.DockerClient | None = None

    async def _initialize(self) -> None:
        """Erstellt DB-Verbindung und Docker-Client beim Start."""
        self._db = DatabaseManager(self._settings.db_path)
        await self._db.initialize()
        self._scan_repo = ScanJobRepository(self._db)

        try:
            self._docker_client = docker.from_env()
            logger.info("watchdog_docker_connected")
        except DockerException as exc:
            logger.error("watchdog_docker_unavailable", error=str(exc))
            self._docker_client = None

    async def run(self) -> None:
        """Hauptschleife — laeuft bis stop() aufgerufen wird."""
        await self._initialize()
        logger.info(
            "watchdog_started",
            check_interval=self.CHECK_INTERVAL,
            max_scan_duration=self.DEFAULT_MAX_SCAN_DURATION,
        )
        while self._running:
            try:
                await self._check_all()
            except Exception as exc:
                # Watchdog darf nie abstuerzen — Fehler loggen, weitermachen
                logger.error("watchdog_check_error", error=str(exc))
            await asyncio.sleep(self.CHECK_INTERVAL)
        await self._shutdown()

    async def _shutdown(self) -> None:
        """Schliesst DB-Verbindung beim Beenden."""
        if self._db is not None:
            await self._db.close()
        logger.info("watchdog_stopped")

    def stop(self) -> None:
        """Signalisiert der Hauptschleife, sich zu beenden."""
        self._running = False

    async def _check_all(self) -> None:
        """Führt alle Prüfungen in einem Durchlauf aus."""
        await self._check_scan_timeouts()
        await self._check_sandbox_health()
        self._check_app_health()
        await self._check_scope_violations()
        await self._check_kill_completion()

    # -- Pruefung 1: Scan-Timeouts ------------------------------------------

    async def _check_scan_timeouts(self) -> None:
        """Killt Scans die laenger als max_duration laufen."""
        if self._scan_repo is None:
            return

        running_scans: list[ScanJob] = await self._scan_repo.list_by_status(
            ScanStatus.RUNNING
        )
        now = datetime.now(UTC)

        for scan in running_scans:
            if scan.started_at is None:
                continue
            # Maximale Dauer: Scan-Config oder Klassen-Default
            max_duration: int = scan.config.get(
                "max_duration", self.DEFAULT_MAX_SCAN_DURATION
            )
            elapsed = (now - scan.started_at).total_seconds()

            if elapsed > max_duration:
                logger.warning(
                    "watchdog_scan_timeout",
                    scan_id=str(scan.id),
                    elapsed_seconds=elapsed,
                    max_duration=max_duration,
                )
                self._execute_kill(
                    f"Scan {scan.id} ueberschreitet maximale Dauer: "
                    f"{elapsed:.0f}s > {max_duration}s"
                )
                await self._scan_repo.update_status(
                    scan.id, ScanStatus.EMERGENCY_KILLED
                )

    # -- Pruefung 2: Sandbox-Gesundheit --------------------------------------

    async def _check_sandbox_health(self) -> None:
        """Markiert Scans als FAILED wenn Sandbox-Container fehlt."""
        if self._scan_repo is None or self._docker_client is None:
            return

        running_scans = await self._scan_repo.list_by_status(ScanStatus.RUNNING)
        if not running_scans:
            return

        try:
            container: Container = self._docker_client.containers.get(
                _SANDBOX_CONTAINER_NAME
            )
            if container.status != "running":
                logger.warning(
                    "watchdog_sandbox_not_running",
                    container_status=container.status,
                    active_scans=len(running_scans),
                )
                for scan in running_scans:
                    await self._scan_repo.update_status(scan.id, ScanStatus.FAILED)
        except NotFound:
            # Container existiert nicht, aber Scans sind aktiv
            logger.warning(
                "watchdog_sandbox_missing", active_scans=len(running_scans)
            )
            for scan in running_scans:
                await self._scan_repo.update_status(scan.id, ScanStatus.FAILED)
        except DockerException as exc:
            logger.error("watchdog_docker_error", error=str(exc))

    # -- Pruefung 3: App-Health-Check ----------------------------------------

    def _check_app_health(self) -> None:
        """Killt nach MAX_HEALTH_FAILURES aufeinanderfolgenden Fehlern."""
        try:
            result = subprocess.run(
                ["curl", "-sf", "--max-time", "5", _HEALTH_URL],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                if self._health_failures > 0:
                    logger.info(
                        "watchdog_health_recovered",
                        previous_failures=self._health_failures,
                    )
                self._health_failures = 0
                return
            self._health_failures += 1
            logger.warning(
                "watchdog_health_failed",
                consecutive_failures=self._health_failures,
                max_allowed=self.MAX_HEALTH_FAILURES,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self._health_failures += 1
            logger.warning(
                "watchdog_health_error",
                error=str(exc),
                consecutive_failures=self._health_failures,
            )

        # Schwelle ueberschritten — Kill ausloesen
        if self._health_failures >= self.MAX_HEALTH_FAILURES:
            self._execute_kill(
                f"MCP-Server antwortet nicht "
                f"({self._health_failures} aufeinanderfolgende Fehler)"
            )

    # -- Prüfung 4: Scope-Verletzungen ----------------------------------------

    async def _check_scope_violations(self) -> None:
        """Prüft ob laufende Scans noch im Scope sind (delegiert an scope_checks)."""
        if self._scan_repo is None:
            return
        from src.watchdog.scope_checks import check_scope_violations
        await check_scope_violations(self._scan_repo, self._settings)

    # -- Prüfung 5: Kill-Vervollständigung ----------------------------------

    async def _check_kill_completion(self) -> None:
        """Eskaliert wenn Container oder Netzwerk nach Kill-Aktivierung noch aktiv sind."""
        kill_switch = KillSwitch()
        if not kill_switch.is_active():
            return

        # Netzwerk-Verifikation: Prüfe ob Scan-Netzwerke getrennt sind
        try:
            from src.shared.network_kill import verify_network_blocked
            network_blocked = await verify_network_blocked()
            if not network_blocked:
                logger.critical(
                    "watchdog_network_still_connected",
                    reason="Netzwerk nach Kill-Aktivierung noch verbunden",
                )
                # Netzwerk erneut blockieren
                from src.shared.network_kill import block_scanning_network
                await block_scanning_network()
        except Exception as exc:
            logger.error("watchdog_network_check_failed", error=str(exc))

        if self._docker_client is None:
            return

        try:
            container: Container = self._docker_client.containers.get(
                _SANDBOX_CONTAINER_NAME
            )
            if container.status in ("running", "restarting"):
                logger.critical(
                    "watchdog_kill_escalation",
                    container_status=container.status,
                    reason="Container läuft noch nach Kill-Aktivierung",
                )
                # Direkter Container-Kill als Eskalation (Kill-Pfad 2)
                container.kill()
                container.remove(force=True)
                logger.info("watchdog_container_force_removed")
        except NotFound:
            # Container existiert nicht — gewünschter Zustand nach Kill
            pass
        except DockerException as exc:
            logger.error("watchdog_kill_escalation_failed", error=str(exc))

    # -- Kill-Ausfuehrung ---------------------------------------------------

    def _execute_kill(self, reason: str) -> None:
        """Aktiviert den zentralen KillSwitch (Singleton)."""
        logger.critical("watchdog_executing_kill", reason=reason)
        KillSwitch().activate("watchdog", reason)

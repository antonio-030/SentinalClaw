"""
Kill-Switch für SentinelClaw.

Sofortiges Abschalten aller aktiven Operationen bei Sicherheitsverstößen
oder unerwarteten Zuständen. Singleton-Pattern mit Thread-sicherem
Event-Flag — einmal aktiviert, ist der Kill-Switch für die gesamte
Sitzung irreversibel (außer im Test-Modus).
"""

import threading
from datetime import UTC, datetime
from typing import Optional

from docker.errors import DockerException, NotFound

import docker
from src.shared.logging_setup import get_logger

# Modulweiter Logger
logger = get_logger(__name__)

# Name des Sandbox-Containers (muss mit docker-compose übereinstimmen)
_SANDBOX_CONTAINER_NAME = "sentinelclaw-sandbox"


class KillSwitch:
    """Zentraler Notaus-Schalter für SentinelClaw.

    Nutzt threading.Event als atomares, thread-sicheres Kill-Flag.
    Sobald aktiviert, kann der Zustand nicht mehr zurückgesetzt werden
    (außer explizit über reset() im Test-Kontext).
    """

    _instance: Optional["KillSwitch"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "KillSwitch":
        """Singleton — es gibt nur einen Kill-Switch pro Prozess."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        """Initialisiert den Kill-Switch (nur beim ersten Mal)."""
        if self._initialized:
            return
        self._kill_flag: threading.Event = threading.Event()
        self._triggered_by: str = ""
        self._reason: str = ""
        self._activated_at: datetime | None = None
        self._initialized: bool = True

    def activate(self, triggered_by: str, reason: str) -> None:
        """Aktiviert den Kill-Switch und stoppt alle Sandbox-Container.

        Setzt das Kill-Flag atomar, stoppt Docker-Container und
        loggt den Vorgang für die Audit-Nachverfolgung.
        """
        # Bereits aktiv — kein doppeltes Auslösen
        if self._kill_flag.is_set():
            logger.warning(
                "kill_switch_already_active",
                triggered_by=triggered_by,
                reason=reason,
                original_trigger=self._triggered_by,
            )
            return

        # Kill-Flag setzen (atomar, irreversibel für diese Sitzung)
        self._kill_flag.set()
        self._triggered_by = triggered_by
        self._reason = reason
        self._activated_at = datetime.now(UTC)

        # Audit-Log: Kill-Switch wurde aktiviert
        logger.critical(
            "kill_switch_activated",
            triggered_by=triggered_by,
            reason=reason,
            activated_at=self._activated_at.isoformat(),
        )

        # Sandbox-Container sofort stoppen
        self._stop_sandbox_container()

    def _stop_sandbox_container(self) -> None:
        """Stoppt den Sandbox-Container — fängt alle Fehler ab."""
        try:
            client = docker.from_env()
            container = client.containers.get(_SANDBOX_CONTAINER_NAME)
            container.kill()
            logger.info(
                "sandbox_container_killed",
                container_name=_SANDBOX_CONTAINER_NAME,
            )
        except NotFound:
            # Container existiert nicht — kein Fehler
            logger.info(
                "sandbox_container_not_found",
                container_name=_SANDBOX_CONTAINER_NAME,
            )
        except DockerException as exc:
            # Docker-Daemon nicht erreichbar oder anderer Fehler
            logger.error(
                "sandbox_container_kill_failed",
                container_name=_SANDBOX_CONTAINER_NAME,
                error=str(exc),
            )

    def is_active(self) -> bool:
        """Prüft ob der Kill-Switch aktiviert wurde."""
        return self._kill_flag.is_set()

    @property
    def triggered_by(self) -> str:
        """Gibt zurück, wer den Kill-Switch ausgelöst hat."""
        return self._triggered_by

    @property
    def reason(self) -> str:
        """Gibt die Begründung für die Aktivierung zurück."""
        return self._reason

    @property
    def activated_at(self) -> datetime | None:
        """Gibt den Zeitpunkt der Aktivierung zurück."""
        return self._activated_at

    # ⚠️ WARNUNG: Nur für Tests verwenden! Im Produktivbetrieb darf der
    # Kill-Switch NIEMALS zurückgesetzt werden. Ein Reset im laufenden
    # Betrieb wäre ein schwerer Sicherheitsverstoß.
    def reset(self) -> None:
        """Setzt den Kill-Switch zurück (NUR FÜR TESTS).

        ⚠️ WARNUNG: Diese Methode existiert ausschließlich für
        Unit-Tests. Im Produktivbetrieb niemals aufrufen!
        """
        logger.warning("kill_switch_reset_called")
        self._kill_flag.clear()
        self._triggered_by = ""
        self._reason = ""
        self._activated_at = None

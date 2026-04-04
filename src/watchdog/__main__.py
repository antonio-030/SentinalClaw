"""
Einstiegspunkt fuer den Watchdog-Service.

Starten mit: python -m src.watchdog
"""

import asyncio
import signal

from src.shared.config import get_settings
from src.shared.logging_setup import setup_logging
from src.watchdog.service import Watchdog


def main() -> None:
    """Initialisiert Logging und startet den Watchdog."""
    settings = get_settings()
    setup_logging(settings.log_level)

    watchdog = Watchdog()

    # Graceful Shutdown bei SIGTERM/SIGINT
    def _handle_signal(sig: int, frame: object) -> None:
        watchdog.stop()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    asyncio.run(watchdog.run())


if __name__ == "__main__":
    main()

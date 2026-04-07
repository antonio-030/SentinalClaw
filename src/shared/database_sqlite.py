"""
SQLite-Backend für SentinelClaw.

Verwendet aiosqlite für asynchronen Zugriff. WAL-Modus erlaubt
gleichzeitige Lese- und Schreibzugriffe. Dieses Backend ist der
Standard für lokale Entwicklung und den PoC.
"""

from pathlib import Path

import aiosqlite

from src.shared.database_schema import SCHEMA_SQL
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


class SQLiteBackend:
    """SQLite-Datenbank-Backend mit aiosqlite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._connection: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Erstellt Verzeichnis, Verbindung und Schema."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(
            str(self._db_path),
            timeout=30.0,
        )

        # WAL-Modus: Gleichzeitige Lese- und Schreibzugriffe
        await self._connection.execute("PRAGMA journal_mode=WAL")
        # Busy-Timeout: Wartet bis zu 30s wenn DB gesperrt
        await self._connection.execute("PRAGMA busy_timeout=30000")
        # Foreign Keys aktivieren (bei SQLite standardmäßig aus)
        await self._connection.execute("PRAGMA foreign_keys=ON")

        await self._connection.executescript(SCHEMA_SQL)
        await self._connection.commit()

        logger.info("SQLite-Datenbank initialisiert", path=str(self._db_path))

    async def get_connection(self) -> aiosqlite.Connection:
        """Gibt die aktive SQLite-Verbindung zurück."""
        if self._connection is None:
            await self.initialize()
        assert self._connection is not None, "SQLite-Verbindung konnte nicht hergestellt werden"
        return self._connection

    async def close(self) -> None:
        """Schließt die SQLite-Verbindung."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            logger.info("SQLite-Verbindung geschlossen")

    @property
    def db_path(self) -> Path:
        """Pfad zur SQLite-Datenbankdatei (für Backup-Service)."""
        return self._db_path

    @property
    def db_type(self) -> str:
        return "sqlite"

"""
Datenbank-Manager für SentinelClaw.

Abstraktionsschicht die sowohl SQLite (PoC/Entwicklung) als auch
PostgreSQL (Produktion) unterstützt. Das Backend wird über die
Umgebungsvariable SENTINEL_DB_TYPE gesteuert.

Repositories greifen ausschließlich über DatabaseManager.get_connection()
auf die Datenbank zu — das konkrete Backend ist transparent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from src.shared.logging_setup import get_logger

if TYPE_CHECKING:
    from src.shared.database_postgres import PostgreSQLBackend
    from src.shared.database_sqlite import SQLiteBackend

logger = get_logger(__name__)


class DatabaseManager:
    """Verwaltet die Datenbankverbindung — unabhängig vom Backend.

    Erstellt beim Initialisieren das richtige Backend (SQLite oder
    PostgreSQL) und delegiert alle Operationen dorthin.
    """

    def __init__(
        self,
        db_path: Path | None = None,
        db_type: str = "sqlite",
        db_dsn: str = "",
    ) -> None:
        self._db_type = db_type
        self._db_path = db_path or Path("data/sentinelclaw.db")
        self._db_dsn = db_dsn
        self._backend: SQLiteBackend | PostgreSQLBackend | None = None

    async def initialize(self) -> None:
        """Erstellt das Backend und initialisiert Schema + Verbindung."""
        if self._db_type == "postgresql":
            from src.shared.database_postgres import PostgreSQLBackend
            self._backend = PostgreSQLBackend(self._db_dsn)
        else:
            from src.shared.database_sqlite import SQLiteBackend
            self._backend = SQLiteBackend(self._db_path)

        await self._backend.initialize()
        logger.info("Datenbank initialisiert", backend=self._db_type)

    async def get_connection(self):
        """Gibt die aktive Datenbankverbindung zurück.

        Für SQLite: aiosqlite.Connection
        Für PostgreSQL: PostgreSQLConnection (Kompatibilitäts-Wrapper)

        Beide unterstützen: execute(), commit(), fetchone(), fetchall(),
        row["column"]-Zugriff und row_factory-Attribut.
        """
        if self._backend is None:
            await self.initialize()
        assert self._backend is not None
        return await self._backend.get_connection()

    async def close(self) -> None:
        """Schließt die Datenbankverbindung bzw. den Pool."""
        if self._backend is not None:
            await self._backend.close()
            self._backend = None
            logger.info("Datenbankverbindung geschlossen")

    @property
    def db_type(self) -> str:
        """Gibt den aktiven Backend-Typ zurück ('sqlite' oder 'postgresql')."""
        return self._db_type

def serialize_json(data: dict | list) -> str:
    """Serialisiert Python-Dicts/Listen als JSON-String für die Datenbank."""
    return json.dumps(data, default=str, ensure_ascii=False)


def deserialize_json(raw: str | None) -> dict | list:
    """Deserialisiert einen JSON-String aus der Datenbank."""
    if raw is None or raw == "":
        return {}
    return json.loads(raw)


def _uuid_to_str(value: UUID | str) -> str:
    """Konvertiert UUID zu String für Datenbank-Speicherung."""
    return str(value) if isinstance(value, UUID) else value

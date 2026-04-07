"""
PostgreSQL-Backend für SentinelClaw.

Verwendet asyncpg für asynchronen Zugriff mit Connection-Pooling.
Stellt eine Kompatibilitätsschicht bereit die die gleiche API
wie das SQLite-Backend bietet (row["column"], fetchone, fetchall).
"""

from __future__ import annotations

from typing import Any

import asyncpg

from src.shared.database_schema import SCHEMA_SQL, convert_schema_for_postgresql
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


def _convert_placeholders(sql: str) -> str:
    """Konvertiert SQLite-Platzhalter (?) zu PostgreSQL ($1, $2, ...).

    Berücksichtigt String-Literale um Fragezeichen in Strings
    nicht fälschlicherweise zu ersetzen.
    """
    result: list[str] = []
    counter = 0
    in_string = False

    for char in sql:
        if char == "'" and not in_string:
            in_string = True
        elif char == "'" and in_string:
            in_string = False
        elif char == "?" and not in_string:
            counter += 1
            result.append(f"${counter}")
            continue
        result.append(char)

    return "".join(result)


class PostgreSQLCursor:
    """Kompatibilitäts-Cursor der die aiosqlite-API nachbildet."""

    def __init__(
        self,
        rows: list[asyncpg.Record] | None = None,
        status: str = "",
    ) -> None:
        self._rows = rows or []
        self._status = status
        self._index = 0

    async def fetchone(self) -> asyncpg.Record | None:
        """Gibt die nächste Zeile zurück oder None."""
        if self._index < len(self._rows):
            row = self._rows[self._index]
            self._index += 1
            return row
        return None

    async def fetchall(self) -> list[asyncpg.Record]:
        """Gibt alle verbleibenden Zeilen zurück."""
        remaining = self._rows[self._index:]
        self._index = len(self._rows)
        return remaining

    @property
    def rowcount(self) -> int:
        """Anzahl betroffener Zeilen (aus Status-String wie 'DELETE 5')."""
        if self._status:
            parts = self._status.split()
            if len(parts) >= 2:
                try:
                    return int(parts[-1])
                except ValueError:
                    return 0
        return len(self._rows)


class PostgreSQLConnection:
    """Wraps asyncpg.Connection um die aiosqlite-API nachzubilden.

    Repositories können diese Klasse transparent nutzen ohne zu
    wissen ob SQLite oder PostgreSQL dahinter liegt.
    """

    def __init__(self, connection: asyncpg.Connection) -> None:
        self._conn = connection
        self._transaction: asyncpg.connection.Transaction | None = None

    @property
    def row_factory(self) -> Any:
        """Kompatibilität: asyncpg.Record unterstützt row["col"] nativ."""
        return None

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        """No-op — asyncpg.Record hat bereits dict-artigen Zugriff."""

    async def execute(
        self, sql: str, params: tuple | list | None = None,
    ) -> PostgreSQLCursor:
        """Führt SQL aus und gibt einen Kompatibilitäts-Cursor zurück."""
        pg_sql = _convert_placeholders(sql)
        sql_upper = pg_sql.strip().upper()
        is_query = sql_upper.startswith(("SELECT", "WITH"))
        is_dml = sql_upper.startswith(("INSERT", "UPDATE", "DELETE"))
        args = tuple(params) if params else ()

        # DML-Befehle in Transaktion wrappen (wie SQLite mit explizitem commit)
        if is_dml and self._transaction is None:
            self._transaction = self._conn.transaction()
            await self._transaction.start()

        if is_query:
            rows = await self._conn.fetch(pg_sql, *args)
            return PostgreSQLCursor(rows=rows)

        status = await self._conn.execute(pg_sql, *args)
        return PostgreSQLCursor(status=status)

    async def executescript(self, sql: str) -> None:
        """Führt mehrere SQL-Statements nacheinander aus."""
        for statement in sql.split(";"):
            stripped = statement.strip()
            if stripped:
                await self._conn.execute(stripped)

    async def commit(self) -> None:
        """Bestätigt die aktuelle Transaktion."""
        if self._transaction is not None:
            await self._transaction.commit()
            self._transaction = None


class PostgreSQLBackend:
    """PostgreSQL-Datenbank-Backend mit asyncpg und Connection-Pooling."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._connection: asyncpg.Connection | None = None
        self._wrapper: PostgreSQLConnection | None = None

    async def initialize(self) -> None:
        """Erstellt Connection-Pool und Schema."""
        self._pool = await asyncpg.create_pool(
            self._dsn,
            min_size=2,
            max_size=10,
            command_timeout=60,
        )

        # Schema erstellen über eine dedizierte Verbindung
        async with self._pool.acquire() as conn:
            pg_schema = convert_schema_for_postgresql(SCHEMA_SQL)
            for statement in pg_schema.split(";"):
                stripped = statement.strip()
                if stripped:
                    try:
                        await conn.execute(stripped)
                    except asyncpg.DuplicateTableError:
                        pass
                    except asyncpg.DuplicateObjectError:
                        pass

        # Persistente Verbindung für Repository-Kompatibilität
        self._connection = await self._pool.acquire()
        self._wrapper = PostgreSQLConnection(self._connection)

        logger.info("PostgreSQL-Datenbank initialisiert", dsn=self._dsn.split("@")[-1])

    async def get_connection(self) -> PostgreSQLConnection:
        """Gibt die persistente PostgreSQL-Verbindung zurück."""
        if self._wrapper is None:
            await self.initialize()
        assert self._wrapper is not None, "PostgreSQL-Verbindung nicht verfügbar"
        return self._wrapper

    async def close(self) -> None:
        """Gibt Verbindung zurück und schließt den Pool."""
        if self._connection is not None and self._pool is not None:
            await self._pool.release(self._connection)
            self._connection = None
            self._wrapper = None
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL-Pool geschlossen")

    @property
    def db_type(self) -> str:
        return "postgresql"

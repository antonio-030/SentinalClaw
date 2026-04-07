"""
Repository für systemweite Einstellungen.

Speichert und lädt Konfigurationswerte aus der system_settings-Tabelle.
Idempotentes Seeding sorgt dafür, dass Defaults beim Start vorhanden sind.
"""

from datetime import UTC, datetime

import aiosqlite

from src.shared.constants.settings_seeds import SEED_DEFINITIONS, SettingDefinition
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Re-Export für externe Nutzer
__all__ = ["SettingsRepository", "SettingDefinition", "seed_defaults"]


class SettingsRepository:
    """CRUD für systemweite Einstellungen."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def get_all(self) -> list[dict]:
        """Lädt alle Einstellungen."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings ORDER BY category, key"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_by_category(self, category: str) -> list[dict]:
        """Lädt Einstellungen einer Kategorie."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings WHERE category = ? ORDER BY key",
            (category,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get(self, key: str) -> dict | None:
        """Lädt eine einzelne Einstellung."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT key, value, category, value_type, label, description, "
            "updated_by, updated_at FROM system_settings WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def update(self, key: str, value: str, updated_by: str) -> bool:
        """Aktualisiert eine Einstellung. Gibt False zurück wenn Key nicht existiert."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()
        result = await conn.execute(
            "UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? "
            "WHERE key = ?",
            (value, updated_by, now, key),
        )
        await conn.commit()
        return result.rowcount > 0

    async def batch_update(
        self, updates: dict[str, str], updated_by: str
    ) -> int:
        """Aktualisiert mehrere Einstellungen. Gibt Anzahl geänderter Werte zurück."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()
        changed = 0
        for key, value in updates.items():
            result = await conn.execute(
                "UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? "
                "WHERE key = ?",
                (value, updated_by, now, key),
            )
            changed += result.rowcount
        await conn.commit()
        return changed


async def seed_defaults(db: DatabaseManager) -> int:
    """Fügt Standard-Einstellungen ein, überspringt bereits vorhandene Keys."""
    conn = await db.get_connection()
    now = datetime.now(UTC).isoformat()
    inserted = 0

    for defn in SEED_DEFINITIONS:
        cursor = await conn.execute(
            "SELECT 1 FROM system_settings WHERE key = ?", (defn["key"],)
        )
        if await cursor.fetchone() is None:
            await conn.execute(
                "INSERT INTO system_settings (key, value, category, value_type, "
                "label, description, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    defn["key"], defn["value"], defn["category"], defn["value_type"],
                    defn["label"], defn["description"], "system", now,
                ),
            )
            inserted += 1

    await conn.commit()
    if inserted:
        logger.info("Standard-Einstellungen gesät", count=inserted)
    return inserted

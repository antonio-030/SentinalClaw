"""
Repository für Scan-Profile (builtin + benutzerdefiniert).

Die 7 vordefinierten Profile werden beim Start aus scan_profiles.py
in die Datenbank gesät. Benutzer können eigene Profile über die UI
erstellen, bearbeiten und löschen. Builtin-Profile sind geschützt.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import aiosqlite

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.scan_profiles import PROFILES

logger = get_logger(__name__)


class ProfileRepository:
    """CRUD für Scan-Profile in der Datenbank."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def list_all(self) -> list[dict]:
        """Lädt alle Profile (builtin + custom)."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT id, name, description, ports, max_escalation_level, "
            "skip_host_discovery, skip_vuln_scan, nmap_extra_flags, "
            "estimated_duration_minutes, is_builtin, created_by, updated_at "
            "FROM custom_scan_profiles ORDER BY is_builtin DESC, name"
        )
        rows = await cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    async def get(self, profile_id: str) -> dict | None:
        """Lädt ein Profil anhand der ID."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM custom_scan_profiles WHERE id = ?", (profile_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_dict(row) if row else None

    async def create(self, data: dict, created_by: str) -> dict:
        """Erstellt ein neues benutzerdefiniertes Profil."""
        profile_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        flags = json.dumps(data.get("nmap_extra_flags") or [])

        conn = await self._db.get_connection()
        await conn.execute(
            "INSERT INTO custom_scan_profiles "
            "(id, name, description, ports, max_escalation_level, "
            "skip_host_discovery, skip_vuln_scan, nmap_extra_flags, "
            "estimated_duration_minutes, is_builtin, created_by, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (
                profile_id, data["name"], data.get("description", ""),
                data["ports"], data.get("max_escalation_level", 2),
                int(data.get("skip_host_discovery", False)),
                int(data.get("skip_vuln_scan", False)),
                flags, data.get("estimated_duration_minutes", 5),
                created_by, now,
            ),
        )
        await conn.commit()
        logger.info("Profil erstellt", name=data["name"], id=profile_id)
        return await self.get(profile_id)  # type: ignore[return-value]

    async def update(self, profile_id: str, data: dict, updated_by: str) -> dict | None:
        """Aktualisiert ein Profil. Builtin-Profile können bearbeitet werden."""
        now = datetime.now(UTC).isoformat()
        flags = json.dumps(data.get("nmap_extra_flags") or [])

        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE custom_scan_profiles SET name = ?, description = ?, "
            "ports = ?, max_escalation_level = ?, skip_host_discovery = ?, "
            "skip_vuln_scan = ?, nmap_extra_flags = ?, "
            "estimated_duration_minutes = ?, updated_at = ? WHERE id = ?",
            (
                data["name"], data.get("description", ""),
                data["ports"], data.get("max_escalation_level", 2),
                int(data.get("skip_host_discovery", False)),
                int(data.get("skip_vuln_scan", False)),
                flags, data.get("estimated_duration_minutes", 5),
                now, profile_id,
            ),
        )
        await conn.commit()
        logger.info("Profil aktualisiert", id=profile_id)
        return await self.get(profile_id)

    async def delete(self, profile_id: str) -> bool:
        """Löscht ein Custom-Profil. Builtin-Profile sind geschützt."""
        conn = await self._db.get_connection()
        # Nur löschen wenn nicht builtin
        result = await conn.execute(
            "DELETE FROM custom_scan_profiles WHERE id = ? AND is_builtin = 0",
            (profile_id,),
        )
        await conn.commit()
        deleted = result.rowcount > 0
        if deleted:
            logger.info("Profil gelöscht", id=profile_id)
        return deleted

    @staticmethod
    def _row_to_dict(row: aiosqlite.Row) -> dict:
        """Konvertiert eine DB-Row in ein Dict mit korrekten Typen."""
        data = dict(row)
        # JSON-Felder deserialisieren
        raw_flags = data.get("nmap_extra_flags", "[]")
        data["nmap_extra_flags"] = json.loads(raw_flags) if raw_flags else []
        # Boolean-Felder korrigieren
        data["skip_host_discovery"] = bool(data.get("skip_host_discovery", 0))
        data["skip_vuln_scan"] = bool(data.get("skip_vuln_scan", 0))
        data["is_builtin"] = bool(data.get("is_builtin", 0))
        return data


async def seed_builtin_profiles(db: DatabaseManager) -> int:
    """Fügt die 7 Builtin-Profile ein, überspringt vorhandene."""
    conn = await db.get_connection()
    now = datetime.now(UTC).isoformat()
    inserted = 0

    for key, profile in PROFILES.items():
        cursor = await conn.execute(
            "SELECT 1 FROM custom_scan_profiles WHERE name = ? AND is_builtin = 1",
            (profile.name,),
        )
        if await cursor.fetchone() is None:
            flags = json.dumps(profile.nmap_extra_flags or [])
            await conn.execute(
                "INSERT INTO custom_scan_profiles "
                "(id, name, description, ports, max_escalation_level, "
                "skip_host_discovery, skip_vuln_scan, nmap_extra_flags, "
                "estimated_duration_minutes, is_builtin, created_by, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'system', ?)",
                (
                    f"builtin-{key}", profile.name, profile.description,
                    profile.ports, profile.max_escalation_level,
                    int(profile.skip_host_discovery), int(profile.skip_vuln_scan),
                    flags, profile.estimated_duration_minutes, now,
                ),
            )
            inserted += 1

    await conn.commit()
    if inserted:
        logger.info("Builtin-Profile gesät", count=inserted)
    return inserted

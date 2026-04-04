"""
Repositories für Scan-Phasen, Hosts und Ports.

Persistiert die Ergebnisse jeder einzelnen Scan-Phase
in der Datenbank. Ermöglicht Fortschritts-Tracking und
phasenübergreifende Datenübergabe.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import aiosqlite

from src.shared.database import DatabaseManager, deserialize_json, serialize_json
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


class ScanPhaseRepository:
    """CRUD für Scan-Phasen (Phase-Tracking)."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(
        self,
        scan_job_id: UUID,
        phase_number: int,
        name: str,
        description: str = "",
    ) -> UUID:
        """Erstellt eine neue Scan-Phase."""
        phase_id = uuid4()
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO scan_phases
               (id, scan_job_id, phase_number, name, description, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (str(phase_id), str(scan_job_id), phase_number, name, description,
             datetime.now(timezone.utc).isoformat()),
        )
        await conn.commit()
        logger.info("Phase erstellt", phase_id=str(phase_id), name=name, number=phase_number)
        return phase_id

    async def update_status(
        self,
        phase_id: UUID,
        status: str,
        tool_used: str | None = None,
        command_executed: str | None = None,
        raw_output: str | None = None,
        parsed_result: dict | None = None,
        hosts_found: int = 0,
        ports_found: int = 0,
        findings_found: int = 0,
        duration_seconds: float = 0.0,
        error_message: str | None = None,
    ) -> None:
        """Aktualisiert den Status einer Phase mit Ergebnissen."""
        conn = await self._db.get_connection()
        now = datetime.now(timezone.utc).isoformat()

        params: list = [status]
        sql_parts = ["status = ?"]

        if status == "running":
            sql_parts.append("started_at = ?")
            params.append(now)
        elif status in ("completed", "failed"):
            sql_parts.append("completed_at = ?")
            params.append(now)

        if tool_used is not None:
            sql_parts.append("tool_used = ?")
            params.append(tool_used)
        if command_executed is not None:
            sql_parts.append("command_executed = ?")
            params.append(command_executed)
        if raw_output is not None:
            # Rohdaten kürzen für DB (max 50KB)
            sql_parts.append("raw_output = ?")
            params.append(raw_output[:50_000])
        if parsed_result is not None:
            sql_parts.append("parsed_result = ?")
            params.append(serialize_json(parsed_result))

        sql_parts.append("hosts_found = ?")
        params.append(hosts_found)
        sql_parts.append("ports_found = ?")
        params.append(ports_found)
        sql_parts.append("findings_found = ?")
        params.append(findings_found)
        sql_parts.append("duration_seconds = ?")
        params.append(duration_seconds)

        if error_message is not None:
            sql_parts.append("error_message = ?")
            params.append(error_message[:1000])

        sql = f"UPDATE scan_phases SET {', '.join(sql_parts)} WHERE id = ?"
        params.append(str(phase_id))

        await conn.execute(sql, params)
        await conn.commit()

    async def list_by_scan(self, scan_job_id: UUID) -> list[dict]:
        """Listet alle Phasen eines Scans, sortiert nach Nummer."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM scan_phases WHERE scan_job_id = ? ORDER BY phase_number",
            (str(scan_job_id),),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


class DiscoveredHostRepository:
    """Persistiert entdeckte Hosts pro Scan."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(
        self,
        scan_job_id: UUID,
        phase_id: UUID,
        address: str,
        hostname: str = "",
        os_guess: str = "",
    ) -> UUID:
        """Speichert einen entdeckten Host."""
        host_id = uuid4()
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO discovered_hosts
               (id, scan_job_id, phase_id, address, hostname, os_guess, state, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'up', ?)""",
            (str(host_id), str(scan_job_id), str(phase_id), address, hostname,
             os_guess, datetime.now(timezone.utc).isoformat()),
        )
        await conn.commit()
        return host_id

    async def list_by_scan(self, scan_job_id: UUID) -> list[dict]:
        """Listet alle entdeckten Hosts eines Scans."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM discovered_hosts WHERE scan_job_id = ? ORDER BY address",
            (str(scan_job_id),),
        )
        return [dict(row) for row in await cursor.fetchall()]


class OpenPortRepository:
    """Persistiert offene Ports pro Host und Scan."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(
        self,
        scan_job_id: UUID,
        phase_id: UUID,
        host_address: str,
        port: int,
        protocol: str = "tcp",
        service: str = "",
        version: str = "",
    ) -> UUID:
        """Speichert einen offenen Port."""
        port_id = uuid4()
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO open_ports
               (id, scan_job_id, phase_id, host_address, port, protocol,
                state, service, version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)""",
            (str(port_id), str(scan_job_id), str(phase_id), host_address,
             port, protocol, service, version,
             datetime.now(timezone.utc).isoformat()),
        )
        await conn.commit()
        return port_id

    async def list_by_scan(self, scan_job_id: UUID) -> list[dict]:
        """Listet alle offenen Ports eines Scans."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM open_ports WHERE scan_job_id = ? ORDER BY host_address, port",
            (str(scan_job_id),),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def list_by_host(self, host_address: str) -> list[dict]:
        """Listet alle offenen Ports eines bestimmten Hosts."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM open_ports WHERE host_address = ? ORDER BY port",
            (host_address,),
        )
        return [dict(row) for row in await cursor.fetchall()]

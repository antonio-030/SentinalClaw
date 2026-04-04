"""
Repository-Klasse für Findings.

Ausgelagert aus repositories.py um die 300-Zeilen-Regel einzuhalten.
"""

from datetime import datetime
from uuid import UUID

import aiosqlite

from src.shared.database import DatabaseManager, deserialize_json, serialize_json
from src.shared.logging_setup import get_logger
from src.shared.types.models import Finding

logger = get_logger(__name__)


class FindingRepository:
    """CRUD-Operationen für Findings."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(self, finding: Finding) -> Finding:
        """Speichert ein neues Finding."""
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO findings
               (id, scan_job_id, tool_name, title, severity, cvss_score,
                cve_id, target_host, target_port, service, description,
                evidence, recommendation, raw_output, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(finding.id),
                str(finding.scan_job_id),
                finding.tool_name,
                finding.title,
                finding.severity.value,
                finding.cvss_score,
                finding.cve_id,
                finding.target_host,
                finding.target_port,
                finding.service,
                finding.description,
                finding.evidence,
                finding.recommendation,
                finding.raw_output,
                finding.created_at.isoformat(),
            ),
        )
        await conn.commit()
        return finding

    async def list_by_scan(self, scan_job_id: UUID) -> list[Finding]:
        """Listet alle Findings eines Scans, sortiert nach Schweregrad."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        # Sortierung: Critical > High > Medium > Low > Info
        cursor = await conn.execute(
            """SELECT * FROM findings WHERE scan_job_id = ?
               ORDER BY cvss_score DESC, created_at ASC""",
            (str(scan_job_id),),
        )
        rows = await cursor.fetchall()
        return [self._row_to_finding(row) for row in rows]

    async def list_all(self, severity: str | None = None, limit: int = 100) -> list[Finding]:
        """Listet alle Findings, optional gefiltert nach Schweregrad."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        if severity:
            cursor = await conn.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY cvss_score DESC LIMIT ?",
                (severity, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM findings ORDER BY cvss_score DESC, created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [self._row_to_finding(row) for row in rows]

    async def get_by_id(self, finding_id: UUID) -> Finding | None:
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT * FROM findings WHERE id = ?", (str(finding_id),))
        row = await cursor.fetchone()
        return self._row_to_finding(row) if row else None

    async def delete(self, finding_id: UUID) -> bool:
        conn = await self._db.get_connection()
        await conn.execute("DELETE FROM findings WHERE id = ?", (str(finding_id),))
        await conn.commit()
        return True

    async def delete_by_scan(self, scan_job_id: UUID) -> int:
        conn = await self._db.get_connection()
        cursor = await conn.execute("DELETE FROM findings WHERE scan_job_id = ?", (str(scan_job_id),))
        await conn.commit()
        return cursor.rowcount

    @staticmethod
    def _row_to_finding(row: aiosqlite.Row) -> Finding:
        """Konvertiert eine DB-Zeile in ein Finding-Modell."""
        return Finding(
            id=UUID(row["id"]),
            scan_job_id=UUID(row["scan_job_id"]),
            tool_name=row["tool_name"],
            title=row["title"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            cve_id=row["cve_id"],
            target_host=row["target_host"],
            target_port=row["target_port"],
            service=row["service"],
            description=row["description"],
            evidence=row["evidence"],
            recommendation=row["recommendation"],
            raw_output=row["raw_output"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

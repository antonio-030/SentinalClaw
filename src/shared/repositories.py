"""
Repository-Klassen für den Datenbankzugriff.

Jede Entität hat ein eigenes Repository. Das Repository-Pattern
ermöglicht den späteren Wechsel von SQLite zu PostgreSQL ohne
Änderungen im Rest des Codes.

WICHTIG: AuditLogRepository hat absichtlich KEIN update() und
kein delete(). Audit-Logs sind unveränderbar.
"""

from datetime import UTC, datetime
from uuid import UUID

import aiosqlite

from src.shared.database import DatabaseManager, deserialize_json, serialize_json
from src.shared.logging_setup import get_logger
from src.shared.types.models import (
    AgentLogEntry,
    AuditLogEntry,
    Finding,
    ScanJob,
    ScanStatus,
)

logger = get_logger(__name__)


class ScanJobRepository:
    """CRUD-Operationen für Scan-Jobs."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(self, job: ScanJob) -> ScanJob:
        """Erstellt einen neuen Scan-Job in der Datenbank."""
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO scan_jobs
               (id, target, scan_type, status, config, max_escalation_level,
                token_budget, tokens_used, started_at, completed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(job.id),
                job.target,
                job.scan_type.value,
                job.status.value,
                serialize_json(job.config),
                job.max_escalation_level,
                job.token_budget,
                job.tokens_used,
                job.started_at.isoformat() if job.started_at else None,
                job.completed_at.isoformat() if job.completed_at else None,
                job.created_at.isoformat(),
            ),
        )
        await conn.commit()
        logger.info("Scan-Job erstellt", scan_id=str(job.id), target=job.target)
        return job

    async def get_by_id(self, job_id: UUID) -> ScanJob | None:
        """Lädt einen Scan-Job anhand seiner ID."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM scan_jobs WHERE id = ?", (str(job_id),)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_scan_job(row)

    async def update_status(
        self, job_id: UUID, status: ScanStatus, tokens_used: int | None = None
    ) -> None:
        """Aktualisiert den Status eines Scan-Jobs."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()

        if status == ScanStatus.RUNNING:
            await conn.execute(
                "UPDATE scan_jobs SET status = ?, started_at = ? WHERE id = ?",
                (status.value, now, str(job_id)),
            )
        elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.EMERGENCY_KILLED):
            params: list = [status.value, now]
            sql = "UPDATE scan_jobs SET status = ?, completed_at = ?"
            if tokens_used is not None:
                sql += ", tokens_used = ?"
                params.append(tokens_used)
            sql += " WHERE id = ?"
            params.append(str(job_id))
            await conn.execute(sql, params)
        else:
            await conn.execute(
                "UPDATE scan_jobs SET status = ? WHERE id = ?",
                (status.value, str(job_id)),
            )

        await conn.commit()
        logger.info("Scan-Status aktualisiert", scan_id=str(job_id), status=status.value)

    async def list_by_status(self, status: ScanStatus) -> list[ScanJob]:
        """Listet alle Scan-Jobs mit einem bestimmten Status."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM scan_jobs WHERE status = ? ORDER BY created_at DESC",
            (status.value,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_scan_job(row) for row in rows]

    async def list_all(self, limit: int = 50) -> list[ScanJob]:
        """Listet die letzten Scan-Jobs."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_scan_job(row) for row in rows]

    async def delete(self, job_id: UUID) -> bool:
        """Löscht einen Scan-Job und alle zugehörigen Daten (kaskadierend)."""
        conn = await self._db.get_connection()
        # Delete in order: agent_logs, findings, scan_results, scan_phases,
        # discovered_hosts, open_ports, then scan_job itself
        for table in ["agent_logs", "scan_results", "findings", "scan_phases",
                       "discovered_hosts", "open_ports"]:
            await conn.execute(f"DELETE FROM {table} WHERE scan_job_id = ?", (str(job_id),))
        await conn.execute("DELETE FROM scan_jobs WHERE id = ?", (str(job_id),))
        await conn.commit()
        return True

    @staticmethod
    def _row_to_scan_job(row: aiosqlite.Row) -> ScanJob:
        """Konvertiert eine DB-Zeile in ein ScanJob-Modell."""
        return ScanJob(
            id=UUID(row["id"]),
            target=row["target"],
            scan_type=row["scan_type"],
            status=row["status"],
            config=deserialize_json(row["config"]),
            max_escalation_level=row["max_escalation_level"],
            token_budget=row["token_budget"],
            tokens_used=row["tokens_used"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=(
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            ),
            created_at=datetime.fromisoformat(row["created_at"]),
        )


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


class AuditLogRepository:
    """Audit-Log-Zugriff. NUR create() und list(). KEIN update, KEIN delete."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(self, entry: AuditLogEntry) -> AuditLogEntry:
        """Schreibt einen unveränderlichen Audit-Eintrag."""
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO audit_logs
               (id, action, resource_type, resource_id, details, triggered_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                str(entry.id),
                entry.action,
                entry.resource_type,
                entry.resource_id,
                serialize_json(entry.details),
                entry.triggered_by,
                entry.created_at.isoformat(),
            ),
        )
        await conn.commit()
        return entry

    async def list_recent(self, limit: int = 100) -> list[AuditLogEntry]:
        """Listet die neuesten Audit-Einträge."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    async def list_by_action(self, action: str, limit: int = 50) -> list[AuditLogEntry]:
        """Listet Audit-Einträge nach Aktionstyp."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM audit_logs WHERE action = ? ORDER BY created_at DESC LIMIT ?",
            (action, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    @staticmethod
    def _row_to_entry(row: aiosqlite.Row) -> AuditLogEntry:
        """Konvertiert eine DB-Zeile in ein AuditLogEntry-Modell."""
        return AuditLogEntry(
            id=UUID(row["id"]),
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            details=deserialize_json(row["details"]),
            triggered_by=row["triggered_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )


class AgentLogRepository:
    """Log-Einträge für Agent-Schritte."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(self, entry: AgentLogEntry) -> AgentLogEntry:
        """Speichert einen Agent-Schritt."""
        conn = await self._db.get_connection()
        await conn.execute(
            """INSERT INTO agent_logs
               (id, scan_job_id, agent_name, step_description, tool_name,
                input_params, output_summary, duration_ms, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(entry.id),
                str(entry.scan_job_id),
                entry.agent_name,
                entry.step_description,
                entry.tool_name,
                serialize_json(entry.input_params),
                entry.output_summary,
                entry.duration_ms,
                entry.created_at.isoformat(),
            ),
        )
        await conn.commit()
        return entry

    async def list_by_scan(self, scan_job_id: UUID) -> list[AgentLogEntry]:
        """Listet alle Agent-Schritte eines Scans."""
        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT * FROM agent_logs WHERE scan_job_id = ? ORDER BY created_at ASC",
            (str(scan_job_id),),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    @staticmethod
    def _row_to_entry(row: aiosqlite.Row) -> AgentLogEntry:
        """Konvertiert eine DB-Zeile in ein AgentLogEntry-Modell."""
        return AgentLogEntry(
            id=UUID(row["id"]),
            scan_job_id=UUID(row["scan_job_id"]),
            agent_name=row["agent_name"],
            step_description=row["step_description"],
            tool_name=row["tool_name"],
            input_params=deserialize_json(row["input_params"]),
            output_summary=row["output_summary"],
            duration_ms=row["duration_ms"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

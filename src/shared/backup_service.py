"""Backup-Service für SentinelClaw.

Unterstützt beide Backends:
- SQLite: Konsistentes Backup mittels VACUUM INTO
- PostgreSQL: Backup mittels pg_dump Subprocess

Verwaltet Backup-Retention und Wiederherstellung.
"""

import asyncio
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

BACKUP_DIR = Path("data/backups")


async def create_backup(db: DatabaseManager) -> Path:
    """Erstellt ein konsistentes Datenbank-Backup.

    Wählt automatisch die richtige Methode je nach Backend:
    - SQLite: VACUUM INTO (atomar, konsistent bei laufenden Schreibvorgängen)
    - PostgreSQL: pg_dump (konsistentes logisches Backup)

    Returns:
        Pfad zur erstellten Backup-Datei.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    if db.db_type == "postgresql":
        return await _backup_postgresql(db, timestamp)
    return await _backup_sqlite(db, timestamp)


async def _backup_sqlite(db: DatabaseManager, timestamp: str) -> Path:
    """SQLite-Backup via VACUUM INTO."""
    backup_path = BACKUP_DIR / f"sentinelclaw_{timestamp}.db"
    conn = await db.get_connection()
    await conn.execute(f"VACUUM INTO '{backup_path}'")

    size_mb = backup_path.stat().st_size / (1024 * 1024)
    logger.info("SQLite-Backup erstellt", path=str(backup_path), size_mb=round(size_mb, 2))
    return backup_path


async def _backup_postgresql(db: DatabaseManager, timestamp: str) -> Path:
    """PostgreSQL-Backup via pg_dump."""
    backup_path = BACKUP_DIR / f"sentinelclaw_{timestamp}.sql"

    from src.shared.config import get_settings
    settings = get_settings()

    process = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--host", settings.db_host,
        "--port", str(settings.db_port),
        "--username", settings.db_user,
        "--dbname", settings.db_name,
        "--no-password",
        "--format", "plain",
        "--file", str(backup_path),
        env={"PGPASSWORD": settings.db_password},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    if process.returncode != 0:
        error_msg = stderr.decode().strip()
        raise RuntimeError(f"pg_dump fehlgeschlagen: {error_msg}")

    size_mb = backup_path.stat().st_size / (1024 * 1024)
    logger.info("PostgreSQL-Backup erstellt", path=str(backup_path), size_mb=round(size_mb, 2))
    return backup_path


def list_backups() -> list[dict]:
    """Listet alle vorhandenen Backups mit Größe und Zeitstempel."""
    if not BACKUP_DIR.exists():
        return []

    backups = []
    for path in sorted(BACKUP_DIR.glob("sentinelclaw_*"), reverse=True):
        stat = path.stat()
        backups.append({
            "filename": path.name,
            "size_bytes": stat.st_size,
            "size_mb": round(stat.st_size / (1024 * 1024), 2),
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
        })
    return backups


async def restore_backup(backup_filename: str, db: DatabaseManager) -> None:
    """Stellt die Datenbank aus einem Backup wieder her.

    ACHTUNG: Überschreibt die aktuelle Datenbank irreversibel.
    """
    # Sicherheitsprüfung: Pfad muss innerhalb von BACKUP_DIR bleiben
    backup_path = (BACKUP_DIR / backup_filename).resolve()
    if not backup_path.is_relative_to(BACKUP_DIR.resolve()):
        raise ValueError(f"Unzulässiger Backup-Pfad: '{backup_filename}'")
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup '{backup_filename}' nicht gefunden")

    if db.db_type == "postgresql":
        await _restore_postgresql(backup_path, db)
    else:
        await _restore_sqlite(backup_path, db)


async def _restore_sqlite(backup_path: Path, db: DatabaseManager) -> None:
    """SQLite-Restore: Datei kopieren und DB neu initialisieren."""
    db_path = db._db_path
    await db.close()
    shutil.copy2(backup_path, db_path)
    logger.info("SQLite-Backup wiederhergestellt", backup=backup_path.name)
    await db.initialize()


async def _restore_postgresql(backup_path: Path, db: DatabaseManager) -> None:
    """PostgreSQL-Restore via psql."""
    from src.shared.config import get_settings
    settings = get_settings()

    await db.close()

    process = await asyncio.create_subprocess_exec(
        "psql",
        "--host", settings.db_host,
        "--port", str(settings.db_port),
        "--username", settings.db_user,
        "--dbname", settings.db_name,
        "--no-password",
        "--file", str(backup_path),
        env={"PGPASSWORD": settings.db_password},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    if process.returncode != 0:
        error_msg = stderr.decode().strip()
        raise RuntimeError(f"PostgreSQL-Restore fehlgeschlagen: {error_msg}")

    logger.info("PostgreSQL-Backup wiederhergestellt", backup=backup_path.name)
    await db.initialize()


def cleanup_old_backups(max_age_days: int | None = None) -> int:
    """Löscht Backups die älter als max_age_days sind.

    Returns:
        Anzahl gelöschter Backups.
    """
    if max_age_days is None:
        try:
            from src.shared.settings_service import get_setting_int
            max_age_days = get_setting_int("backup_retention_days", 30)
        except Exception:
            max_age_days = 30

    if not BACKUP_DIR.exists():
        return 0

    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
    deleted = 0

    for path in BACKUP_DIR.glob("sentinelclaw_*"):
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if mtime < cutoff:
            path.unlink()
            deleted += 1

    if deleted:
        logger.info(f"{deleted} alte Backups gelöscht (>{max_age_days} Tage)")
    return deleted

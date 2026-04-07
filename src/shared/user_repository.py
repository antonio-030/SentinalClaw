"""Benutzer-Repository für Datenbankzugriff (CRUD-Operationen).

Ausgelagert aus auth.py um die 300-Zeilen-Grenze einzuhalten.
Die Klasse wird in auth.py re-exportiert für Abwärtskompatibilität.
"""

from datetime import UTC, datetime
from uuid import uuid4

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


class UserRepository:
    """Datenbankzugriff für Benutzer-Verwaltung (CRUD-Operationen)."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def create(
        self,
        email: str,
        display_name: str,
        password: str,
        role: str = "analyst",
        must_change_password: bool = False,
    ) -> dict:
        """Erstellt einen neuen Benutzer mit gehashtem Passwort."""
        from src.shared.auth import hash_password

        conn = await self._db.get_connection()
        user_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        pw_hash = hash_password(password)

        await conn.execute(
            """
            INSERT INTO users
                (id, email, display_name, password_hash, role, must_change_password, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, email, display_name, pw_hash, role, must_change_password, now),
        )
        await conn.commit()
        logger.info("Benutzer erstellt", user_id=user_id, email=email, role=role)

        return {
            "id": user_id,
            "email": email,
            "display_name": display_name,
            "role": role,
            "is_active": True,
            "created_at": now,
        }

    async def get_by_email(self, email: str) -> dict | None:
        """Sucht einen Benutzer anhand der E-Mail-Adresse."""
        conn = await self._db.get_connection()
        cursor = await conn.execute(
            "SELECT id, email, display_name, password_hash, role, is_active, "
            "mfa_enabled, mfa_secret, must_change_password, last_login_at, "
            "created_at FROM users WHERE email = ?",
            (email,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    async def get_by_id(self, user_id: str) -> dict | None:
        """Sucht einen Benutzer anhand der ID."""
        conn = await self._db.get_connection()
        cursor = await conn.execute(
            "SELECT id, email, display_name, password_hash, role, is_active, "
            "mfa_enabled, mfa_secret, must_change_password, last_login_at, "
            "created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    async def list_all(self) -> list[dict]:
        """Listet alle Benutzer auf (ohne Passwort-Hash und ohne MFA-Secret)."""
        conn = await self._db.get_connection()
        cursor = await conn.execute(
            "SELECT id, email, display_name, password_hash, role, is_active, "
            "mfa_enabled, mfa_secret, must_change_password, last_login_at, "
            "created_at FROM users ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [self._row_to_public_dict(row) for row in rows]

    async def update_last_login(self, user_id: str) -> None:
        """Aktualisiert den Zeitstempel des letzten Logins."""
        conn = await self._db.get_connection()
        now = datetime.now(UTC).isoformat()
        await conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (now, user_id),
        )
        await conn.commit()

    async def delete(self, user_id: str) -> None:
        """Löscht einen Benutzer aus der Datenbank."""
        conn = await self._db.get_connection()
        await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await conn.commit()
        logger.info("Benutzer gelöscht", user_id=user_id)

    async def update_role(self, user_id: str, role: str) -> None:
        """Ändert die Rolle eines Benutzers."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id),
        )
        await conn.commit()
        logger.info("Benutzer-Rolle geändert", user_id=user_id, new_role=role)

    async def update_mfa(
        self, user_id: str, mfa_enabled: bool, mfa_secret: str,
    ) -> None:
        """Aktualisiert den MFA-Status und das TOTP-Secret eines Benutzers."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET mfa_enabled = ?, mfa_secret = ? WHERE id = ?",
            (mfa_enabled, mfa_secret, user_id),
        )
        await conn.commit()
        logger.info(
            "MFA-Status geändert", user_id=user_id, mfa_enabled=mfa_enabled,
        )

    async def update_password(self, user_id: str, new_hash: str) -> None:
        """Setzt ein neues Passwort-Hash für den Benutzer."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id),
        )
        await conn.commit()
        logger.info("Passwort geändert", user_id=user_id)

    async def clear_must_change(self, user_id: str) -> None:
        """Entfernt die Pflicht zur Passwortänderung."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET must_change_password = 0 WHERE id = ?",
            (user_id,),
        )
        await conn.commit()
        logger.info("Passwortänderungspflicht aufgehoben", user_id=user_id)

    # Spalten-Reihenfolge: id(0), email(1), display_name(2), password_hash(3),
    # role(4), is_active(5), mfa_enabled(6), mfa_secret(7),
    # must_change_password(8), last_login_at(9), created_at(10)

    @staticmethod
    def _row_to_dict(row: tuple) -> dict:
        """Vollständiges Dict (inkl. Hash + MFA-Secret)."""
        return {
            "id": row[0], "email": row[1], "display_name": row[2],
            "password_hash": row[3], "role": row[4],
            "is_active": bool(row[5]), "mfa_enabled": bool(row[6]),
            "mfa_secret": row[7] or "", "must_change_password": bool(row[8]),
            "last_login_at": row[9], "created_at": row[10],
        }

    @staticmethod
    def _row_to_public_dict(row: tuple) -> dict:
        """Öffentliches Dict (ohne Hash/Secret)."""
        return {
            "id": row[0], "email": row[1], "display_name": row[2],
            "role": row[4], "is_active": bool(row[5]),
            "mfa_enabled": bool(row[6]),
            "last_login_at": row[9], "created_at": row[10],
        }


async def ensure_default_admin(db: DatabaseManager) -> None:
    """Legt einen Standard-Admin an (mit Passwortänderungspflicht)."""
    repo = UserRepository(db)
    admin = await repo.get_by_email("admin@sentinelclaw.local")
    if not admin:
        await repo.create(
            email="admin@sentinelclaw.local",
            display_name="Administrator",
            password="admin",
            role="system_admin",
            must_change_password=True,
        )
        logger.info("Standard-Admin erstellt (admin@sentinelclaw.local)")

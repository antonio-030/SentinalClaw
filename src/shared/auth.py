"""
Authentifizierung und Autorisierung für SentinelClaw.

Stellt JWT-basierte Auth, Passwort-Hashing (bcrypt) und RBAC bereit.
MFA-Funktionen (TOTP) sind in src/shared/mfa.py ausgelagert.
"""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import bcrypt
import jwt

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.mfa import create_mfa_session_token as _create_mfa_session_raw
from src.shared.mfa import decode_mfa_session_token as _decode_mfa_session_raw
from src.shared.mfa import (
    generate_mfa_secret,  # noqa: F401
    get_mfa_provisioning_uri,  # noqa: F401
    verify_mfa_token,  # noqa: F401
)

logger = get_logger(__name__)

# JWT-Secret aus Umgebungsvariable — Fallback NUR für lokale Entwicklung
_DEFAULT_DEV_SECRET = "sentinelclaw-dev-only-NICHT-FUER-PRODUKTION"
SECRET_KEY = os.environ.get("SENTINEL_JWT_SECRET", _DEFAULT_DEV_SECRET)

if SECRET_KEY == _DEFAULT_DEV_SECRET:
    logger.warning(
        "JWT-Secret nicht gesetzt — nutze Dev-Default. "
        "Setze SENTINEL_JWT_SECRET in .env für Produktion!"
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 Stunden

# Rollen-Hierarchie: höhere Zahl = mehr Rechte
ROLES = {
    "system_admin": 100,
    "org_admin": 80,
    "security_lead": 60,
    "analyst": 40,
    "viewer": 20,
}



def hash_password(password: str) -> str:
    """Erzeugt einen bcrypt-Hash für das Passwort."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Prüft ob das Passwort zum gespeicherten Hash passt."""
    return bcrypt.checkpw(password.encode(), hashed.encode())



def create_access_token(user_id: str, email: str, role: str) -> str:
    """Erstellt einen JWT-Access-Token mit Benutzer-Informationen."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_session_token(user_id: str, email: str, role: str) -> str:
    """Delegiert an mfa.py — übergibt das JWT-Secret und den Algorithmus."""
    return _create_mfa_session_raw(user_id, email, role, SECRET_KEY, ALGORITHM)


def decode_mfa_session_token(token: str) -> dict | None:
    """Delegiert an mfa.py — übergibt das JWT-Secret und den Algorithmus."""
    return _decode_mfa_session_raw(token, SECRET_KEY, ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Dekodiert und validiert einen JWT-Token. Gibt None bei Fehler zurück."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None



def role_has_permission(user_role: str, required_role: str) -> bool:
    """Prüft ob die Benutzer-Rolle ausreichend Rechte hat."""
    return ROLES.get(user_role, 0) >= ROLES.get(required_role, 100)



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
    ) -> dict:
        """Erstellt einen neuen Benutzer mit gehashtem Passwort."""
        conn = await self._db.get_connection()
        user_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        pw_hash = hash_password(password)

        await conn.execute(
            """
            INSERT INTO users (id, email, display_name, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, email, display_name, pw_hash, role, now),
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
            "mfa_enabled, mfa_secret, last_login_at, created_at FROM users WHERE email = ?",
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
            "mfa_enabled, mfa_secret, last_login_at, created_at FROM users WHERE id = ?",
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
            "mfa_enabled, mfa_secret, last_login_at, created_at "
            "FROM users ORDER BY created_at DESC"
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
        self, user_id: str, mfa_enabled: bool, mfa_secret: str
    ) -> None:
        """Aktualisiert den MFA-Status und das TOTP-Secret eines Benutzers."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET mfa_enabled = ?, mfa_secret = ? WHERE id = ?",
            (mfa_enabled, mfa_secret, user_id),
        )
        await conn.commit()
        logger.info(
            "MFA-Status geändert",
            user_id=user_id,
            mfa_enabled=mfa_enabled,
        )

    @staticmethod
    def _row_to_dict(row: tuple) -> dict:
        """Konvertiert eine Datenbankzeile in ein vollständiges Dict (inkl. Hash + MFA-Secret)."""
        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "password_hash": row[3],
            "role": row[4],
            "is_active": bool(row[5]),
            "mfa_enabled": bool(row[6]),
            "mfa_secret": row[7] or "",
            "last_login_at": row[8],
            "created_at": row[9],
        }

    @staticmethod
    def _row_to_public_dict(row: tuple) -> dict:
        """Konvertiert eine Datenbankzeile in ein öffentliches Dict (ohne Hash/Secret)."""
        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "role": row[4],
            "is_active": bool(row[5]),
            "mfa_enabled": bool(row[6]),
            "last_login_at": row[8],
            "created_at": row[9],
        }



async def ensure_default_admin(db: DatabaseManager) -> None:
    """Legt einen Standard-Admin an, falls noch keiner existiert."""
    repo = UserRepository(db)
    admin = await repo.get_by_email("admin@sentinelclaw.local")
    if not admin:
        await repo.create(
            email="admin@sentinelclaw.local",
            display_name="Administrator",
            password="admin",
            role="system_admin",
        )
        logger.info("Standard-Admin erstellt (admin@sentinelclaw.local)")



def extract_user_from_request(request: object) -> dict:
    """Extrahiert den authentifizierten Benutzer aus dem Request-State.

    Wird von allen Route-Modulen genutzt um den aktuellen User zu holen.
    Wirft 401 wenn kein User im Request vorhanden ist.
    """
    from fastapi import HTTPException

    user = getattr(getattr(request, "state", None), "user", None)
    if not user:
        raise HTTPException(401, "Nicht authentifiziert")
    return user


def require_role(request: object, required_role: str) -> dict:
    """Prüft ob der aktuelle Benutzer die erforderliche Rolle hat.

    Kombiniert User-Extraktion und Rollen-Prüfung in einem Aufruf.
    Gibt den User zurück wenn die Berechtigung ausreicht.
    Wirft 401 (nicht eingeloggt) oder 403 (unzureichende Rolle).
    """
    from fastapi import HTTPException

    user = extract_user_from_request(request)
    if not role_has_permission(user.get("role", ""), required_role):
        raise HTTPException(
            403,
            f"Unzureichende Berechtigung — Rolle '{required_role}' oder höher erforderlich",
        )
    return user

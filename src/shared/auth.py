"""
Authentifizierung und Autorisierung fuer SentinelClaw.

Stellt JWT-basierte Authentifizierung, Passwort-Hashing (bcrypt)
und rollenbasierte Zugriffskontrolle (RBAC) bereit.
Standardmaessig wird beim ersten Start ein Admin-Benutzer angelegt.
"""

import os

import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# JWT-Secret aus Umgebungsvariable — Fallback NUR fuer lokale Entwicklung
_DEFAULT_DEV_SECRET = "sentinelclaw-dev-only-NICHT-FUER-PRODUKTION"
SECRET_KEY = os.environ.get("SENTINEL_JWT_SECRET", _DEFAULT_DEV_SECRET)

if SECRET_KEY == _DEFAULT_DEV_SECRET:
    logger.warning(
        "JWT-Secret nicht gesetzt — nutze Dev-Default. "
        "Setze SENTINEL_JWT_SECRET in .env fuer Produktion!"
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 Stunden

# Rollen-Hierarchie: hoehere Zahl = mehr Rechte
ROLES = {
    "system_admin": 100,
    "org_admin": 80,
    "security_lead": 60,
    "analyst": 40,
    "viewer": 20,
}


# ─── Passwort-Funktionen ─────────────────────────────────────────


def hash_password(password: str) -> str:
    """Erzeugt einen bcrypt-Hash fuer das Passwort."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Prueft ob das Passwort zum gespeicherten Hash passt."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ─── JWT-Token-Funktionen ────────────────────────────────────────


def create_access_token(user_id: str, email: str, role: str) -> str:
    """Erstellt einen JWT-Access-Token mit Benutzer-Informationen."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Dekodiert und validiert einen JWT-Token. Gibt None bei Fehler zurueck."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


# ─── Rollen-Pruefung ─────────────────────────────────────────────


def role_has_permission(user_role: str, required_role: str) -> bool:
    """Prueft ob die Benutzer-Rolle ausreichend Rechte hat."""
    return ROLES.get(user_role, 0) >= ROLES.get(required_role, 100)


# ─── Benutzer-Repository ─────────────────────────────────────────


class UserRepository:
    """Datenbankzugriff fuer Benutzer-Verwaltung (CRUD-Operationen)."""

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
        now = datetime.now(timezone.utc).isoformat()
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
            "mfa_enabled, last_login_at, created_at FROM users WHERE email = ?",
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
            "mfa_enabled, last_login_at, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    async def list_all(self) -> list[dict]:
        """Listet alle Benutzer auf (ohne Passwort-Hash)."""
        conn = await self._db.get_connection()
        cursor = await conn.execute(
            "SELECT id, email, display_name, password_hash, role, is_active, "
            "mfa_enabled, last_login_at, created_at FROM users ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [self._row_to_public_dict(row) for row in rows]

    async def update_last_login(self, user_id: str) -> None:
        """Aktualisiert den Zeitstempel des letzten Logins."""
        conn = await self._db.get_connection()
        now = datetime.now(timezone.utc).isoformat()
        await conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (now, user_id),
        )
        await conn.commit()

    async def delete(self, user_id: str) -> None:
        """Loescht einen Benutzer aus der Datenbank."""
        conn = await self._db.get_connection()
        await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await conn.commit()
        logger.info("Benutzer geloescht", user_id=user_id)

    async def update_role(self, user_id: str, role: str) -> None:
        """Aendert die Rolle eines Benutzers."""
        conn = await self._db.get_connection()
        await conn.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id),
        )
        await conn.commit()
        logger.info("Benutzer-Rolle geaendert", user_id=user_id, new_role=role)

    # ─── Interne Hilfsmethoden ────────────────────────────────────

    @staticmethod
    def _row_to_dict(row: tuple) -> dict:
        """Konvertiert eine Datenbankzeile in ein vollstaendiges Dict (inkl. Hash)."""
        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "password_hash": row[3],
            "role": row[4],
            "is_active": bool(row[5]),
            "mfa_enabled": bool(row[6]),
            "last_login_at": row[7],
            "created_at": row[8],
        }

    @staticmethod
    def _row_to_public_dict(row: tuple) -> dict:
        """Konvertiert eine Datenbankzeile in ein oeffentliches Dict (ohne Hash)."""
        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "role": row[4],
            "is_active": bool(row[5]),
            "mfa_enabled": bool(row[6]),
            "last_login_at": row[7],
            "created_at": row[8],
        }


# ─── Standard-Admin beim ersten Start anlegen ────────────────────


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


# ─── Shared RBAC-Helpers fuer alle Route-Module ─────────────────


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
    """Prueft ob der aktuelle Benutzer die erforderliche Rolle hat.

    Kombiniert User-Extraktion und Rollen-Pruefung in einem Aufruf.
    Gibt den User zurueck wenn die Berechtigung ausreicht.
    Wirft 401 (nicht eingeloggt) oder 403 (unzureichende Rolle).
    """
    from fastapi import HTTPException

    user = extract_user_from_request(request)
    if not role_has_permission(user.get("role", ""), required_role):
        raise HTTPException(
            403,
            f"Unzureichende Berechtigung — Rolle '{required_role}' oder hoeher erforderlich",
        )
    return user

"""Authentifizierung und Autorisierung für SentinelClaw.

Stellt JWT-basierte Auth, Passwort-Hashing (bcrypt) und RBAC bereit.
MFA-Funktionen (TOTP) sind in src/shared/mfa.py ausgelagert.
UserRepository ist in src/shared/user_repository.py ausgelagert.
"""

import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import bcrypt
import jwt

from src.shared.logging_setup import get_logger
from src.shared.mfa import create_mfa_session_token as _create_mfa_session_raw
from src.shared.mfa import decode_mfa_session_token as _decode_mfa_session_raw
from src.shared.mfa import (
    generate_mfa_secret,  # noqa: F401
    get_mfa_provisioning_uri,  # noqa: F401
    verify_mfa_token,  # noqa: F401
)

# Re-Exporte für Abwärtskompatibilität — UserRepository wurde ausgelagert
from src.shared.user_repository import (
    UserRepository,  # noqa: F401
    ensure_default_admin,  # noqa: F401
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
# Token-Lebensdauer konfigurierbar über Umgebungsvariable (Default: 60 Min für Enterprise)
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.environ.get("SENTINEL_TOKEN_EXPIRE_MINUTES", "60")
)
# Inaktivitäts-Timeout: Automatischer Logout nach N Minuten ohne Aktivität
SESSION_INACTIVITY_MINUTES = int(
    os.environ.get("SENTINEL_SESSION_INACTIVITY_MINUTES", "30")
)


def validate_jwt_secret_for_production(debug: bool) -> None:
    """Prüft ob das JWT-Secret für Produktion sicher genug ist."""
    if not debug and SECRET_KEY == _DEFAULT_DEV_SECRET:
        raise RuntimeError(
            "SENTINEL_JWT_SECRET ist nicht gesetzt oder nutzt den Dev-Default. "
            "Setze ein sicheres Secret in .env bevor du im Produktionsmodus startest. "
            "Mindestens 32 Zeichen, z.B.: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )

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


def create_access_token(
    user_id: str, email: str, role: str, org_id: str = "default-org",
) -> tuple[str, str]:
    """Erstellt einen JWT-Access-Token mit jti und org_id.

    Returns:
        Tuple aus (token, jti) — jti wird für Logout/Revokation benötigt.
    """
    jti = uuid4().hex
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "org_id": org_id,
        "jti": jti,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": now,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti


def generate_csrf_token() -> str:
    """Erzeugt ein kryptografisch sicheres CSRF-Token."""
    return secrets.token_hex(32)


def create_mfa_session_token(user_id: str, email: str, role: str) -> str:
    """Delegiert an mfa.py — übergibt JWT-Secret und Algorithmus."""
    return _create_mfa_session_raw(user_id, email, role, SECRET_KEY, ALGORITHM)

def decode_mfa_session_token(token: str) -> dict | None:
    """Delegiert an mfa.py — übergibt JWT-Secret und Algorithmus."""
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


def extract_user_from_request(request: object) -> dict:
    """Extrahiert den authentifizierten Benutzer aus dem Request-State."""
    from fastapi import HTTPException

    user = getattr(getattr(request, "state", None), "user", None)
    if not user:
        raise HTTPException(401, "Nicht authentifiziert")
    return user


def require_role(request: object, required_role: str) -> dict:
    """Prüft ob der aktuelle Benutzer die erforderliche Rolle hat."""
    from fastapi import HTTPException

    user = extract_user_from_request(request)
    if not role_has_permission(user.get("role", ""), required_role):
        raise HTTPException(
            403,
            f"Unzureichende Berechtigung — Rolle '{required_role}' oder höher erforderlich",
        )
    return user

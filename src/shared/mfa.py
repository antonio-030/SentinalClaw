"""
Multi-Faktor-Authentifizierung (MFA) für SentinelClaw.

Stellt TOTP-basierte Funktionen bereit:
  - Secret-Generierung für neue MFA-Einrichtung
  - Provisioning-URI für QR-Code-Generierung
  - Token-Verifikation mit Zeittoleranz
  - MFA-Session-Token für den zweistufigen Login-Flow
"""

from datetime import UTC, datetime, timedelta

import jwt
import pyotp

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Wird zur Laufzeit aus auth.py bezogen um zirkuläre Imports zu vermeiden
_MFA_SESSION_EXPIRE_MINUTES = 5


# ─── TOTP-Funktionen ─────────────────────────────────────────────


def generate_mfa_secret() -> str:
    """Erzeugt ein neues TOTP-Secret für den Benutzer."""
    return pyotp.random_base32()


def get_mfa_provisioning_uri(secret: str, email: str) -> str:
    """Erzeugt die otpauth:// URI für QR-Code-Generierung."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="SentinelClaw")


def verify_mfa_token(secret: str, token: str) -> bool:
    """Prüft einen 6-stelligen TOTP-Code gegen das Secret.

    Erlaubt ±30 Sekunden Toleranz (valid_window=1) um
    Zeitversatz zwischen Server und Authenticator-App auszugleichen.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


# ─── MFA-Session-Token ───────────────────────────────────────────


def create_mfa_session_token(
    user_id: str, email: str, role: str, secret_key: str, algorithm: str
) -> str:
    """Erstellt einen kurzlebigen Token für die MFA-Verifikation beim Login.

    Dieser Token berechtigt NUR zum Abschluss des MFA-Flows,
    nicht für andere API-Zugriffe (erkennbar am purpose-Claim).
    """
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "purpose": "mfa_login",
        "exp": datetime.now(UTC) + timedelta(minutes=_MFA_SESSION_EXPIRE_MINUTES),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_mfa_session_token(
    token: str, secret_key: str, algorithm: str
) -> dict | None:
    """Dekodiert einen MFA-Session-Token und prüft den Zweck.

    Gibt None zurück wenn der Token ungültig ist oder
    nicht für den MFA-Login-Flow bestimmt ist.
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.PyJWTError:
        return None

    if payload.get("purpose") != "mfa_login":
        return None
    return payload

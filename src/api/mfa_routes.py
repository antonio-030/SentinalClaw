"""
MFA-Routen (Multi-Faktor-Authentifizierung) für die SentinelClaw REST-API.

Endpoints unter /api/v1/auth/mfa:
  - POST /auth/mfa/login    -> TOTP-Verifikation beim Login (öffentlich)
  - POST /auth/mfa/setup    -> MFA-Secret generieren (authentifiziert)
  - POST /auth/mfa/verify   -> MFA aktivieren mit erstem Code (authentifiziert)
  - POST /auth/mfa/disable  -> MFA deaktivieren (authentifiziert)
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import (
    UserRepository,
    create_access_token,
    decode_mfa_session_token,
    extract_user_from_request,
    generate_mfa_secret,
    get_mfa_provisioning_uri,
    verify_mfa_token,
)
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth/mfa", tags=["MFA"])


# ─── Request-Modelle ─────────────────────────────────────────────


class MfaLoginRequest(BaseModel):
    """MFA-Code-Eingabe beim Login (zweiter Schritt)."""
    mfa_session: str
    token: str = Field(description="6-stelliger TOTP-Code")


class MfaVerifyRequest(BaseModel):
    """Erster TOTP-Code zum Aktivieren von MFA."""
    secret: str
    token: str = Field(description="6-stelliger TOTP-Code")


class MfaDisableRequest(BaseModel):
    """TOTP-Code zum Deaktivieren von MFA."""
    token: str = Field(description="6-stelliger TOTP-Code")


# ─── Hilfsfunktionen ─────────────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkuläre Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


# ─── Endpoints ────��───────────────────────────────────────────────


@router.post("/login")
async def mfa_login(body: MfaLoginRequest) -> dict:
    """Verifiziert den TOTP-Code und schließt den MFA-Login ab.

    Erwartet den temporären MFA-Session-Token und einen gültigen
    6-stelligen TOTP-Code. Gibt bei Erfolg den vollwertigen JWT zurück.
    """
    # MFA-Session-Token dekodieren und validieren
    payload = decode_mfa_session_token(body.mfa_session)
    if payload is None:
        raise HTTPException(401, "MFA-Session abgelaufen oder ungültig")

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(payload["sub"])
    if not user or not user.get("mfa_enabled"):
        raise HTTPException(400, "MFA ist für diesen Benutzer nicht aktiviert")

    # TOTP-Code gegen das gespeicherte Secret prüfen
    if not verify_mfa_token(user["mfa_secret"], body.token):
        logger.warning("MFA-Code ungültig", email=user["email"])
        raise HTTPException(401, "Ungültiger MFA-Code")

    # MFA erfolgreich — vollwertigen Token ausgeben
    await repo.update_last_login(user["id"])
    access_token = create_access_token(user["id"], user["email"], user["role"])
    logger.info("MFA-Login erfolgreich", email=user["email"])

    return {
        "token": access_token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "mfa_required": False,
        "mfa_session": "",
    }


@router.post("/setup")
async def mfa_setup(request: Request) -> dict:
    """Generiert ein neues MFA-Secret und die QR-Code-URI.

    Das Secret wird noch NICHT in der Datenbank gespeichert —
    erst nach erfolgreicher Verifikation mit /mfa/verify.
    """
    caller = extract_user_from_request(request)

    db = await _get_db()
    repo = UserRepository(db)
    user = await repo.get_by_id(caller["sub"])
    if not user:
        raise HTTPException(404, "Benutzer nicht gefunden")

    if user.get("mfa_enabled"):
        raise HTTPException(400, "MFA ist bereits aktiviert")

    secret = generate_mfa_secret()
    provisioning_uri = get_mfa_provisioning_uri(secret, user["email"])

    logger.info("MFA-Setup gestartet", user_id=user["id"])
    return {"secret": secret, "provisioning_uri": provisioning_uri}


@router.post("/verify")
async def mfa_verify(request: Request, body: MfaVerifyRequest) -> dict:
    """Verifiziert den ersten TOTP-Code und aktiviert MFA.

    Wird nach /mfa/setup aufgerufen. Prüft ob der Benutzer das Secret
    korrekt in seine Authenticator-App übernommen hat.
    """
    caller = extract_user_from_request(request)

    # TOTP-Code gegen das übergebene Secret prüfen
    if not verify_mfa_token(body.secret, body.token):
        raise HTTPException(400, "Ungültiger Code — bitte erneut versuchen")

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(caller["sub"])
    if not user:
        raise HTTPException(404, "Benutzer nicht gefunden")

    if user.get("mfa_enabled"):
        raise HTTPException(400, "MFA ist bereits aktiviert")

    # Secret speichern und MFA aktivieren
    await repo.update_mfa(user["id"], mfa_enabled=True, mfa_secret=body.secret)
    logger.info("MFA aktiviert", user_id=user["id"])

    return {"status": "enabled", "message": "MFA wurde erfolgreich aktiviert"}


@router.post("/disable")
async def mfa_disable(request: Request, body: MfaDisableRequest) -> dict:
    """Deaktiviert MFA. Erfordert einen gültigen TOTP-Code als Bestätigung."""
    caller = extract_user_from_request(request)

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(caller["sub"])
    if not user:
        raise HTTPException(404, "Benutzer nicht gefunden")

    if not user.get("mfa_enabled"):
        raise HTTPException(400, "MFA ist nicht aktiviert")

    # Aktuellen TOTP-Code prüfen bevor MFA deaktiviert wird
    if not verify_mfa_token(user["mfa_secret"], body.token):
        raise HTTPException(400, "Ungültiger Code — MFA bleibt aktiv")

    await repo.update_mfa(user["id"], mfa_enabled=False, mfa_secret="")
    logger.info("MFA deaktiviert", user_id=user["id"])

    return {"status": "disabled", "message": "MFA wurde deaktiviert"}

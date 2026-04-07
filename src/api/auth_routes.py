"""
Authentifizierungs-Routen für die SentinelClaw REST-API.

Endpoints unter /api/v1/auth:
  - POST /auth/login            -> Benutzer-Login (öffentlich, MFA-fähig)
  - POST /auth/register         -> Benutzer anlegen (nur system_admin)
  - POST /auth/change-password  -> Eigenes Passwort ändern
  - POST /auth/logout           -> Serverseitiges Logout
  - GET  /auth/me               -> Aktuellen Benutzer abrufen

Benutzerverwaltung (users) befindet sich in user_management_routes.py.
MFA-Endpoints befinden sich in mfa_routes.py.
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.api.cookie_auth import clear_auth_cookies, set_auth_cookies
from src.shared.auth import (
    UserRepository,
    create_access_token,
    create_mfa_session_token,
    extract_user_from_request,
    generate_csrf_token,
    hash_password,
    role_has_permission,
    verify_password,
)
from src.shared.logging_setup import get_logger
from src.shared.token_blacklist import token_blacklist

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


# ─── Request/Response Modelle ─────────────────────────────────────


class LoginRequest(BaseModel):
    """Anmeldedaten für den Login."""
    email: str
    password: str


class RegisterRequest(BaseModel):
    """Daten für die Benutzer-Registrierung."""
    email: str
    display_name: str
    password: str


class ChangePasswordRequest(BaseModel):
    """Anfrage zum Ändern des eigenen Passworts."""
    old_password: str
    new_password: str


# ─── Hilfsfunktionen ─────────────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkuläre Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


def _extract_user_from_request(request: Request) -> dict:
    """Wrapper für shared Helper — Abwärtskompatibilität."""
    return extract_user_from_request(request)


def _require_role(user: dict, required_role: str) -> None:
    """Prüft ob der Benutzer die erforderliche Rolle hat."""
    if not role_has_permission(user.get("role", ""), required_role):
        raise HTTPException(
            403,
            f"Unzureichende Berechtigung — Rolle '{required_role}' oder höher erforderlich",
        )


def _check_rate_limit(request: Request) -> None:
    """Prüft ob die Client-IP durch Rate-Limiting blockiert ist."""
    from src.api.rate_limit_login import get_rate_limiter

    client_ip = request.client.host if request.client else "unknown"
    limiter = get_rate_limiter()

    if limiter.is_blocked(client_ip):
        logger.warning("Login-Rate-Limit erreicht", ip=client_ip)
        raise HTTPException(
            429,
            "Zu viele fehlgeschlagene Login-Versuche. Bitte warte 5 Minuten.",
        )


def _build_mfa_response(user: dict) -> dict:
    """Erstellt die MFA-Antwort mit temporärem Session-Token."""
    mfa_session = create_mfa_session_token(
        user["id"], user["email"], user["role"]
    )
    logger.info("MFA erforderlich", email=user["email"])
    return {
        "token": "",
        "user": {},
        "mfa_required": True,
        "mfa_session": mfa_session,
    }


def _build_login_response(user: dict) -> JSONResponse:
    """Erstellt die vollständige Login-Antwort mit Auth-Cookies."""
    token, jti = create_access_token(user["id"], user["email"], user["role"])
    csrf_token = generate_csrf_token()
    logger.info("Benutzer eingeloggt", email=user["email"], role=user["role"])

    response = JSONResponse(content={
        "token": "",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "mfa_required": False,
        "mfa_session": "",
        "must_change_password": user.get("must_change_password", False),
    })
    set_auth_cookies(response, token, csrf_token)
    return response


# ─── Endpoints ────────────────────────────────────────────────────


@router.post("/login")
async def login(request: Request, body: LoginRequest) -> dict:
    """Authentifiziert einen Benutzer und gibt einen JWT-Token zurück.

    Bei aktiviertem MFA wird stattdessen ein temporärer MFA-Session-Token
    zurückgegeben, mit dem der zweite Faktor verifiziert werden muss.
    Rate-Limited: Max. N fehlgeschlagene Versuche pro IP in 5 Minuten.
    """
    from src.api.rate_limit_login import get_rate_limiter

    _check_rate_limit(request)

    client_ip = request.client.host if request.client else "unknown"
    limiter = get_rate_limiter()

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_email(body.email)
    if not user:
        limiter.record_failure(client_ip)
        raise HTTPException(401, "Ungültige Anmeldedaten")

    if not user.get("is_active"):
        raise HTTPException(403, "Benutzerkonto ist deaktiviert")

    if not verify_password(body.password, user["password_hash"]):
        limiter.record_failure(client_ip)
        raise HTTPException(401, "Ungültige Anmeldedaten")

    # Erfolgreicher Passwort-Check — Rate-Limit-Zähler zurücksetzen
    limiter.reset(client_ip)

    # MFA-Prüfung: Wenn aktiviert, noch keinen vollwertigen Token ausgeben
    if user.get("mfa_enabled"):
        return _build_mfa_response(user)

    # Kein MFA — direkt vollwertigen Token als HttpOnly Cookie ausgeben
    await repo.update_last_login(user["id"])
    return _build_login_response(user)


@router.post("/register")
async def register(body: RegisterRequest, request: Request) -> dict:
    """Registriert einen neuen Benutzer (nur für system_admin)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "system_admin")

    db = await _get_db()
    repo = UserRepository(db)

    # Passwort-Policy prüfen
    from src.shared.password_policy import validate_password
    pw_errors = validate_password(body.password)
    if pw_errors:
        raise HTTPException(400, "Passwort-Anforderungen: " + "; ".join(pw_errors))

    # Prüfen ob E-Mail bereits vergeben ist
    existing = await repo.get_by_email(body.email)
    if existing:
        raise HTTPException(409, f"E-Mail '{body.email}' ist bereits registriert")

    user = await repo.create(
        email=body.email,
        display_name=body.display_name,
        password=body.password,
    )
    return {"status": "created", "user": user}


@router.post("/change-password")
async def change_password(request: Request, body: ChangePasswordRequest) -> dict:
    """Ändert das Passwort des aktuell eingeloggten Benutzers.

    Prüft das alte Passwort, validiert das neue (min. 8 Zeichen),
    setzt das neue Passwort und hebt die Passwortänderungspflicht auf.
    """
    caller = _extract_user_from_request(request)

    # Passwort-Policy prüfen (Enterprise-Anforderungen)
    from src.shared.password_policy import validate_password
    pw_errors = validate_password(body.new_password)
    if pw_errors:
        raise HTTPException(400, "Passwort-Anforderungen nicht erfüllt: " + "; ".join(pw_errors))

    db = await _get_db()
    repo = UserRepository(db)
    user = await repo.get_by_id(caller["sub"])
    if not user:
        raise HTTPException(404, "Benutzer nicht gefunden")

    if not verify_password(body.old_password, user["password_hash"]):
        raise HTTPException(401, "Altes Passwort ist falsch")

    new_hash = hash_password(body.new_password)
    await repo.update_password(user["id"], new_hash)
    await repo.clear_must_change(user["id"])

    logger.info("Passwort geändert", user_id=user["id"], email=user["email"])
    return {"status": "changed", "message": "Passwort erfolgreich geändert"}


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    """Serverseitiges Logout — revoziert den Token und löscht die Cookies.

    Der Token wird auf die Blacklist gesetzt und kann nicht mehr verwendet werden,
    selbst wenn der Cookie noch im Browser vorhanden wäre.
    """
    caller = _extract_user_from_request(request)

    # Token revozieren falls jti vorhanden
    jti = caller.get("jti")
    exp = caller.get("exp", "")
    if jti:
        db = await _get_db()
        # exp als ISO-String für DB speichern
        from datetime import UTC, datetime
        exp_str = datetime.fromtimestamp(exp, tz=UTC).isoformat() if exp else ""
        await token_blacklist.revoke(jti, exp_str, db)

    logger.info("Benutzer ausgeloggt", user_id=caller.get("sub"))

    response = JSONResponse(content={"status": "logged_out"})
    clear_auth_cookies(response)
    return response


@router.get("/me")
async def get_current_user(request: Request) -> dict:
    """Gibt die Daten des aktuell eingeloggten Benutzers zurück."""
    caller = _extract_user_from_request(request)

    db = await _get_db()
    repo = UserRepository(db)
    user = await repo.get_by_id(caller["sub"])
    if not user:
        raise HTTPException(404, "Benutzer nicht gefunden")

    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "role": user["role"],
        "is_active": user["is_active"],
        "mfa_enabled": user["mfa_enabled"],
        "last_login_at": user["last_login_at"],
        "created_at": user["created_at"],
    }

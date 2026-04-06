"""
Authentifizierungs-Routen für die SentinelClaw REST-API.

Endpoints unter /api/v1/auth:
  - POST /auth/login            -> Benutzer-Login (öffentlich, MFA-fähig)
  - POST /auth/register         -> Benutzer anlegen (nur system_admin)
  - GET  /auth/me               -> Aktuellen Benutzer abrufen
  - GET  /auth/users            -> Alle Benutzer auflisten (org_admin+)
  - DELETE /auth/users/{id}     -> Benutzer löschen (nur system_admin)
  - PUT  /auth/users/{id}/role  -> Rolle ändern (org_admin+)

MFA-Endpoints befinden sich in mfa_routes.py.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.shared.auth import (
    ROLES,
    UserRepository,
    create_access_token,
    create_mfa_session_token,
    extract_user_from_request,
    role_has_permission,
    verify_password,
)
from src.shared.logging_setup import get_logger

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


class ChangeRoleRequest(BaseModel):
    """Anfrage zum Ändern der Benutzer-Rolle."""
    role: str


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


# ─── Endpoints ────────────────────────────────────────────────────


@router.post("/login")
async def login(request: Request, body: LoginRequest) -> dict:
    """Authentifiziert einen Benutzer und gibt einen JWT-Token zurück.

    Bei aktiviertem MFA wird stattdessen ein temporärer MFA-Session-Token
    zurückgegeben, mit dem der zweite Faktor verifiziert werden muss.
    Rate-Limited: Max. N fehlgeschlagene Versuche pro IP in 5 Minuten.
    """
    from src.api.server import get_rate_limiter

    # Client-IP für Rate-Limiting extrahieren
    client_ip = request.client.host if request.client else "unknown"
    limiter = get_rate_limiter()

    if limiter.is_blocked(client_ip):
        logger.warning("Login-Rate-Limit erreicht", ip=client_ip)
        raise HTTPException(
            429,
            "Zu viele fehlgeschlagene Login-Versuche. Bitte warte 5 Minuten.",
        )

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

    # Kein MFA — direkt vollwertigen Token ausgeben
    await repo.update_last_login(user["id"])
    token = create_access_token(user["id"], user["email"], user["role"])
    logger.info("Benutzer eingeloggt", email=user["email"], role=user["role"])

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "mfa_required": False,
        "mfa_session": "",
    }


@router.post("/register")
async def register(body: RegisterRequest, request: Request) -> dict:
    """Registriert einen neuen Benutzer (nur für system_admin)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "system_admin")

    db = await _get_db()
    repo = UserRepository(db)

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


@router.get("/users")
async def list_users(request: Request) -> list[dict]:
    """Listet alle Benutzer auf (nur für org_admin oder höher)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "org_admin")

    db = await _get_db()
    repo = UserRepository(db)
    return await repo.list_all()


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request) -> dict:
    """Löscht einen Benutzer (nur für system_admin)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "system_admin")

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(user_id)
    if not user:
        raise HTTPException(404, f"Benutzer '{user_id}' nicht gefunden")

    # Selbstlöschung verhindern
    if caller["sub"] == user_id:
        raise HTTPException(400, "Eigenes Konto kann nicht gelöscht werden")

    await repo.delete(user_id)
    return {"status": "deleted", "user_id": user_id}


@router.put("/users/{user_id}/role")
async def change_role(user_id: str, body: ChangeRoleRequest, request: Request) -> dict:
    """Ändert die Rolle eines Benutzers (nur für org_admin oder höher)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "org_admin")

    if body.role not in ROLES:
        raise HTTPException(
            400,
            f"Ungültige Rolle '{body.role}' — erlaubt: {list(ROLES.keys())}",
        )

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(user_id)
    if not user:
        raise HTTPException(404, f"Benutzer '{user_id}' nicht gefunden")

    # Nur höhere Rollen dürfen niedrigere Rollen vergeben
    if not role_has_permission(caller["role"], body.role):
        raise HTTPException(403, "Kann keine Rolle vergeben die höher ist als die eigene")

    await repo.update_role(user_id, body.role)
    logger.info(
        "Benutzer-Rolle geändert",
        user_id=user_id,
        old_role=user["role"],
        new_role=body.role,
        changed_by=caller["sub"],
    )
    return {"status": "updated", "user_id": user_id, "role": body.role}

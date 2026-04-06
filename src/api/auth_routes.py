"""
Authentifizierungs-Routen fuer die SentinelClaw REST-API.

Endpoints unter /api/v1/auth:
  - POST /auth/login       -> Benutzer-Login (oeffentlich)
  - POST /auth/register    -> Benutzer anlegen (nur system_admin)
  - GET  /auth/me           -> Aktuellen Benutzer abrufen
  - GET  /auth/users        -> Alle Benutzer auflisten (org_admin+)
  - DELETE /auth/users/{id} -> Benutzer loeschen (nur system_admin)
  - PUT  /auth/users/{id}/role -> Rolle aendern (org_admin+)
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.shared.auth import (
    ROLES,
    UserRepository,
    create_access_token,
    decode_token,
    extract_user_from_request,
    require_role,
    role_has_permission,
    verify_password,
)
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


# ─── Request/Response Modelle ─────────────────────────────────────


class LoginRequest(BaseModel):
    """Anmeldedaten fuer den Login."""
    email: str
    password: str


class LoginResponse(BaseModel):
    """Antwort nach erfolgreichem Login."""
    token: str
    user: dict


class RegisterRequest(BaseModel):
    """Daten fuer die Benutzer-Registrierung."""
    email: str
    display_name: str
    password: str


class ChangeRoleRequest(BaseModel):
    """Anfrage zum Aendern der Benutzer-Rolle."""
    role: str


# ─── Hilfsfunktionen ─────────────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkulaere Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


def _extract_user_from_request(request: Request) -> dict:
    """Wrapper fuer shared Helper — Abwaertskompatibilitaet."""
    return extract_user_from_request(request)


def _require_role(user: dict, required_role: str) -> None:
    """Prueft ob der Benutzer die erforderliche Rolle hat."""
    if not role_has_permission(user.get("role", ""), required_role):
        raise HTTPException(
            403,
            f"Unzureichende Berechtigung — Rolle '{required_role}' oder hoeher erforderlich",
        )


# ─── Endpoints ────────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, body: LoginRequest) -> LoginResponse:
    """Authentifiziert einen Benutzer und gibt einen JWT-Token zurueck.

    Rate-Limited: Max. N fehlgeschlagene Versuche pro IP in 5 Minuten.
    """
    from src.api.server import get_rate_limiter

    # Client-IP fuer Rate-Limiting extrahieren
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
        raise HTTPException(401, "Ungueltige Anmeldedaten")

    if not user.get("is_active"):
        raise HTTPException(403, "Benutzerkonto ist deaktiviert")

    if not verify_password(body.password, user["password_hash"]):
        limiter.record_failure(client_ip)
        raise HTTPException(401, "Ungueltige Anmeldedaten")

    # Erfolgreicher Login — Rate-Limit-Zaehler zuruecksetzen
    limiter.reset(client_ip)

    # Letzten Login aktualisieren
    await repo.update_last_login(user["id"])

    token = create_access_token(user["id"], user["email"], user["role"])
    logger.info("Benutzer eingeloggt", email=user["email"], role=user["role"])

    return LoginResponse(
        token=token,
        user={
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    )


@router.post("/register")
async def register(body: RegisterRequest, request: Request) -> dict:
    """Registriert einen neuen Benutzer (nur fuer system_admin)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "system_admin")

    db = await _get_db()
    repo = UserRepository(db)

    # Pruefen ob E-Mail bereits vergeben ist
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
    """Gibt die Daten des aktuell eingeloggten Benutzers zurueck."""
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
    """Listet alle Benutzer auf (nur fuer org_admin oder hoeher)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "org_admin")

    db = await _get_db()
    repo = UserRepository(db)
    return await repo.list_all()


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request) -> dict:
    """Loescht einen Benutzer (nur fuer system_admin)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "system_admin")

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(user_id)
    if not user:
        raise HTTPException(404, f"Benutzer '{user_id}' nicht gefunden")

    # Selbstloeschung verhindern
    if caller["sub"] == user_id:
        raise HTTPException(400, "Eigenes Konto kann nicht geloescht werden")

    await repo.delete(user_id)
    return {"status": "deleted", "user_id": user_id}


@router.put("/users/{user_id}/role")
async def change_role(user_id: str, body: ChangeRoleRequest, request: Request) -> dict:
    """Aendert die Rolle eines Benutzers (nur fuer org_admin oder hoeher)."""
    caller = _extract_user_from_request(request)
    _require_role(caller, "org_admin")

    if body.role not in ROLES:
        raise HTTPException(
            400,
            f"Ungueltige Rolle '{body.role}' — erlaubt: {list(ROLES.keys())}",
        )

    db = await _get_db()
    repo = UserRepository(db)

    user = await repo.get_by_id(user_id)
    if not user:
        raise HTTPException(404, f"Benutzer '{user_id}' nicht gefunden")

    # Nur hoehere Rollen duerfen niedrigere Rollen vergeben
    if not role_has_permission(caller["role"], body.role):
        raise HTTPException(403, "Kann keine Rolle vergeben die hoeher ist als die eigene")

    await repo.update_role(user_id, body.role)
    logger.info(
        "Benutzer-Rolle geaendert",
        user_id=user_id,
        old_role=user["role"],
        new_role=body.role,
        changed_by=caller["sub"],
    )
    return {"status": "updated", "user_id": user_id, "role": body.role}

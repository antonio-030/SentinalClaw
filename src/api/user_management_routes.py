"""
Benutzerverwaltungs-Routen für die SentinelClaw REST-API.

Endpoints unter /api/v1/auth:
  - GET    /auth/users            -> Alle Benutzer auflisten (org_admin+)
  - DELETE /auth/users/{id}       -> Benutzer löschen (nur system_admin)
  - PUT    /auth/users/{id}/role  -> Rolle ändern (org_admin+)

Ausgelagert aus auth_routes.py um die 300-Zeilen-Grenze einzuhalten.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.shared.auth import (
    ROLES,
    UserRepository,
    extract_user_from_request,
    role_has_permission,
)
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["User Management"])


# ─── Request-Modelle ─────────────────────────────────────────────


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

    # Caller darf keine Benutzer mit gleicher oder höherer Rolle modifizieren
    if ROLES.get(user["role"], 0) >= ROLES.get(caller.get("role", ""), 0):
        raise HTTPException(
            403,
            "Kann keine Benutzer mit gleicher oder höherer Rolle modifizieren",
        )

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

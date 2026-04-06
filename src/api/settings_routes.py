"""
REST-Routen für Systemeinstellungen und Scan-Profile.

Einstellungen sind über die UI änderbar (security_lead+).
Jede Änderung wird im Audit-Log protokolliert.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger
from src.shared.settings_service import invalidate_cache
from src.shared.types.models import AuditLogEntry

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Settings"])


# ─── Request/Response Modelle ────────────────────────────────────────


class SettingOut(BaseModel):
    """Eine einzelne Einstellung."""

    key: str
    value: str
    category: str
    value_type: str
    label: str
    description: str
    updated_by: str
    updated_at: str


class SettingsUpdateRequest(BaseModel):
    """Batch-Update für Einstellungen."""

    settings: dict[str, str] = Field(description="Key-Value-Paare")


class ProfileCreateRequest(BaseModel):
    """Neues Scan-Profil erstellen."""

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="")
    ports: str = Field(min_length=1)
    max_escalation_level: int = Field(default=2, ge=0, le=4)
    skip_host_discovery: bool = False
    skip_vuln_scan: bool = False
    nmap_extra_flags: list[str] = Field(default_factory=list)
    estimated_duration_minutes: int = Field(default=5, ge=1, le=120)


# ─── DB-Zugriff ─────────────────────────────────────────────────────


async def _get_db():
    from src.api.server import get_db
    return await get_db()


# ─── Settings Endpoints ──────────────────────────────────────────────


@router.get("/settings", response_model=list[SettingOut])
async def list_settings(request: Request):
    """Alle Systemeinstellungen laden (analyst+)."""
    require_role(request, "analyst")
    from src.shared.settings_repository import SettingsRepository

    db = await _get_db()
    repo = SettingsRepository(db)
    return await repo.get_all()


@router.get("/settings/{category}", response_model=list[SettingOut])
async def list_settings_by_category(category: str, request: Request):
    """Einstellungen einer Kategorie laden."""
    require_role(request, "analyst")
    from src.shared.settings_repository import SettingsRepository

    valid_categories = {"tool_timeouts", "agent", "sandbox", "scan", "llm"}
    if category not in valid_categories:
        raise HTTPException(400, f"Ungültige Kategorie: {category}")

    db = await _get_db()
    repo = SettingsRepository(db)
    return await repo.get_by_category(category)


@router.put("/settings")
async def update_settings(body: SettingsUpdateRequest, request: Request):
    """Einstellungen aktualisieren (security_lead+). Wird im Audit-Log protokolliert."""
    user = require_role(request, "security_lead")
    from src.shared.repositories import AuditLogRepository
    from src.shared.settings_repository import SettingsRepository

    db = await _get_db()
    repo = SettingsRepository(db)
    changed = await repo.batch_update(body.settings, user["email"])

    # Cache invalidieren damit neue Werte sofort gelten
    invalidate_cache()

    # Audit-Log schreiben
    audit_repo = AuditLogRepository(db)
    await audit_repo.create(AuditLogEntry(
        action="settings.updated",
        resource_type="system_settings",
        details={"changed_keys": list(body.settings.keys()), "count": changed},
        triggered_by=user["email"],
    ))

    logger.info("Einstellungen aktualisiert", user=user["email"], count=changed)
    return {"updated": changed}


# ─── Profile Endpoints ───────────────────────────────────────────────


@router.get("/profiles")
async def list_profiles(request: Request):
    """Alle Scan-Profile laden (builtin + custom)."""
    require_role(request, "analyst")
    from src.shared.profile_repository import ProfileRepository

    db = await _get_db()
    repo = ProfileRepository(db)
    return await repo.list_all()


@router.post("/profiles", status_code=201)
async def create_profile(body: ProfileCreateRequest, request: Request):
    """Neues benutzerdefiniertes Scan-Profil erstellen (security_lead+)."""
    user = require_role(request, "security_lead")
    from src.shared.profile_repository import ProfileRepository
    from src.shared.repositories import AuditLogRepository

    db = await _get_db()
    repo = ProfileRepository(db)

    try:
        profile = await repo.create(body.model_dump(), user["email"])
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(409, f"Profil '{body.name}' existiert bereits") from exc
        raise

    # Audit-Log
    audit_repo = AuditLogRepository(db)
    await audit_repo.create(AuditLogEntry(
        action="profile.created",
        resource_type="scan_profile",
        resource_id=profile["id"],
        details={"name": body.name},
        triggered_by=user["email"],
    ))

    return profile


@router.put("/profiles/{profile_id}")
async def update_profile(profile_id: str, body: ProfileCreateRequest, request: Request):
    """Scan-Profil aktualisieren (security_lead+)."""
    user = require_role(request, "security_lead")
    from src.shared.profile_repository import ProfileRepository
    from src.shared.repositories import AuditLogRepository

    db = await _get_db()
    repo = ProfileRepository(db)

    existing = await repo.get(profile_id)
    if not existing:
        raise HTTPException(404, "Profil nicht gefunden")

    profile = await repo.update(profile_id, body.model_dump(), user["email"])

    audit_repo = AuditLogRepository(db)
    await audit_repo.create(AuditLogEntry(
        action="profile.updated",
        resource_type="scan_profile",
        resource_id=profile_id,
        details={"name": body.name},
        triggered_by=user["email"],
    ))

    return profile


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_profile(profile_id: str, request: Request):
    """Benutzerdefiniertes Profil löschen (security_lead+). Builtin-Profile sind geschützt."""
    user = require_role(request, "security_lead")
    from src.shared.profile_repository import ProfileRepository
    from src.shared.repositories import AuditLogRepository

    db = await _get_db()
    repo = ProfileRepository(db)

    existing = await repo.get(profile_id)
    if not existing:
        raise HTTPException(404, "Profil nicht gefunden")
    if existing.get("is_builtin"):
        raise HTTPException(403, "Vordefinierte Profile können nicht gelöscht werden")

    await repo.delete(profile_id)

    audit_repo = AuditLogRepository(db)
    await audit_repo.create(AuditLogEntry(
        action="profile.deleted",
        resource_type="scan_profile",
        resource_id=profile_id,
        details={"name": existing["name"]},
        triggered_by=user["email"],
    ))

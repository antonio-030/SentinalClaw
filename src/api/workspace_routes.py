"""
REST-Routen für NemoClaw Workspace-Konfiguration.

Verwaltet die Agent-Workspace-Dateien (SOUL.md, IDENTITY.md, USER.md,
AGENTS.md, MEMORY.md) die in der OpenClaw-Sandbox gemountet werden.

Lesen: analyst+ | Schreiben: security_lead+
"""

import re
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/workspace", tags=["Workspace"])

# Erlaubte Workspace-Dateien — nur diese dürfen geschrieben werden
_ALLOWED_FILES: set[str] = {"SOUL.md", "IDENTITY.md", "USER.md", "AGENTS.md", "MEMORY.md"}

# Workspace-Verzeichnis relativ zum Projektroot
_WORKSPACE_DIR = Path(__file__).resolve().parent.parent.parent / "workspace"


def _validate_filename(filename: str) -> Path:
    """Validiert den Dateinamen gegen Path-Traversal und gibt den Pfad zurück."""
    # Nur .md Dateien erlaubt
    if not filename.endswith(".md"):
        raise HTTPException(400, "Nur Markdown-Dateien (.md) sind erlaubt")

    # Path-Traversal verhindern: kein /, \, .., ~ etc.
    if re.search(r"[/\\~]|\.\.", filename):
        raise HTTPException(400, "Ungültiger Dateiname")

    filepath = _WORKSPACE_DIR / filename
    # Sicherstellen dass der aufgelöste Pfad im Workspace-Verzeichnis liegt
    try:
        filepath.resolve().relative_to(_WORKSPACE_DIR.resolve())
    except ValueError:
        raise HTTPException(400, "Zugriff außerhalb des Workspace-Verzeichnisses")

    return filepath


# ─── Request/Response Modelle ────────────────────────────────────────


class WorkspaceFileOut(BaseModel):
    """Antwort für eine einzelne Workspace-Datei."""

    name: str
    content: str
    size: int
    modified_at: str


class WorkspaceFileUpdate(BaseModel):
    """Anfrage zum Aktualisieren einer Workspace-Datei."""

    content: str = Field(min_length=1, max_length=50_000)


class WorkspaceFileUpdated(BaseModel):
    """Antwort nach erfolgreichem Update."""

    name: str
    content: str
    updated_at: str


# ─── Endpoints ────────────────────────────────────────────────────────


@router.get("")
async def list_workspace_files(request: Request) -> list[WorkspaceFileOut]:
    """Listet alle Workspace-Dateien (analyst+)."""
    require_role(request, "analyst")

    if not _WORKSPACE_DIR.is_dir():
        logger.warning("Workspace-Verzeichnis nicht gefunden", path=str(_WORKSPACE_DIR))
        return []

    files: list[WorkspaceFileOut] = []
    for filepath in sorted(_WORKSPACE_DIR.glob("*.md")):
        if not filepath.is_file():
            continue
        content = filepath.read_text(encoding="utf-8")
        stat = filepath.stat()
        files.append(WorkspaceFileOut(
            name=filepath.name,
            content=content,
            size=stat.st_size,
            modified_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
        ))

    return files


@router.get("/{filename}")
async def get_workspace_file(filename: str, request: Request) -> WorkspaceFileOut:
    """Gibt den Inhalt einer Workspace-Datei zurück (analyst+)."""
    require_role(request, "analyst")

    filepath = _validate_filename(filename)
    if not filepath.is_file():
        raise HTTPException(404, f"Datei '{filename}' nicht gefunden")

    content = filepath.read_text(encoding="utf-8")
    stat = filepath.stat()

    return WorkspaceFileOut(
        name=filepath.name,
        content=content,
        size=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
    )


@router.put("/{filename}")
async def update_workspace_file(
    filename: str,
    request: Request,
    body: WorkspaceFileUpdate,
) -> WorkspaceFileUpdated:
    """Aktualisiert eine Workspace-Datei (security_lead+)."""
    caller = require_role(request, "security_lead")

    # Nur vordefinierte Dateien dürfen geschrieben werden
    if filename not in _ALLOWED_FILES:
        raise HTTPException(
            400,
            f"Datei '{filename}' ist nicht bearbeitbar. "
            f"Erlaubt: {', '.join(sorted(_ALLOWED_FILES))}",
        )

    filepath = _validate_filename(filename)

    # Workspace-Verzeichnis erstellen falls nötig
    filepath.parent.mkdir(parents=True, exist_ok=True)

    filepath.write_text(body.content, encoding="utf-8")

    logger.info(
        "Workspace-Datei aktualisiert",
        file=filename,
        by=caller.get("email", "unbekannt"),
        size=len(body.content),
    )

    # Audit-Log schreiben
    try:
        from src.api.server import get_db
        from src.shared.repositories import AuditLogRepository
        from src.shared.types.models import AuditLogEntry

        db = await get_db()
        audit_repo = AuditLogRepository(db)
        await audit_repo.create(AuditLogEntry(
            action="workspace.update",
            resource_type="workspace_file",
            resource_id=filename,
            details={"size": len(body.content)},
            triggered_by=caller.get("email", "api_user"),
        ))
    except Exception as audit_error:
        logger.warning("Audit-Log Fehler", error=str(audit_error))

    return WorkspaceFileUpdated(
        name=filename,
        content=body.content,
        updated_at=datetime.now(UTC).isoformat(),
    )

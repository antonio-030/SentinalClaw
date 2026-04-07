"""
Scan-Validierung und Ausfuehrungslogik fuer die SentinelClaw REST-API.

Enthaelt extrahierte Hilfsfunktionen aus scan_routes.py:
  - Eingabevalidierung (Target, UUID)
  - Sicherheitsschicht-Pruefung
  - Profil-Aufloesung
  - Scan-Job-Erstellung mit Audit-Log
  - Background-Scan-Ausfuehrung
"""

from uuid import UUID

from fastapi import HTTPException

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


# ─── Validierung ─────────────────────────────────────────────────


def validate_scan_target(raw_target: str) -> str:
    """Validiert und bereinigt das Scan-Ziel.

    Entfernt fuehrende/nachfolgende Leerzeichen und lehnt
    leere Strings ab.
    """
    target = raw_target.strip()
    if not target:
        raise HTTPException(400, "Scan-Ziel darf nicht leer sein")
    return target


def parse_scan_uuid(scan_id: str) -> UUID:
    """Parst einen String als UUID und wirft HTTP 400 bei Fehler."""
    try:
        return UUID(scan_id)
    except ValueError:
        raise HTTPException(400, f"Ungueltige Scan-ID: {scan_id}")


async def check_security_layers() -> None:
    """Prueft ob alle Sicherheitsschichten aktiv sind.

    Blockiert den Scan mit HTTP 503 wenn nicht alle Schichten
    bereit sind — kein Scan ohne volle Absicherung.
    """
    from src.shared.security_layer_check import check_all_security_layers

    all_layers_ok, layer_errors = await check_all_security_layers()
    if not all_layers_ok:
        raise HTTPException(
            503,
            "Scan blockiert — nicht alle Sicherheitsschichten aktiv: "
            + "; ".join(layer_errors),
        )


# ─── Profil-Aufloesung ──────────────────────────────────────────


def resolve_scan_profile(
    profile_name: str | None,
    default_ports: str,
    default_escalation: int,
) -> tuple[str, int]:
    """Laedt das Scan-Profil und gibt Ports + Eskalationslevel zurueck.

    Falls kein Profil angegeben ist, werden die Default-Werte
    unveraendert zurueckgegeben.
    """
    if not profile_name:
        return default_ports, default_escalation

    from src.shared.scan_profiles import get_profile

    profile = get_profile(profile_name)
    return profile.ports, profile.max_escalation_level


# ─── Scan-Job-Erstellung ────────────────────────────────────────


async def create_scan_job_with_audit(
    db: object,
    target: str,
    scan_type: str,
    escalation: int,
    ports: str,
    profile_name: str | None,
    caller_email: str,
) -> str:
    """Erstellt den Scan-Job in der DB und schreibt einen Audit-Log-Eintrag.

    Gibt die Scan-ID als String zurueck.
    """
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanJob

    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Scan-Job in der Datenbank anlegen
    job = ScanJob(
        target=target,
        scan_type=scan_type,
        max_escalation_level=escalation,
        config={"ports": ports, "profile": profile_name},
    )
    await scan_repo.create(job)

    # Audit-Log ueber Scan-Erstellung schreiben
    await audit_repo.create(AuditLogEntry(
        action="scan.created",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"target": target, "ports": ports},
        triggered_by=caller_email,
    ))

    return str(job.id)


# ─── Background-Scan-Ausfuehrung ────────────────────────────────


async def run_scan_background(
    scan_id: str, target: str, ports: str, escalation: int
) -> None:
    """Fuehrt den Scan im Hintergrund aus.

    Nutzt die gemeinsame DB-Connection der API (WAL-Modus
    erlaubt parallele Reads). Bei Fehler wird der Scan-Status
    auf FAILED gesetzt.
    """
    from uuid import UUID as _UUID

    from src.orchestrator.agent import OrchestratorAgent
    from src.shared.repositories import ScanJobRepository
    from src.shared.types.models import ScanStatus
    from src.shared.types.scope import PentestScope

    try:
        # Importiert get_db aus server.py um zirkulaere Imports zu vermeiden
        from src.api.server import get_db

        db = await get_db()
        scan_repo = ScanJobRepository(db)
        await scan_repo.update_status(_UUID(scan_id), ScanStatus.RUNNING)

        scope = PentestScope(
            targets_include=[target],
            max_escalation_level=escalation,
            ports_include=ports,
        )

        # Orchestrator bekommt die gleiche DB-Connection
        orchestrator = OrchestratorAgent(scope=scope, db=db)
        await orchestrator.orchestrate_scan(
            target, ports=ports, existing_scan_id=scan_id
        )

    except Exception as error:
        logger.error(
            "Background-Scan fehlgeschlagen",
            scan_id=scan_id,
            error=str(error),
        )
        try:
            from src.api.server import get_db

            db = await get_db()
            repo = ScanJobRepository(db)
            await repo.update_status(_UUID(scan_id), ScanStatus.FAILED)
        except Exception:
            pass

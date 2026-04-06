"""
Scope-Prüfungen für den Watchdog-Service.

Prüft ob laufende Scans noch innerhalb des definierten Scopes
operieren (Zeitfenster, Target-Whitelist). Bei Verletzungen
wird der Kill-Switch aktiviert.
"""

from datetime import UTC, datetime

from src.shared.config import Settings
from src.shared.kill_switch import KillSwitch
from src.shared.logging_setup import get_logger
from src.shared.repositories import ScanJobRepository
from src.shared.types.models import ScanJob, ScanStatus

logger = get_logger(__name__)


async def check_scope_violations(
    scan_repo: ScanJobRepository,
    settings: Settings,
) -> None:
    """Prüft ob laufende Scans noch im Scope sind.

    Kontrolliert Zeitfenster und Target-Whitelist. Löst den
    Kill-Switch aus wenn ein Scan außerhalb des Scopes arbeitet.
    """
    running_scans: list[ScanJob] = await scan_repo.list_by_status(
        ScanStatus.RUNNING
    )
    if not running_scans:
        return

    now = datetime.now(UTC)
    allowed_targets = settings.get_allowed_targets_list()

    for scan in running_scans:
        if _is_time_expired(scan, now):
            _kill_scan(scan_repo, scan, "Zeitfenster abgelaufen")
            await scan_repo.update_status(scan.id, ScanStatus.EMERGENCY_KILLED)
            return

        if _is_target_outside_whitelist(scan, allowed_targets):
            _kill_scan(
                scan_repo, scan,
                f"Ziel '{scan.target}' nicht in der Whitelist",
            )
            await scan_repo.update_status(scan.id, ScanStatus.EMERGENCY_KILLED)
            return


def _is_time_expired(scan: ScanJob, now: datetime) -> bool:
    """Prüft ob das Zeitfenster eines Scans abgelaufen ist."""
    window_end_str = scan.config.get("time_window_end")
    if not window_end_str:
        return False
    try:
        window_end = datetime.fromisoformat(window_end_str)
        if now > window_end:
            logger.warning(
                "watchdog_scope_time_expired",
                scan_id=str(scan.id),
                window_end=window_end_str,
            )
            return True
    except ValueError:
        pass
    return False


def _is_target_outside_whitelist(
    scan: ScanJob, allowed_targets: list[str]
) -> bool:
    """Prüft ob das Scan-Ziel außerhalb der Whitelist liegt."""
    if not allowed_targets:
        return False
    if scan.target not in allowed_targets:
        logger.warning(
            "watchdog_scope_target_violation",
            scan_id=str(scan.id),
            target=scan.target,
        )
        return True
    return False


def _kill_scan(
    scan_repo: ScanJobRepository,
    scan: ScanJob,
    reason: str,
) -> None:
    """Aktiviert den Kill-Switch wegen Scope-Verletzung."""
    full_reason = f"Scan {scan.id}: {reason}"
    logger.critical("watchdog_scope_kill", reason=full_reason)
    KillSwitch().activate("watchdog", full_reason)

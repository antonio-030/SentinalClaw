"""
Admin-Kommandos für die SentinelClaw CLI.

Enthält cmd_status(), cmd_history(), cmd_kill() und cmd_profiles() —
Kommandos für System-Verwaltung und Übersicht.
"""

import argparse

from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, ScanJobRepository
from src.shared.types.models import AuditLogEntry, ScanStatus

logger = get_logger(__name__)


def cmd_profiles() -> None:
    """Zeigt alle verfügbaren Scan-Profile an."""
    from src.shared.scan_profiles import list_profiles

    print()
    print("  SentinelClaw \u2014 Scan-Profile")
    print("  " + "=" * 55)
    print()
    for profile in list_profiles():
        print(f"  {profile.name}")
        print(f"    {profile.description}")
        print(f"    Ports: {profile.ports}")
        print(f"    Stufe: {profile.max_escalation_level} | ~{profile.estimated_duration_minutes} Min")
        print()
    print("  Nutzung: sentinelclaw orchestrate --target <ziel> --profile <name>")
    print()


async def cmd_status() -> None:
    """Zeigt System-Status und laufende Scans."""
    settings = get_settings()
    print()
    print("  SentinelClaw \u2014 System-Status")
    print("  " + "=" * 40)
    print()

    # LLM-Provider
    print(f"  LLM-Provider:    {settings.llm_provider}")

    # Claude CLI prüfen
    import shutil
    claude_path = shutil.which("claude")
    print(f"  Claude CLI:      {'\u2705 ' + claude_path if claude_path else '\u274c Nicht gefunden'}")

    # Docker prüfen
    try:
        import docker
        client = docker.from_env()
        version = client.version().get("Version", "?")
        print(f"  Docker:          \u2705 {version}")

        try:
            sandbox = client.containers.get("sentinelclaw-sandbox")
            print(f"  Sandbox:         \u2705 {sandbox.status}")
        except docker.errors.NotFound:
            print("  Sandbox:         \u274c Container nicht gestartet")
    except Exception:
        print("  Docker:          \u274c Nicht erreichbar")

    # OpenClaw prüfen
    try:
        from openclaw import OpenClaw  # noqa: F401
        print("  OpenClaw/NemoClaw: \u2705 SDK verf\u00fcgbar")
    except Exception:
        print("  OpenClaw/NemoClaw: \u26a0 SDK nicht importierbar")

    # DB prüfen
    db = DatabaseManager(settings.db_path)
    try:
        await db.initialize()
        scan_repo = ScanJobRepository(db)
        running = await scan_repo.list_by_status(ScanStatus.RUNNING)
        all_scans = await scan_repo.list_all(5)

        print(f"  Datenbank:       \u2705 {settings.db_path}")
        print(f"  Laufende Scans:  {len(running)}")
        print(f"  Gesamt-Scans:    {len(all_scans)}")

        if running:
            print()
            print("  --- Laufende Scans ---")
            for job in running:
                print(f"    {job.id} \u2192 {job.target} ({job.scan_type}, seit {job.started_at})")

        await db.close()
    except Exception as error:
        print(f"  Datenbank:       \u274c {error}")

    print()


async def cmd_history(args: argparse.Namespace) -> None:
    """Zeigt vergangene Scans."""
    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    await db.initialize()
    scan_repo = ScanJobRepository(db)

    scans = await scan_repo.list_all(args.limit)

    print()
    print("  SentinelClaw \u2014 Scan-Historie")
    print("  " + "=" * 55)
    print()

    if not scans:
        print("  Noch keine Scans durchgef\u00fchrt.")
    else:
        status_icons = {
            "completed": "\u2705",
            "failed": "\u274c",
            "running": "\U0001f535",
            "pending": "\u23f3",
            "cancelled": "\u26aa",
            "emergency_killed": "\U0001f534",
        }
        print(f"  {'Status':<4} {'ID':<10} {'Ziel':<25} {'Typ':<8} {'Tokens':>8} {'Datum'}")
        print(f"  {'\u2500' * 70}")
        for job in scans:
            icon = status_icons.get(job.status.value, "?")
            scan_id = str(job.id)[:8]
            date = job.created_at.strftime("%d.%m.%Y %H:%M")
            print(
                f"  {icon}    {scan_id:<10} {job.target:<25} "
                f"{job.scan_type:<8} {job.tokens_used:>8} {date}"
            )

    await db.close()
    print()


async def cmd_kill() -> None:
    """Aktiviert den Kill-Switch — stoppt ALLE laufenden Scans."""
    from src.shared.kill_switch import KillSwitch

    print()
    print("  \U0001f534 SentinelClaw \u2014 NOTAUS")
    print("  " + "=" * 40)
    print()

    confirm = input("  Wirklich ALLE Scans sofort stoppen? [j/N]: ").strip().lower()
    if confirm not in ("j", "ja", "y", "yes"):
        print("  Abgebrochen.")
        return

    ks = KillSwitch()
    ks.activate(triggered_by="cli_user", reason="Manueller Kill \u00fcber CLI")

    print()
    print("  \u2705 Kill-Switch aktiviert")
    print("  \u2705 Sandbox-Container wird gestoppt")
    print("  \u2705 Alle laufenden Scans abgebrochen")
    print()

    # Laufende Scans in DB auf KILLED setzen
    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    try:
        await db.initialize()
        scan_repo = ScanJobRepository(db)
        running = await scan_repo.list_by_status(ScanStatus.RUNNING)
        for job in running:
            await scan_repo.update_status(job.id, ScanStatus.EMERGENCY_KILLED)
            print(f"  Scan {str(job.id)[:8]} \u2192 EMERGENCY_KILLED")

        # Audit-Log
        audit_repo = AuditLogRepository(db)
        await audit_repo.create(AuditLogEntry(
            action="kill.activated",
            resource_type="system",
            details={"scans_killed": len(running)},
            triggered_by="cli_user",
        ))
        await db.close()
    except Exception:
        pass

    print()

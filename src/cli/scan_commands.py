"""
Scan-Kommandos für die SentinelClaw CLI.

Enthält cmd_scan() und cmd_orchestrate() — die beiden Kommandos
die tatsächlich einen Scan starten und den Agent ausführen.
"""

import argparse
import time

from src.cli.output import print_result
from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, ScanJobRepository
from src.shared.types.models import AuditLogEntry, ScanJob, ScanStatus
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


async def cmd_scan(args: argparse.Namespace) -> None:
    """Führt einen Recon-Scan auf dem Ziel durch."""
    settings = get_settings()
    target = args.target

    # Scope aus Konfiguration + CLI-Target bauen
    allowed = settings.get_allowed_targets_list()
    if target not in allowed and not any(target in a for a in allowed):
        # Target automatisch zur erlaubten Liste hinzufügen (PoC)
        allowed.append(target)

    scope = PentestScope(
        targets_include=allowed,
        max_escalation_level=min(args.level, 2),
        ports_include=args.ports,
    )

    # Disclaimer anzeigen
    print()
    print("=" * 60)
    print("  \u26a0  RECHTLICHER HINWEIS")
    print("=" * 60)
    print()
    print("  Dieses Tool darf ausschlie\u00dflich f\u00fcr autorisierte")
    print("  Sicherheits\u00fcberpr\u00fcfungen eingesetzt werden.")
    print("  (StGB \u00a7202a-c)")
    print()

    if not args.yes:
        confirm = input("  Autorisierung best\u00e4tigen? [j/N]: ").strip().lower()
        if confirm not in ("j", "ja", "y", "yes"):
            print("  Abgebrochen.")
            return

    print()
    print(f"  Ziel:  {target}")
    print(f"  Ports: {args.ports}")
    print(f"  Stufe: {args.level}")
    print()

    # DB initialisieren
    db = DatabaseManager(settings.db_path)
    await db.initialize()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Scan-Job erstellen
    job = ScanJob(
        target=target,
        scan_type="recon",
        max_escalation_level=args.level,
        token_budget=settings.llm_max_tokens_per_scan,
        config={"ports": args.ports},
    )
    await scan_repo.create(job)
    await scan_repo.update_status(job.id, ScanStatus.RUNNING)

    # Audit-Log
    await audit_repo.create(AuditLogEntry(
        action="scan.started",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"target": target, "level": args.level},
        triggered_by="cli_user",
    ))

    print(f"  Scan-ID: {job.id}")
    print("  Status:  RUNNING")
    print()

    # NemoClaw-Runtime und Recon-Agent erstellen
    from src.agents.nemoclaw_runtime import NemoClawRuntime
    from src.agents.recon.agent import ReconAgent

    runtime = NemoClawRuntime()
    agent = ReconAgent(runtime=runtime, scope=scope)

    print("  Agent arbeitet...")
    print()

    start_time = time.monotonic()

    try:
        result = await agent.run_reconnaissance(target, ports=args.ports)

        duration = time.monotonic() - start_time
        await scan_repo.update_status(
            job.id, ScanStatus.COMPLETED, tokens_used=result.total_tokens_used
        )

        # Ergebnis ausgeben
        print_result(result, args.output)

        # Audit-Log
        await audit_repo.create(AuditLogEntry(
            action="scan.completed",
            resource_type="scan_job",
            resource_id=str(job.id),
            details={
                "hosts": result.total_hosts,
                "ports": result.total_open_ports,
                "vulns": result.total_vulnerabilities,
                "duration_s": round(duration, 1),
                "tokens": result.total_tokens_used,
            },
            triggered_by="cli_user",
        ))

    except Exception as error:
        await scan_repo.update_status(job.id, ScanStatus.FAILED)
        logger.error("Scan fehlgeschlagen", error=str(error), scan_id=str(job.id))
        print(f"\n  \u274c Scan fehlgeschlagen: {error}")

    finally:
        await db.close()


async def cmd_orchestrate(args: argparse.Namespace) -> None:
    """Führt einen orchestrierten Scan durch (FA-01)."""
    settings = get_settings()
    target = args.target

    # Profil laden (überschreibt Ports und Eskalationsstufe)
    ports = args.ports
    escalation = 2
    profile_name = ""

    if hasattr(args, "profile") and args.profile:
        from src.shared.scan_profiles import get_profile
        profile = get_profile(args.profile)
        ports = profile.ports
        escalation = profile.max_escalation_level
        profile_name = profile.name

    # Scope bauen
    allowed = settings.get_allowed_targets_list()
    if target not in allowed:
        allowed.append(target)

    scope = PentestScope(
        targets_include=allowed,
        max_escalation_level=escalation,
        ports_include=ports,
    )

    # Disclaimer
    print()
    print("=" * 60)
    print("  SentinelClaw \u2014 Orchestrierter Security-Scan")
    print("  Powered by NVIDIA NemoClaw")
    print("=" * 60)
    print()
    print(f"  Ziel:     {target}")
    print(f"  Ports:    {ports}")
    if profile_name:
        print(f"  Profil:   {profile_name}")
    print(f"  Typ:      {args.type}")
    print()
    print("  \u26a0  Dieses Tool darf ausschlie\u00dflich f\u00fcr autorisierte")
    print("     Sicherheits\u00fcberpr\u00fcfungen eingesetzt werden. (StGB \u00a7202a-c)")
    print()

    if not args.yes:
        confirm = input("  Autorisierung best\u00e4tigen? [j/N]: ").strip().lower()
        if confirm not in ("j", "ja", "y", "yes"):
            print("  Abgebrochen.")
            return

    print()
    print("  Orchestrator erstellt Scan-Plan...")
    print()

    from src.orchestrator.agent import OrchestratorAgent

    orchestrator = OrchestratorAgent(scope=scope)

    try:
        result = await orchestrator.orchestrate_scan(
            target=target,
            scan_type=args.type,
            ports=args.ports,
        )

        # Scan-Plan anzeigen
        print("  Scan-Plan:")
        for i, phase in enumerate(result.plan, 1):
            icon = "\u2705" if phase.status == "completed" else "\u274c" if phase.status == "failed" else "\u23f3"
            print(f"    {icon} Phase {i}: {phase.name}")
        print()

        if result.recon_result:
            print_result(result.recon_result, args.output)

        # Executive Summary
        if result.executive_summary:
            print("  --- Executive Summary ---")
            print(f"  {result.executive_summary}")
            print()

        # Empfehlungen
        if result.recommendations:
            print("  --- Empfehlungen ---")
            for rec in result.recommendations:
                print(f"    \u2192 {rec}")
            print()

        print(f"  Dauer:  {result.total_duration_seconds:.1f}s")
        print(f"  Tokens: {result.total_tokens_used}")
        print()

    except Exception as error:
        print(f"\n  \u274c Scan fehlgeschlagen: {error}")

    finally:
        await orchestrator.close()

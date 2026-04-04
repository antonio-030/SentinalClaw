"""
SentinelClaw CLI — Kommandozeilen-Interface für den PoC.

Starten mit: python -m src.cli scan --target <IP/CIDR>
"""

import argparse
import asyncio

from src.shared.config import get_settings
from src.shared.logging_setup import setup_logging


def _build_parser() -> argparse.ArgumentParser:
    """Erstellt den ArgumentParser mit allen Subcommands."""
    parser = argparse.ArgumentParser(
        prog="sentinelclaw",
        description="SentinelClaw \u2014 AI-gest\u00fctzte Security Assessment Platform",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Scan-Command
    scan_parser = subparsers.add_parser("scan", help="Recon-Scan durchf\u00fchren")
    scan_parser.add_argument("--target", "-t", required=True, help="Scan-Ziel (IP, CIDR, Domain)")
    scan_parser.add_argument("--ports", "-p", default="1-1000", help="Port-Range (Default: 1-1000)")
    scan_parser.add_argument(
        "--level", "-l", type=int, default=2, choices=[0, 1, 2],
        help="Eskalationsstufe (0-2)",
    )
    scan_parser.add_argument(
        "--output", "-o", default="markdown", choices=["markdown", "json"],
        help="Ausgabeformat",
    )
    scan_parser.add_argument("--yes", "-y", action="store_true", help="Disclaimer automatisch best\u00e4tigen")

    # Orchestrate-Command (FA-01)
    orch_parser = subparsers.add_parser("orchestrate", help="Orchestrierten Scan durchf\u00fchren")
    orch_parser.add_argument("--target", "-t", required=True, help="Scan-Ziel")
    orch_parser.add_argument("--ports", "-p", default="1-1000", help="Port-Range")
    orch_parser.add_argument(
        "--profile",
        choices=["quick", "standard", "full", "web", "database", "infrastructure", "stealth"],
        help="Scan-Profil (\u00fcberschreibt --ports)",
    )
    orch_parser.add_argument(
        "--type", default="recon", choices=["recon", "vuln", "full"],
        help="Scan-Typ",
    )
    orch_parser.add_argument(
        "--output", "-o", default="markdown", choices=["markdown", "json"],
        help="Ausgabeformat",
    )
    orch_parser.add_argument("--yes", "-y", action="store_true", help="Disclaimer best\u00e4tigen")

    # Profiles-Command
    subparsers.add_parser("profiles", help="Verf\u00fcgbare Scan-Profile anzeigen")

    # Status-Command
    subparsers.add_parser("status", help="System-Status und laufende Scans anzeigen")

    # History-Command
    hist_parser = subparsers.add_parser("history", help="Vergangene Scans anzeigen")
    hist_parser.add_argument("--limit", "-n", type=int, default=10, help="Anzahl Eintr\u00e4ge")

    # Kill-Command
    subparsers.add_parser("kill", help="Alle laufenden Scans sofort stoppen (NOTAUS)")

    # Findings-Command
    find_parser = subparsers.add_parser("findings", help="Findings anzeigen und exportieren")
    find_parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low", "info"],
    )
    find_parser.add_argument("--scan-id", help="Nur Findings eines bestimmten Scans")
    find_parser.add_argument("--host", help="Nur Findings eines bestimmten Hosts")
    find_parser.add_argument(
        "--output", "-o", default="table", choices=["table", "json"],
    )
    find_parser.add_argument("--limit", "-n", type=int, default=50)

    # Compare-Command — Scan-Vergleich
    cmp_parser = subparsers.add_parser("compare", help="Zwei Scans vergleichen (Delta)")
    cmp_parser.add_argument("--scan-a", required=True, help="Scan-ID A (Baseline)")
    cmp_parser.add_argument("--scan-b", required=True, help="Scan-ID B (Neuer Scan)")
    cmp_parser.add_argument(
        "--output", "-o", default="table", choices=["table", "json"],
        help="Ausgabeformat",
    )

    # Report-Command
    report_parser = subparsers.add_parser("report", help="Report generieren")
    report_parser.add_argument("--scan-id", required=True, help="Scan-ID")
    report_parser.add_argument(
        "--type", default="technical",
        choices=["executive", "technical", "compliance"],
    )
    report_parser.add_argument("--output-file", "-f", help="In Datei schreiben")

    # Export-Command — Findings in verschiedenen Formaten exportieren
    export_parser = subparsers.add_parser("export", help="Findings exportieren (CSV, JSONL, SARIF)")
    export_parser.add_argument("--scan-id", required=True, help="Scan-ID fuer den Export")
    export_parser.add_argument(
        "--format",
        required=True,
        choices=["csv", "jsonl", "sarif"],
        help="Exportformat: csv, jsonl oder sarif",
    )
    export_parser.add_argument("--output-file", "-f", help="In Datei schreiben (sonst stdout)")

    return parser


def _dispatch(args: argparse.Namespace) -> None:
    """Verteilt den CLI-Aufruf an die passende Command-Funktion."""
    # Lazy-Imports um zirkuläre Abhängigkeiten und Startzeit zu minimieren
    from src.cli.admin_commands import cmd_history, cmd_kill, cmd_profiles, cmd_status
    from src.cli.data_commands import cmd_compare, cmd_export, cmd_findings, cmd_report
    from src.cli.scan_commands import cmd_orchestrate, cmd_scan

    command = args.command

    if command == "scan":
        asyncio.run(cmd_scan(args))
    elif command == "orchestrate":
        asyncio.run(cmd_orchestrate(args))
    elif command == "status":
        asyncio.run(cmd_status())
    elif command == "history":
        asyncio.run(cmd_history(args))
    elif command == "kill":
        asyncio.run(cmd_kill())
    elif command == "findings":
        asyncio.run(cmd_findings(args))
    elif command == "compare":
        asyncio.run(cmd_compare(args))
    elif command == "report":
        asyncio.run(cmd_report(args))
    elif command == "export":
        asyncio.run(cmd_export(args))
    elif command == "profiles":
        cmd_profiles()


def main() -> None:
    """CLI-Einstiegspunkt."""
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Logging initialisieren
    settings = get_settings()
    setup_logging(settings.log_level)

    _dispatch(args)


if __name__ == "__main__":
    main()

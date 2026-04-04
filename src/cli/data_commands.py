"""
Daten-Kommandos für die SentinelClaw CLI.

Enthält cmd_findings(), cmd_compare(), cmd_report() und cmd_export() —
Kommandos zum Anzeigen, Vergleichen und Exportieren von Scan-Daten.
"""

import argparse
from pathlib import Path
from uuid import UUID

from src.shared.config import get_settings
from src.shared.database import DatabaseManager
from src.shared.exporters import export_findings_csv, export_findings_jsonl, export_findings_sarif
from src.shared.logging_setup import get_logger
from src.shared.repositories import FindingRepository

from src.cli.output import (
    print_compare_json,
    print_compare_table,
    print_findings_json,
    print_findings_table,
)

logger = get_logger(__name__)


async def cmd_findings(args: argparse.Namespace) -> None:
    """Listet Findings aus der Datenbank, sortiert nach Schweregrad."""
    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    await db.initialize()
    finding_repo = FindingRepository(db)

    # Findings laden — je nach Filter-Kombination
    if args.scan_id:
        findings = await finding_repo.list_by_scan(UUID(args.scan_id))
    else:
        findings = await finding_repo.list_all(
            severity=args.severity, limit=args.limit,
        )

    # Nachfilter: Host-Filter wird in-memory angewendet
    if args.host:
        findings = [f for f in findings if f.target_host == args.host]

    # Severity-Filter auch bei scan-id-Abfrage anwenden
    if args.severity and args.scan_id:
        findings = [f for f in findings if f.severity.value == args.severity]

    await db.close()

    if args.output == "json":
        print_findings_json(findings)
    else:
        print_findings_table(findings)


async def cmd_compare(args: argparse.Namespace) -> None:
    """Vergleicht zwei Scans und zeigt das Delta (neue/behobene Findings, Ports)."""
    from src.shared.scan_compare import ScanComparator

    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    await db.initialize()

    scan_id_a = UUID(args.scan_a)
    scan_id_b = UUID(args.scan_b)

    comparator = ScanComparator(db)
    result = await comparator.compare(scan_id_a, scan_id_b)

    await db.close()

    if args.output == "json":
        print_compare_json(result, scan_id_a, scan_id_b)
    else:
        print_compare_table(result)


async def cmd_report(args: argparse.Namespace) -> None:
    """Generiert einen Report für einen bestimmten Scan."""
    from src.shared.report_generator import ReportGenerator

    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    await db.initialize()

    generator = ReportGenerator(db)
    scan_id = UUID(args.scan_id)
    report_type = args.type

    # Report-Typ auswählen und generieren
    if report_type == "executive":
        content = await generator.generate_executive_summary(scan_id)
    elif report_type == "compliance":
        content = await generator.generate_compliance_report(scan_id)
    else:
        content = await generator.generate_technical_report(scan_id)

    await db.close()

    # Ausgabe: in Datei oder auf stdout
    if args.output_file:
        output_path = Path(args.output_file)
        output_path.write_text(content, encoding="utf-8")
        print(f"\n  \u2705 Report geschrieben: {output_path.resolve()}\n")
    else:
        print(content)


async def cmd_export(args: argparse.Namespace) -> None:
    """Exportiert Findings eines Scans in das gewaehlte Format (CSV, JSONL, SARIF)."""
    settings = get_settings()
    db = DatabaseManager(settings.db_path)
    await db.initialize()

    scan_id = UUID(args.scan_id)
    fmt: str = args.format

    # Passendes Exportformat waehlen
    exporters: dict[str, any] = {
        "csv": export_findings_csv,
        "jsonl": export_findings_jsonl,
        "sarif": export_findings_sarif,
    }

    exporter = exporters[fmt]
    content: str = await exporter(db, scan_id)
    await db.close()

    # Ausgabe: in Datei oder auf stdout
    if args.output_file:
        output_path = Path(args.output_file)
        output_path.write_text(content, encoding="utf-8")
        print(f"\n  Exportiert: {output_path.resolve()}  ({fmt.upper()})\n")
    else:
        print(content)

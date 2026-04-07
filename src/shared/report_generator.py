"""
Report-Generator für SentinelClaw.

Erzeugt Markdown-Reports aus Datenbank-Daten: Executive Summary,
technischer Detailbericht und Compliance-Mapping (BSI, ISO 27001).

Die Template-Logik für den technischen und Compliance-Report liegt
in report_templates.py — diese Klasse delegiert dorthin.
"""

from uuid import UUID

from src.shared.constants.severity import SEVERITY_ICONS, SEVERITY_ORDER
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.report_templates import (
    BSI_MAPPING,
    ISO27001_MAPPING,
    assess_risk_level,
    build_compliance_report,
    build_technical_report,
    count_severities,
    footer,
    format_authorization_section,
    generate_recommendations,
)
from src.shared.repositories import AuditLogRepository, FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob

logger = get_logger(__name__)

# Abwärtskompatible Aliase — werden von pdf_section_renderers importiert
_BSI_MAPPING = BSI_MAPPING
_ISO27001_MAPPING = ISO27001_MAPPING

# Lokale Aliase für Severity-Helfer
_SEVERITY_ICONS = SEVERITY_ICONS
_SEVERITY_ORDER = SEVERITY_ORDER


class ReportGenerator:
    """Erzeugt Markdown-Reports aus Scan-Daten in der Datenbank."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db
        self._scan_repo = ScanJobRepository(db)
        self._finding_repo = FindingRepository(db)
        self._audit_repo = AuditLogRepository(db)

    async def generate_executive_summary(self, scan_id: UUID) -> str:
        """Erzeugt eine Management-taugliche Zusammenfassung."""
        scan, findings = await self._load_scan_data(scan_id)
        severity_counts = count_severities(findings)
        auth = await self._load_authorization(scan.target)
        lines: list[str] = []

        # Header
        lines.append(f"# Executive Summary — {scan.target}")
        lines.append("")
        lines.append(f"**Scan-ID:** `{scan.id}`")
        lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
        lines.append(f"**Status:** {scan.status.value.upper()}")
        lines.append("")

        # Autorisierungssektion
        lines.extend(format_authorization_section(auth))

        # Übersichts-Statistik
        lines.extend(_build_executive_stats(scan, findings, severity_counts))

        # Risikobewertung
        risk_level = assess_risk_level(severity_counts)
        lines.append(f"**Gesamtrisiko:** {risk_level}")
        lines.append("")

        # Top-Findings (max. 5, höchste Schwere zuerst)
        lines.extend(_build_top_findings(findings))

        # Empfehlungen
        lines.append("## Empfehlungen")
        lines.append("")
        lines.extend(generate_recommendations(severity_counts))
        lines.append("")

        # Fußzeile
        lines.append("---")
        lines.append(footer())

        return "\n".join(lines)

    async def generate_technical_report(self, scan_id: UUID) -> str:
        """Erzeugt einen vollständigen technischen Detailbericht."""
        scan, findings = await self._load_scan_data(scan_id)
        auth = await self._load_authorization(scan.target)
        return build_technical_report(scan, findings, auth)

    async def generate_compliance_report(self, scan_id: UUID) -> str:
        """Erzeugt ein Compliance-Mapping (BSI Grundschutz, ISO 27001)."""
        scan, findings = await self._load_scan_data(scan_id)
        auth = await self._load_authorization(scan.target)
        return build_compliance_report(scan, findings, auth)

    async def _load_scan_data(self, scan_id: UUID) -> tuple[ScanJob, list[Finding]]:
        """Lädt Scan-Job und zugehörige Findings aus der Datenbank."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ValueError(f"Scan-Job {scan_id} nicht gefunden")
        findings = await self._finding_repo.list_by_scan(scan_id)
        return scan, findings

    async def _load_authorization(self, target: str) -> dict | None:
        """Lädt die Autorisierung für ein Scan-Ziel aus der Whitelist."""
        conn = await self._db.get_connection()
        import aiosqlite
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT target, confirmed_by, confirmation, notes, created_at "
            "FROM authorized_targets WHERE target = ?",
            (target,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


# ── Helfer für die Executive Summary ─────────────────────────────


def _build_executive_stats(
    scan: ScanJob,
    findings: list[Finding],
    severity_counts: dict[str, int],
) -> list[str]:
    """Erzeugt die Übersichts-Statistik der Executive Summary."""
    lines: list[str] = []
    lines.append("## Zusammenfassung")
    lines.append("")
    lines.append(f"- **Ziel:** {scan.target}")
    lines.append(f"- **Scan-Typ:** {scan.scan_type.value}")
    lines.append(f"- **Findings gesamt:** {len(findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            icon = _SEVERITY_ICONS.get(sev, "")
            lines.append(f"  - {icon} {sev.capitalize()}: {count}")
    lines.append("")
    return lines


def _build_top_findings(findings: list[Finding]) -> list[str]:
    """Erzeugt die Top-5-Findings-Sektion, sortiert nach Schweregrad."""
    top_findings = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99),
    )[:5]
    lines: list[str] = []
    if top_findings:
        lines.append("## Top-Findings")
        lines.append("")
        for i, finding in enumerate(top_findings, 1):
            icon = _SEVERITY_ICONS.get(finding.severity.value, "")
            cve_tag = f" ({finding.cve_id})" if finding.cve_id else ""
            lines.append(f"{i}. {icon} **{finding.title}**{cve_tag}")
            lines.append(f"   - Host: {finding.target_host}:{finding.target_port or '—'}")
            lines.append(f"   - CVSS: {finding.cvss_score}")
        lines.append("")
    return lines

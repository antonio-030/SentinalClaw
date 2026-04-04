"""
Report-Generator fuer SentinelClaw.

Erzeugt Markdown-Reports aus Datenbank-Daten: Executive Summary,
technischer Detailbericht und Compliance-Mapping (BSI, ISO 27001).
"""

from datetime import UTC, datetime
from uuid import UUID

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import AuditLogRepository, FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob

logger = get_logger(__name__)

# Schweregrad-Icons und Sortier-Reihenfolge
_SEVERITY_ICONS: dict[str, str] = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f535",
    "info": "\u26aa",
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Compliance-Mapping: Schweregrad -> relevante BSI- und ISO-27001-Kontrollen
_BSI_MAPPING: dict[str, list[str]] = {
    "critical": ["SYS.1.1.A6 (Schadsoftware)", "OPS.1.1.3.A4 (Patch-Management)"],
    "high": ["SYS.1.1.A4 (Datensicherung)", "NET.1.1.A5 (Netzwerk-Segmentierung)"],
    "medium": ["OPS.1.1.3.A2 (Aenderungsmanagement)", "CON.3.A3 (Datenschutzkonzept)"],
    "low": ["OPS.1.1.3.A1 (Informationssicherheit)"],
    "info": ["INF.1.A1 (Informationswerte-Inventar)"],
}
_ISO27001_MAPPING: dict[str, list[str]] = {
    "critical": ["A.12.6.1 (Vulnerability Management)", "A.14.2.2 (Change Control)"],
    "high": ["A.12.2.1 (Malware Controls)", "A.13.1.1 (Network Controls)"],
    "medium": ["A.12.1.2 (Change Management)", "A.18.1.3 (Protection of Records)"],
    "low": ["A.8.1.1 (Inventory of Assets)"],
    "info": ["A.8.1.1 (Inventory of Assets)"],
}


class ReportGenerator:
    """Erzeugt Markdown-Reports aus Scan-Daten in der Datenbank."""

    def __init__(self, db: DatabaseManager) -> None:
        self._scan_repo = ScanJobRepository(db)
        self._finding_repo = FindingRepository(db)
        self._audit_repo = AuditLogRepository(db)

    async def generate_executive_summary(self, scan_id: UUID) -> str:
        """Erzeugt eine Management-taugliche Zusammenfassung."""
        scan, findings = await self._load_scan_data(scan_id)
        severity_counts = _count_severities(findings)
        lines: list[str] = []

        # Header
        lines.append(f"# Executive Summary — {scan.target}")
        lines.append("")
        lines.append(f"**Scan-ID:** `{scan.id}`")
        lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
        lines.append(f"**Status:** {scan.status.value.upper()}")
        lines.append("")

        # Uebersichts-Statistik
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

        # Risikobewertung
        risk_level = _assess_risk_level(severity_counts)
        lines.append(f"**Gesamtrisiko:** {risk_level}")
        lines.append("")

        # Top-Findings (max. 5, hoechste Schwere zuerst)
        top_findings = sorted(
            findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99),
        )[:5]
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

        # Empfehlungen
        lines.append("## Empfehlungen")
        lines.append("")
        lines.extend(_generate_recommendations(severity_counts))
        lines.append("")

        # Fusszeile
        lines.append("---")
        lines.append(_footer())

        return "\n".join(lines)

    async def generate_technical_report(self, scan_id: UUID) -> str:
        """Erzeugt einen vollstaendigen technischen Detailbericht."""
        scan, findings = await self._load_scan_data(scan_id)
        severity_counts = _count_severities(findings)
        lines: list[str] = []

        # Header
        lines.append(f"# Technischer Security-Report — {scan.target}")
        lines.append("")
        lines.append(f"**Scan-ID:** `{scan.id}`")
        lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
        lines.append(f"**Typ:** {scan.scan_type.value} | **Status:** {scan.status.value.upper()}")
        lines.append(f"**Tokens verbraucht:** {scan.tokens_used:,}")
        lines.append("")

        # Statistik-Tabelle
        lines.append("## Statistik")
        lines.append("")
        lines.append("| Schweregrad | Anzahl |")
        lines.append("|-------------|--------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            icon = _SEVERITY_ICONS.get(sev, "")
            count = severity_counts.get(sev, 0)
            lines.append(f"| {icon} {sev.capitalize()} | {count} |")
        lines.append(f"| **Gesamt** | **{len(findings)}** |")
        lines.append("")

        # Alle Findings, gruppiert nach Schweregrad
        sorted_findings = sorted(
            findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99),
        )
        if sorted_findings:
            lines.append("## Findings")
            lines.append("")
            for finding in sorted_findings:
                lines.extend(_format_finding_detail(finding))
        else:
            lines.append("## Findings")
            lines.append("")
            lines.append("Keine Findings vorhanden.")
            lines.append("")

        # Fusszeile
        lines.append("---")
        lines.append(_footer())

        return "\n".join(lines)

    async def generate_compliance_report(self, scan_id: UUID) -> str:
        """Erzeugt ein Compliance-Mapping (BSI Grundschutz, ISO 27001)."""
        scan, findings = await self._load_scan_data(scan_id)
        severity_counts = _count_severities(findings)
        lines: list[str] = []

        # Header
        lines.append(f"# Compliance-Report — {scan.target}")
        lines.append("")
        lines.append(f"**Scan-ID:** `{scan.id}`")
        lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
        lines.append("")

        # BSI Grundschutz und ISO 27001 Mapping-Tabellen
        for framework, mapping in [("BSI IT-Grundschutz", _BSI_MAPPING), ("ISO 27001", _ISO27001_MAPPING)]:
            lines.append(f"## {framework} Mapping")
            lines.append("")
            lines.append(f"| Finding | Schweregrad | {framework}-Kontrolle |")
            lines.append("|---------|-------------|" + "─" * (len(framework) + 12) + "|")
            for finding in findings:
                controls = mapping.get(finding.severity.value, [])
                control_str = ", ".join(controls) if controls else "—"
                icon = _SEVERITY_ICONS.get(finding.severity.value, "")
                title = finding.title[:40]
                lines.append(f"| {title} | {icon} {finding.severity.value.upper()} | {control_str} |")
            lines.append("")

        # Compliance-Zusammenfassung
        lines.append("## Compliance-Bewertung")
        lines.append("")
        critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        if critical_high > 0:
            lines.append(
                f"**{critical_high} kritische/hohe Findings** erfordern sofortige Massnahmen "
                "gemaess BSI IT-Grundschutz und ISO 27001."
            )
        else:
            lines.append("Keine kritischen oder hohen Findings. Grundlegende Compliance gegeben.")
        lines.append("")
        lines.extend(_generate_recommendations(severity_counts))
        lines.append("")

        # Fusszeile
        lines.append("---")
        lines.append(_footer())

        return "\n".join(lines)

    async def _load_scan_data(self, scan_id: UUID) -> tuple[ScanJob, list[Finding]]:
        """Laedt Scan-Job und zugehoerige Findings aus der Datenbank."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ValueError(f"Scan-Job {scan_id} nicht gefunden")
        findings = await self._finding_repo.list_by_scan(scan_id)
        return scan, findings


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    """Zaehlt Findings pro Schweregrad."""
    counts: dict[str, int] = {}
    for finding in findings:
        sev = finding.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _assess_risk_level(severity_counts: dict[str, int]) -> str:
    """Bewertet das Gesamtrisiko anhand der Schweregrad-Verteilung."""
    if severity_counts.get("critical", 0) > 0:
        return "\U0001f534 KRITISCH — Sofortige Massnahmen erforderlich"
    if severity_counts.get("high", 0) > 0:
        return "\U0001f7e0 HOCH — Zeitnahe Massnahmen empfohlen"
    if severity_counts.get("medium", 0) > 0:
        return "\U0001f7e1 MITTEL — Massnahmen im naechsten Wartungsfenster"
    if severity_counts.get("low", 0) > 0:
        return "\U0001f535 NIEDRIG — Beobachtung empfohlen"
    return "\u26aa INFORMATIV — Keine unmittelbaren Risiken"


def _generate_recommendations(severity_counts: dict[str, int]) -> list[str]:
    """Generiert Handlungsempfehlungen basierend auf Schweregrad-Verteilung."""
    recommendations: list[str] = []
    if severity_counts.get("critical", 0) > 0:
        recommendations.append("1. **Sofort:** Alle kritischen Findings innerhalb von 24h beheben")
        recommendations.append("2. **Patch-Management:** Notfall-Patches fuer betroffene Systeme einspielen")
    if severity_counts.get("high", 0) > 0:
        recommendations.append("3. **Kurzfristig:** Hohe Findings innerhalb von 7 Tagen adressieren")
        recommendations.append("4. **Netzwerk:** Betroffene Dienste isolieren bis zur Behebung")
    if severity_counts.get("medium", 0) > 0:
        recommendations.append("5. **Mittelfristig:** Mittlere Findings im naechsten Sprint einplanen")
    if severity_counts.get("low", 0) > 0:
        recommendations.append("6. **Langfristig:** Niedrige Findings in Backlog aufnehmen")
    if not recommendations:
        recommendations.append("- Keine unmittelbaren Massnahmen erforderlich")
        recommendations.append("- Regelmaessige Scans beibehalten")
    return recommendations


def _format_finding_detail(finding: Finding) -> list[str]:
    """Formatiert ein einzelnes Finding fuer den technischen Report."""
    icon = _SEVERITY_ICONS.get(finding.severity.value, "")
    cve_tag = f" ({finding.cve_id})" if finding.cve_id else ""
    lines: list[str] = []

    lines.append(f"### {icon} {finding.title}{cve_tag}")
    lines.append("")
    lines.append(f"- **Schweregrad:** {finding.severity.value.upper()}")
    lines.append(f"- **CVSS:** {finding.cvss_score}")
    lines.append(f"- **Host:** {finding.target_host}:{finding.target_port or '—'}")
    if finding.service:
        lines.append(f"- **Dienst:** {finding.service}")
    if finding.tool_name:
        lines.append(f"- **Tool:** {finding.tool_name}")
    if finding.description:
        lines.append(f"- **Beschreibung:** {finding.description}")
    if finding.evidence:
        lines.append(f"- **Evidenz:** `{finding.evidence[:200]}`")
    if finding.recommendation:
        lines.append(f"- **Empfehlung:** {finding.recommendation}")
    lines.append("")
    return lines


def _footer() -> str:
    """Erzeugt die Report-Fusszeile mit Zeitstempel."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return f"*Generiert von SentinelClaw v0.1 (PoC) am {timestamp} UTC*"

"""
Report-Templates für SentinelClaw.

Enthält Compliance-Mappings, Hilfs-Formatter und die Template-Funktionen
für den technischen Detailbericht und den Compliance-Report.
"""

from datetime import UTC, datetime

from src.shared.constants.severity import SEVERITY_ICONS, SEVERITY_ORDER
from src.shared.types.models import Finding, ScanJob

# Lokale Aliase — kürzer im Template-Code
_SEVERITY_ICONS = SEVERITY_ICONS
_SEVERITY_ORDER = SEVERITY_ORDER

# Compliance-Mapping: Schweregrad -> relevante BSI- und ISO-27001-Kontrollen
BSI_MAPPING: dict[str, list[str]] = {
    "critical": ["SYS.1.1.A6 (Schadsoftware)", "OPS.1.1.3.A4 (Patch-Management)"],
    "high": ["SYS.1.1.A4 (Datensicherung)", "NET.1.1.A5 (Netzwerk-Segmentierung)"],
    "medium": ["OPS.1.1.3.A2 (Aenderungsmanagement)", "CON.3.A3 (Datenschutzkonzept)"],
    "low": ["OPS.1.1.3.A1 (Informationssicherheit)"],
    "info": ["INF.1.A1 (Informationswerte-Inventar)"],
}
ISO27001_MAPPING: dict[str, list[str]] = {
    "critical": ["A.12.6.1 (Vulnerability Management)", "A.14.2.2 (Change Control)"],
    "high": ["A.12.2.1 (Malware Controls)", "A.13.1.1 (Network Controls)"],
    "medium": ["A.12.1.2 (Change Management)", "A.18.1.3 (Protection of Records)"],
    "low": ["A.8.1.1 (Inventory of Assets)"],
    "info": ["A.8.1.1 (Inventory of Assets)"],
}

# Bestätigungstyp-Labels für die Autorisierungssektion
CONFIRMATION_LABELS: dict[str, str] = {
    "owner": "Eigentümer/Betreiber des Systems",
    "pentest_mandate": "Pentest-Auftrag / Vertragliche Vereinbarung",
    "internal": "Interne Freigabe / IT-Abteilung",
}


# ── Hilfs-Formatter ───────────────────────────────────────────────


def format_authorization_section(auth: dict | None) -> list[str]:
    """Formatiert die Autorisierungssektion für den Report."""
    lines: list[str] = []
    lines.append("## Autorisierung")
    lines.append("")
    if auth:
        label = CONFIRMATION_LABELS.get(auth["confirmation"], auth["confirmation"])
        lines.append(f"- **Bestätigungstyp:** {label}")
        lines.append(f"- **Autorisiert von:** {auth['confirmed_by']}")
        lines.append(f"- **Autorisiert am:** {auth['created_at']}")
        if auth.get("notes"):
            lines.append(f"- **Notizen:** {auth['notes']}")
        lines.append("")
        lines.append(
            "> Dieser Scan wurde gemäß §202a, §303b StGB autorisiert durchgeführt. "
            "Der Auftraggeber bestätigt die Berechtigung zum aktiven Scannen des Zielsystems."
        )
    else:
        lines.append(
            "> **Hinweis:** Keine Autorisierung in der Whitelist gefunden. "
            "Stellen Sie sicher, dass eine gültige Genehmigung vorliegt."
        )
    lines.append("")
    return lines


def count_severities(findings: list[Finding]) -> dict[str, int]:
    """Zählt Findings pro Schweregrad."""
    counts: dict[str, int] = {}
    for finding in findings:
        sev = finding.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def assess_risk_level(severity_counts: dict[str, int]) -> str:
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


def generate_recommendations(severity_counts: dict[str, int]) -> list[str]:
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


def format_finding_detail(finding: Finding) -> list[str]:
    """Formatiert ein einzelnes Finding für den technischen Report."""
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


def footer() -> str:
    """Erzeugt die Report-Fußzeile mit Zeitstempel."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return f"*Generiert von SentinelClaw v0.1 (PoC) am {timestamp} UTC*"


# ── Template-Funktionen ──────────────────────────────────────────


def build_technical_report(
    scan: ScanJob,
    findings: list[Finding],
    auth: dict | None,
) -> str:
    """Erzeugt einen vollständigen technischen Detailbericht als Markdown."""
    severity_counts = count_severities(findings)
    lines: list[str] = []

    # Header
    lines.append(f"# Technischer Security-Report — {scan.target}")
    lines.append("")
    lines.append(f"**Scan-ID:** `{scan.id}`")
    lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
    lines.append(f"**Typ:** {scan.scan_type.value} | **Status:** {scan.status.value.upper()}")
    lines.append(f"**Tokens verbraucht:** {scan.tokens_used:,}")
    lines.append("")

    # Autorisierungssektion
    lines.extend(format_authorization_section(auth))

    # Statistik-Tabelle
    lines.extend(_build_statistics_table(severity_counts, len(findings)))

    # Alle Findings, gruppiert nach Schweregrad
    lines.extend(_build_findings_section(findings))

    # Fußzeile
    lines.append("---")
    lines.append(footer())

    return "\n".join(lines)


def build_compliance_report(
    scan: ScanJob,
    findings: list[Finding],
    auth: dict | None,
) -> str:
    """Erzeugt ein Compliance-Mapping (BSI Grundschutz, ISO 27001)."""
    severity_counts = count_severities(findings)
    lines: list[str] = []

    # Header
    lines.append(f"# Compliance-Report — {scan.target}")
    lines.append("")
    lines.append(f"**Scan-ID:** `{scan.id}`")
    lines.append(f"**Datum:** {scan.created_at.strftime('%d.%m.%Y %H:%M')} UTC")
    lines.append("")

    # Autorisierungssektion
    lines.extend(format_authorization_section(auth))

    # BSI Grundschutz und ISO 27001 Mapping-Tabellen
    for framework, mapping in [("BSI IT-Grundschutz", BSI_MAPPING), ("ISO 27001", ISO27001_MAPPING)]:
        lines.extend(_build_framework_table(framework, mapping, findings))

    # Compliance-Zusammenfassung
    lines.extend(_build_compliance_assessment(severity_counts))

    # Fußzeile
    lines.append("---")
    lines.append(footer())

    return "\n".join(lines)


# ── Interne Helfer für Templates ─────────────────────────────────


def _build_statistics_table(
    severity_counts: dict[str, int],
    total: int,
) -> list[str]:
    """Erzeugt die Schweregrad-Statistik-Tabelle für den technischen Report."""
    lines: list[str] = []
    lines.append("## Statistik")
    lines.append("")
    lines.append("| Schweregrad | Anzahl |")
    lines.append("|-------------|--------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        icon = _SEVERITY_ICONS.get(sev, "")
        count = severity_counts.get(sev, 0)
        lines.append(f"| {icon} {sev.capitalize()} | {count} |")
    lines.append(f"| **Gesamt** | **{total}** |")
    lines.append("")
    return lines


def _build_findings_section(findings: list[Finding]) -> list[str]:
    """Erzeugt die Finding-Detail-Sektion, sortiert nach Schweregrad."""
    sorted_findings = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99),
    )
    lines: list[str] = []
    lines.append("## Findings")
    lines.append("")
    if sorted_findings:
        for finding in sorted_findings:
            lines.extend(format_finding_detail(finding))
    else:
        lines.append("Keine Findings vorhanden.")
        lines.append("")
    return lines


def _build_framework_table(
    framework: str,
    mapping: dict[str, list[str]],
    findings: list[Finding],
) -> list[str]:
    """Erzeugt eine Compliance-Mapping-Tabelle für ein einzelnes Framework."""
    lines: list[str] = []
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
    return lines


def _build_compliance_assessment(severity_counts: dict[str, int]) -> list[str]:
    """Erzeugt die Compliance-Bewertung mit Empfehlungen."""
    lines: list[str] = []
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
    lines.extend(generate_recommendations(severity_counts))
    lines.append("")
    return lines

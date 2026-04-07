"""
Report-Typ-spezifische Renderer für PDF-Reports.

Enthält die Render-Funktionen für Executive-, Technical- und
Compliance-Reports sowie Findings-Tabellen und Detail-Ansichten.
"""

from fpdf import FPDF

from src.shared.constants.severity import SEVERITY_ORDER
from src.shared.pdf_sections import (
    SEVERITY_COLORS,
    SEVERITY_LIST,
    count_by_severity,
    render_section_heading,
)
from src.shared.types.models import Finding, ScanJob

# ── Executive Report ────────────────────────────────────────────────

def render_executive(pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
    """Executive Summary Inhalt."""
    severity_counts = count_by_severity(findings)

    # Zusammenfassung
    render_section_heading(pdf, "Zusammenfassung")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 5, f"Findings gesamt: {len(findings)}", new_x="LMARGIN", new_y="NEXT")
    for severity in SEVERITY_LIST:
        count = severity_counts.get(severity, 0)
        if count > 0:
            r, g, b = SEVERITY_COLORS.get(severity, (100, 100, 100))
            pdf.set_text_color(r, g, b)
            pdf.cell(0, 5, f"  {severity.upper()}: {count}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Top-Findings
    render_findings_table(pdf, findings[:10])


# ── Technical Report ────────────────────────────────────────────────

def render_technical(pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
    """Technischer Report Inhalt."""
    render_section_heading(pdf, "Statistik")
    render_severity_table(pdf, findings)
    pdf.ln(3)

    # Alle Findings detailliert
    render_section_heading(pdf, "Findings")
    if not findings:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 6, "Keine Findings vorhanden.", new_x="LMARGIN", new_y="NEXT")
        return

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99)
    )
    for finding in sorted_findings:
        render_finding_detail(pdf, finding)


# ── Compliance Report ───────────────────────────────────────────────

def render_compliance(pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
    """Compliance-Report Inhalt mit BSI- und ISO-27001-Mapping."""
    from src.shared.report_templates import BSI_MAPPING as _BSI_MAPPING
    from src.shared.report_templates import ISO27001_MAPPING as _ISO27001_MAPPING

    frameworks = [
        ("BSI IT-Grundschutz", _BSI_MAPPING),
        ("ISO 27001", _ISO27001_MAPPING),
    ]
    for framework_name, mapping in frameworks:
        _render_compliance_framework(pdf, framework_name, mapping, findings)


def _render_compliance_framework(
    pdf: FPDF,
    framework_name: str,
    mapping: dict[str, list[str]],
    findings: list[Finding],
) -> None:
    """Rendert eine einzelne Compliance-Framework-Zuordnungstabelle."""
    render_section_heading(pdf, f"{framework_name} Mapping")

    # Tabellenkopf
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(70, 6, "Finding", border=1, fill=True)
    pdf.cell(25, 6, "Schwere", border=1, fill=True)
    pdf.cell(0, 6, "Kontrolle", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    # Tabellenzeilen (max. 20 Findings pro Framework)
    pdf.set_font("Helvetica", "", 7)
    for finding in findings[:20]:
        controls = mapping.get(finding.severity.value, [])
        control_str = ", ".join(controls) if controls else "—"
        r, g, b = SEVERITY_COLORS.get(finding.severity.value, (100, 100, 100))

        pdf.cell(70, 5, finding.title[:35], border=1)
        pdf.set_text_color(r, g, b)
        pdf.cell(25, 5, finding.severity.value.upper(), border=1)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 5, control_str[:60], border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)


# ── Tabellen und Detail-Renderer ────────────────────────────────────

def render_severity_table(pdf: FPDF, findings: list[Finding]) -> None:
    """Schweregrad-Verteilungstabelle."""
    counts = count_by_severity(findings)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(50, 6, "Schweregrad", border=1, fill=True)
    pdf.cell(30, 6, "Anzahl", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8)
    for severity in SEVERITY_LIST:
        r, g, b = SEVERITY_COLORS.get(severity, (100, 100, 100))
        pdf.set_text_color(r, g, b)
        pdf.cell(50, 5, severity.upper(), border=1)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(30, 5, str(counts.get(severity, 0)), border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(50, 5, "GESAMT", border=1)
    pdf.cell(30, 5, str(len(findings)), border=1, new_x="LMARGIN", new_y="NEXT")


def render_findings_table(pdf: FPDF, findings: list[Finding]) -> None:
    """Findings-Übersichtstabelle."""
    if not findings:
        return
    render_section_heading(pdf, "Top-Findings")

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99)
    )

    # Tabellenkopf
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(18, 5, "Schwere", border=1, fill=True)
    pdf.cell(62, 5, "Titel", border=1, fill=True)
    pdf.cell(35, 5, "Host", border=1, fill=True)
    pdf.cell(14, 5, "Port", border=1, fill=True)
    pdf.cell(18, 5, "CVSS", border=1, fill=True)
    pdf.cell(0, 5, "CVE", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 7)
    for finding in sorted_findings:
        _render_finding_row(pdf, finding)


def _render_finding_row(pdf: FPDF, finding: Finding) -> None:
    """Rendert eine einzelne Zeile in der Findings-Übersichtstabelle."""
    r, g, b = SEVERITY_COLORS.get(finding.severity.value, (100, 100, 100))
    pdf.set_text_color(r, g, b)
    pdf.cell(18, 5, finding.severity.value.upper(), border=1)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(62, 5, finding.title[:30], border=1)
    pdf.cell(35, 5, finding.target_host[:18], border=1)
    pdf.cell(14, 5, str(finding.target_port or "—"), border=1)
    pdf.cell(18, 5, str(finding.cvss_score), border=1)
    pdf.cell(0, 5, (finding.cve_id or "—")[:18], border=1, new_x="LMARGIN", new_y="NEXT")


def render_finding_detail(pdf: FPDF, finding: Finding) -> None:
    """Einzelnes Finding im Detail."""
    # Prüfen ob noch Platz auf der Seite ist
    if pdf.get_y() > 250:
        pdf.add_page()

    r, g, b = SEVERITY_COLORS.get(finding.severity.value, (100, 100, 100))

    # Titel mit farbigem Severity-Badge
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(r, g, b)
    cve = f" ({finding.cve_id})" if finding.cve_id else ""
    severity = finding.severity.value.upper()
    title_line = f"[{severity}] {finding.title}{cve}"
    pdf.cell(0, 6, title_line, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(60, 60, 60)
    port = finding.target_port or "—"
    host_line = f"Host: {finding.target_host}:{port}  |  CVSS: {finding.cvss_score}"
    pdf.cell(0, 4, host_line, new_x="LMARGIN", new_y="NEXT")

    if finding.description:
        pdf.set_font("Helvetica", "", 7)
        pdf.multi_cell(0, 4, f"Beschreibung: {finding.description[:300]}")

    if finding.recommendation:
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(34, 120, 90)
        pdf.multi_cell(0, 4, f"Empfehlung: {finding.recommendation[:200]}")

    pdf.ln(3)

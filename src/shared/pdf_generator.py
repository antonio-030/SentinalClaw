"""
PDF-Report-Generator für SentinelClaw.

Erzeugt professionelle PDF-Reports mit Autorisierungsnachweis,
Findings-Tabelle und SentinelClaw-Branding. Nutzt fpdf2 (pure Python).
"""

from datetime import UTC, datetime
from uuid import UUID

from fpdf import FPDF

from src.shared.constants.severity import SEVERITY_ORDER
from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.repositories import FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob

logger = get_logger(__name__)


def _safe(text: str) -> str:
    """Ersetzt Unicode-Sonderzeichen für den PDF-Standard-Font (Latin-1)."""
    replacements = {
        "\u2014": "--",   # Em-Dash
        "\u2013": "-",    # En-Dash
        "\u2018": "'",    # Left single quote
        "\u2019": "'",    # Right single quote
        "\u201c": '"',    # Left double quote
        "\u201d": '"',    # Right double quote
        "\u2026": "...",  # Ellipsis
        "\u00b7": "-",    # Middle dot
        "\u2022": "-",    # Bullet
        "\u25cf": "*",    # Black circle
        "\u26aa": "o",    # White circle
        "\u2705": "[ok]",
        "\u274c": "[x]",
        "\u2728": "*",
        "\u2192": "->",   # Right arrow
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    # Verbleibende Nicht-Latin-1-Zeichen ersetzen
    return text.encode("latin-1", errors="replace").decode("latin-1")


# Bestätigungstyp-Labels
_CONFIRMATION_LABELS: dict[str, str] = {
    "owner": "Eigentümer/Betreiber des Systems",
    "pentest_mandate": "Pentest-Auftrag / Vertragliche Vereinbarung",
    "internal": "Interne Freigabe / IT-Abteilung",
}

# Schweregrad-Farben (R, G, B)
_SEVERITY_COLORS: dict[str, tuple[int, int, int]] = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (107, 114, 128),
}

# Report-Typ-Titel
_REPORT_TITLES: dict[str, str] = {
    "executive": "Executive Summary",
    "technical": "Technischer Security-Report",
    "compliance": "Compliance-Report",
}


class SentinelClawPdf(FPDF):
    """PDF mit SentinelClaw-Header und Footer. Sanitized Unicode automatisch."""

    def __init__(self, report_type: str = "technical") -> None:
        super().__init__()
        self._report_type = report_type

    def cell(self, w=0, h=None, text="", **kwargs):
        """Überschreibt cell() um Unicode-Zeichen automatisch zu ersetzen."""
        return super().cell(w, h, _safe(str(text)), **kwargs)

    def multi_cell(self, w=0, h=None, text="", **kwargs):
        """Überschreibt multi_cell() um Unicode-Zeichen automatisch zu ersetzen."""
        return super().multi_cell(w, h, _safe(str(text)), **kwargs)

    def header(self) -> None:
        """Seitenkopf mit Branding."""
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "SentinelClaw Security Assessment Platform", align="L")
        title = _REPORT_TITLES.get(self._report_type, "Report")
        self.cell(0, 6, title, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self) -> None:
        """Seitenfuß mit Seitenzahl und Zeitstempel."""
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 8, f"Generiert von SentinelClaw v0.1 | {timestamp}", align="L")
        self.cell(0, 8, f"Seite {self.page_no()}/{{nb}}", align="R")


class PdfReportGenerator:
    """Erzeugt PDF-Reports aus Scan-Daten mit Autorisierungsnachweis."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db
        self._scan_repo = ScanJobRepository(db)
        self._finding_repo = FindingRepository(db)

    async def generate_pdf(self, scan_id: UUID, report_type: str) -> bytes:
        """Erzeugt den PDF-Report als Bytes."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ValueError(f"Scan-Job {scan_id} nicht gefunden")
        findings = await self._finding_repo.list_by_scan(scan_id)
        auth = await self._load_authorization(scan.target)

        pdf = SentinelClawPdf(report_type)
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # Deckblatt-Bereich
        self._render_cover(pdf, scan, report_type)

        # Autorisierungssektion
        self._render_authorization(pdf, auth)

        # Report-Inhalt je nach Typ
        if report_type == "executive":
            self._render_executive(pdf, scan, findings)
        elif report_type == "technical":
            self._render_technical(pdf, scan, findings)
        elif report_type == "compliance":
            self._render_compliance(pdf, scan, findings)

        return pdf.output()

    # ── Render-Methoden ──────────────────────────────────────────────

    def _render_cover(self, pdf: FPDF, scan: ScanJob, report_type: str) -> None:
        """Deckblatt mit Scan-Metadaten."""
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(15, 52, 96)
        title = _REPORT_TITLES.get(report_type, "Security Report")
        pdf.cell(0, 12, title, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 8, f"Ziel: {scan.target}", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(120, 120, 120)
        date_str = scan.created_at.strftime("%d.%m.%Y %H:%M UTC")
        status = scan.status.value.upper()
        info = f"Scan-ID: {scan.id}  |  Datum: {date_str}  |  Status: {status}"
        pdf.cell(0, 7, info, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(8)

    def _render_authorization(self, pdf: FPDF, auth: dict | None) -> None:
        """Autorisierungsnachweis als hervorgehobener Kasten."""
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(0, 8, "Autorisierung", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

        # Kasten-Hintergrund
        box_y = pdf.get_y()
        box_x = 10

        if auth:
            label = _CONFIRMATION_LABELS.get(auth["confirmation"], auth["confirmation"])

            # Grüner Rahmen für autorisiert
            pdf.set_fill_color(236, 253, 245)
            pdf.set_draw_color(34, 197, 94)
            pdf.rect(box_x, box_y, 190, 34, style="DF")

            pdf.set_xy(box_x + 4, box_y + 3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(22, 101, 52)
            pdf.cell(0, 5, "AUTORISIERT", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(box_x + 4)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(90, 5, f"Bestätigungstyp: {label}")
            confirmed = auth["confirmed_by"]
            pdf.cell(
                0, 5, f"Autorisiert von: {confirmed}",
                new_x="LMARGIN", new_y="NEXT",
            )

            pdf.set_x(box_x + 4)
            pdf.cell(90, 5, f"Datum: {auth['created_at']}")
            if auth.get("notes"):
                pdf.cell(0, 5, f"Notizen: {auth['notes']}", new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(box_x + 4)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(
                0, 5,
                "Dieser Scan wurde gemäß §202a, §303b StGB autorisiert durchgeführt.",
                new_x="LMARGIN", new_y="NEXT",
            )
        else:
            # Gelber Rahmen für fehlende Autorisierung
            pdf.set_fill_color(254, 252, 232)
            pdf.set_draw_color(202, 138, 4)
            pdf.rect(box_x, box_y, 190, 14, style="DF")

            pdf.set_xy(box_x + 4, box_y + 3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(133, 77, 14)
            pdf.cell(
                0, 5, "KEINE AUTORISIERUNG GEFUNDEN — Bitte Whitelist prüfen",
                new_x="LMARGIN", new_y="NEXT",
            )

        pdf.set_y(box_y + (38 if auth else 18))
        pdf.ln(4)

    def _render_executive(self, pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
        """Executive Summary Inhalt."""
        severity_counts = _count(findings)

        # Zusammenfassung
        self._section_heading(pdf, "Zusammenfassung")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 5, f"Findings gesamt: {len(findings)}", new_x="LMARGIN", new_y="NEXT")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                r, g, b = _SEVERITY_COLORS.get(sev, (100, 100, 100))
                pdf.set_text_color(r, g, b)
                pdf.cell(0, 5, f"  {sev.upper()}: {count}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Top-Findings
        self._render_findings_table(pdf, findings[:10])

    def _render_technical(self, pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
        """Technischer Report Inhalt."""
        self._section_heading(pdf, "Statistik")
        self._render_severity_table(pdf, findings)
        pdf.ln(3)

        # Alle Findings detailliert
        self._section_heading(pdf, "Findings")
        if not findings:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 6, "Keine Findings vorhanden.", new_x="LMARGIN", new_y="NEXT")
            return

        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99))
        for finding in sorted_findings:
            self._render_finding_detail(pdf, finding)

    def _render_compliance(self, pdf: FPDF, scan: ScanJob, findings: list[Finding]) -> None:
        """Compliance-Report Inhalt."""
        from src.shared.report_generator import _BSI_MAPPING, _ISO27001_MAPPING

        frameworks = [
            ("BSI IT-Grundschutz", _BSI_MAPPING),
            ("ISO 27001", _ISO27001_MAPPING),
        ]
        for framework, mapping in frameworks:
            self._section_heading(pdf, f"{framework} Mapping")

            # Tabelle
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(70, 6, "Finding", border=1, fill=True)
            pdf.cell(25, 6, "Schwere", border=1, fill=True)
            pdf.cell(0, 6, "Kontrolle", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "", 7)
            for finding in findings[:20]:
                controls = mapping.get(finding.severity.value, [])
                control_str = ", ".join(controls) if controls else "—"
                r, g, b = _SEVERITY_COLORS.get(finding.severity.value, (100, 100, 100))

                pdf.cell(70, 5, finding.title[:35], border=1)
                pdf.set_text_color(r, g, b)
                pdf.cell(25, 5, finding.severity.value.upper(), border=1)
                pdf.set_text_color(60, 60, 60)
                pdf.cell(0, 5, control_str[:60], border=1, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

    # ── Hilfs-Render-Methoden ────────────────────────────────────────

    def _section_heading(self, pdf: FPDF, title: str) -> None:
        """Rendert eine Sektionsüberschrift."""
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(15, 52, 96)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def _render_severity_table(self, pdf: FPDF, findings: list[Finding]) -> None:
        """Schweregrad-Verteilungstabelle."""
        counts = _count(findings)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(50, 6, "Schweregrad", border=1, fill=True)
        pdf.cell(30, 6, "Anzahl", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 8)
        for sev in ["critical", "high", "medium", "low", "info"]:
            r, g, b = _SEVERITY_COLORS.get(sev, (100, 100, 100))
            pdf.set_text_color(r, g, b)
            pdf.cell(50, 5, sev.upper(), border=1)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(30, 5, str(counts.get(sev, 0)), border=1, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(50, 5, "GESAMT", border=1)
        pdf.cell(30, 5, str(len(findings)), border=1, new_x="LMARGIN", new_y="NEXT")

    def _render_findings_table(self, pdf: FPDF, findings: list[Finding]) -> None:
        """Findings-Übersichtstabelle."""
        if not findings:
            return
        self._section_heading(pdf, "Top-Findings")

        sorted_f = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99))

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(18, 5, "Schwere", border=1, fill=True)
        pdf.cell(62, 5, "Titel", border=1, fill=True)
        pdf.cell(35, 5, "Host", border=1, fill=True)
        pdf.cell(14, 5, "Port", border=1, fill=True)
        pdf.cell(18, 5, "CVSS", border=1, fill=True)
        pdf.cell(0, 5, "CVE", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 7)
        for f in sorted_f:
            r, g, b = _SEVERITY_COLORS.get(f.severity.value, (100, 100, 100))
            pdf.set_text_color(r, g, b)
            pdf.cell(18, 5, f.severity.value.upper(), border=1)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(62, 5, f.title[:30], border=1)
            pdf.cell(35, 5, f.target_host[:18], border=1)
            pdf.cell(14, 5, str(f.target_port or "—"), border=1)
            pdf.cell(18, 5, str(f.cvss_score), border=1)
            pdf.cell(0, 5, (f.cve_id or "—")[:18], border=1, new_x="LMARGIN", new_y="NEXT")

    def _render_finding_detail(self, pdf: FPDF, finding: Finding) -> None:
        """Einzelnes Finding im Detail."""
        # Prüfen ob noch Platz auf der Seite ist
        if pdf.get_y() > 250:
            pdf.add_page()

        r, g, b = _SEVERITY_COLORS.get(finding.severity.value, (100, 100, 100))

        # Titel mit farbigem Severity-Badge
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(r, g, b)
        cve = f" ({finding.cve_id})" if finding.cve_id else ""
        sev = finding.severity.value.upper()
        title_line = f"[{sev}] {finding.title}{cve}"
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

    # ── Datenbank-Zugriff ────────────────────────────────────────────

    async def _load_authorization(self, target: str) -> dict | None:
        """Lädt die Autorisierung für ein Scan-Ziel."""
        import aiosqlite

        conn = await self._db.get_connection()
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT target, confirmed_by, confirmation, notes, created_at "
            "FROM authorized_targets WHERE target = ?",
            (target,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


def _count(findings: list[Finding]) -> dict[str, int]:
    """Zählt Findings pro Schweregrad."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts

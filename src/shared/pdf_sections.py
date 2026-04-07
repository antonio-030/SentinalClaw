"""
Basis-Komponenten für PDF-Reports.

Enthält Konstanten, Hilfsfunktionen, die SentinelClawPdf-Klasse
und strukturelle Renderer (Deckblatt, Autorisierung, Überschriften).
"""

from fpdf import FPDF

from src.shared.types.models import Finding, ScanJob

# ── Konstanten ──────────────────────────────────────────────────────

# Bestätigungstyp-Labels
CONFIRMATION_LABELS: dict[str, str] = {
    "owner": "Eigentümer/Betreiber des Systems",
    "pentest_mandate": "Pentest-Auftrag / Vertragliche Vereinbarung",
    "internal": "Interne Freigabe / IT-Abteilung",
}

# Schweregrad-Farben (R, G, B)
SEVERITY_COLORS: dict[str, tuple[int, int, int]] = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (107, 114, 128),
}

# Report-Typ-Titel
REPORT_TITLES: dict[str, str] = {
    "executive": "Executive Summary",
    "technical": "Technischer Security-Report",
    "compliance": "Compliance-Report",
}

# Schweregrade in der gewünschten Reihenfolge
SEVERITY_LIST: list[str] = ["critical", "high", "medium", "low", "info"]


# ── Hilfsfunktionen ────────────────────────────────────────────────

def safe_text(text: str) -> str:
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


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Zählt Findings pro Schweregrad."""
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.severity.value
        counts[severity] = counts.get(severity, 0) + 1
    return counts


# ── PDF-Klasse ──────────────────────────────────────────────────────

class SentinelClawPdf(FPDF):
    """PDF mit SentinelClaw-Header und Footer. Sanitized Unicode automatisch."""

    def __init__(self, report_type: str = "technical") -> None:
        super().__init__()
        self._report_type = report_type

    def cell(self, w=0, h=None, text="", **kwargs):
        """Überschreibt cell() um Unicode-Zeichen automatisch zu ersetzen."""
        return super().cell(w, h, safe_text(str(text)), **kwargs)

    def multi_cell(self, w=0, h=None, text="", **kwargs):
        """Überschreibt multi_cell() um Unicode-Zeichen automatisch zu ersetzen."""
        return super().multi_cell(w, h, safe_text(str(text)), **kwargs)

    def header(self) -> None:
        """Seitenkopf mit Branding."""
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "SentinelClaw Security Assessment Platform", align="L")
        title = REPORT_TITLES.get(self._report_type, "Report")
        self.cell(0, 6, title, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self) -> None:
        """Seitenfuß mit Seitenzahl und Zeitstempel."""
        from datetime import UTC, datetime

        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 8, f"Generiert von SentinelClaw v0.1 | {timestamp}", align="L")
        self.cell(0, 8, f"Seite {self.page_no()}/{{nb}}", align="R")


# ── Strukturelle Renderer ───────────────────────────────────────────

def render_section_heading(pdf: FPDF, title: str) -> None:
    """Rendert eine Sektionsüberschrift."""
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def render_cover(pdf: FPDF, scan: ScanJob, report_type: str) -> None:
    """Deckblatt mit Scan-Metadaten."""
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(15, 52, 96)
    title = REPORT_TITLES.get(report_type, "Security Report")
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


def _render_auth_authorized(pdf: FPDF, auth: dict, box_x: int, box_y: float) -> None:
    """Rendert den grünen Autorisierungskasten für autorisierte Scans."""
    label = CONFIRMATION_LABELS.get(auth["confirmation"], auth["confirmation"])

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


def _render_auth_missing(pdf: FPDF, box_x: int, box_y: float) -> None:
    """Rendert den gelben Warnkasten bei fehlender Autorisierung."""
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


def render_authorization(pdf: FPDF, auth: dict | None) -> None:
    """Autorisierungsnachweis als hervorgehobener Kasten."""
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 8, "Autorisierung", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    box_y = pdf.get_y()
    box_x = 10

    if auth:
        _render_auth_authorized(pdf, auth, box_x, box_y)
    else:
        _render_auth_missing(pdf, box_x, box_y)

    pdf.set_y(box_y + (38 if auth else 18))
    pdf.ln(4)

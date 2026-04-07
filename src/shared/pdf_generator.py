"""
PDF-Report-Generator für SentinelClaw.

Erzeugt professionelle PDF-Reports mit Autorisierungsnachweis,
Findings-Tabelle und SentinelClaw-Branding. Delegiert das Rendern
an pdf_sections.py (Basis) und pdf_section_renderers.py (Reports).
"""

from uuid import UUID

from fpdf import FPDF

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.pdf_section_renderers import (
    render_compliance,
    render_executive,
    render_technical,
)
from src.shared.pdf_sections import (
    SentinelClawPdf,
    render_authorization,
    render_cover,
)
from src.shared.repositories import FindingRepository, ScanJobRepository
from src.shared.types.models import Finding, ScanJob

logger = get_logger(__name__)


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
        render_cover(pdf, scan, report_type)

        # Autorisierungssektion
        render_authorization(pdf, auth)

        # Report-Inhalt je nach Typ
        self._render_content(pdf, report_type, scan, findings)

        return pdf.output()

    def _render_content(
        self,
        pdf: FPDF,
        report_type: str,
        scan: ScanJob,
        findings: list[Finding],
    ) -> None:
        """Wählt den passenden Renderer für den Report-Typ."""
        renderers = {
            "executive": render_executive,
            "technical": render_technical,
            "compliance": render_compliance,
        }
        renderer = renderers.get(report_type)
        if renderer:
            renderer(pdf, scan, findings)

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

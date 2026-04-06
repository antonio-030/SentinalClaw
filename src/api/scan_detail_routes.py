"""
Scan-Detail-Routen fuer die SentinelClaw REST-API.

Enthaelt Sub-Ressourcen-Endpoints unter /api/v1/scans/{scan_id}:
  - GET  /scans/{id}/export   -> Findings exportieren (CSV, JSONL, SARIF)
  - POST /scans/compare       -> Zwei Scans vergleichen
  - GET  /scans/{id}/report   -> Report generieren (Executive, Technical, Compliance)
  - GET  /scans/{id}/hosts    -> Entdeckte Hosts auflisten
  - GET  /scans/{id}/ports    -> Offene Ports auflisten
  - GET  /scans/{id}/phases   -> Scan-Phasen auflisten
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Scan-Details"])


# ─── Request-Modelle ──────────────────────────────────────────────


class CompareRequest(BaseModel):
    """Anfrage fuer den Vergleich zweier Scans."""

    scan_id_a: str = Field(description="Baseline-Scan-ID (aelter)")
    scan_id_b: str = Field(description="Vergleichs-Scan-ID (neuer)")


# ─── Hilfsfunktionen ──────────────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkulaere Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


async def _require_scan(scan_id: str):
    """Laedt einen Scan oder wirft 400/404 wenn ungueltig/nicht gefunden."""
    from src.shared.repositories import ScanJobRepository

    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        raise HTTPException(400, f"Ungueltige Scan-ID: {scan_id}")

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    job = await scan_repo.get_by_id(scan_uuid)
    if not job:
        raise HTTPException(404, f"Scan {scan_id} nicht gefunden")
    return db, job


# ─── Endpoints ─────────────────────────────────────────────────────


@router.get("/{scan_id}/export")
async def export_findings(
    scan_id: str,
    format: str = Query(
        default="csv",
        description="Export-Format: csv, jsonl oder sarif",
    ),
) -> Response:
    """Exportiert Findings eines Scans im gewuenschten Format."""
    from src.shared.exporters import (
        export_findings_csv,
        export_findings_jsonl,
        export_findings_sarif,
    )

    db, _job = await _require_scan(scan_id)

    # Format-Zuordnung: Exportfunktion, Content-Type, Dateiendung
    format_map: dict[str, tuple] = {
        "csv": (export_findings_csv, "text/csv", "csv"),
        "jsonl": (export_findings_jsonl, "application/jsonl", "jsonl"),
        "sarif": (export_findings_sarif, "application/json", "sarif.json"),
    }

    if format not in format_map:
        raise HTTPException(
            400, f"Unbekanntes Format: {format}. Erlaubt: csv, jsonl, sarif"
        )

    export_fn, content_type, extension = format_map[format]
    content = await export_fn(db, UUID(scan_id))

    # Dateiname fuer den Download-Header zusammenbauen
    filename = f"sentinelclaw-{scan_id[:8]}.{extension}"

    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/compare")
async def compare_scans(request: CompareRequest) -> dict:
    """Vergleicht zwei Scans und zeigt das Delta (neue/behobene Findings, Ports)."""
    from src.shared.repositories import ScanJobRepository
    from src.shared.scan_compare import ScanComparator

    try:
        uuid_a = UUID(request.scan_id_a)
        uuid_b = UUID(request.scan_id_b)
    except ValueError as e:
        raise HTTPException(400, f"Ungueltige Scan-ID: {e}")

    db = await _get_db()
    scan_repo = ScanJobRepository(db)

    # Beide Scans muessen existieren
    job_a = await scan_repo.get_by_id(uuid_a)
    if not job_a:
        raise HTTPException(404, f"Scan A {request.scan_id_a} nicht gefunden")

    job_b = await scan_repo.get_by_id(uuid_b)
    if not job_b:
        raise HTTPException(404, f"Scan B {request.scan_id_b} nicht gefunden")

    comparator = ScanComparator(db)
    result = await comparator.compare(uuid_a, uuid_b)

    return {
        "scan_id_a": request.scan_id_a,
        "scan_id_b": request.scan_id_b,
        "new_findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "target_host": f.target_host,
                "target_port": f.target_port,
            }
            for f in result.new_findings
        ],
        "fixed_findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "target_host": f.target_host,
                "target_port": f.target_port,
            }
            for f in result.fixed_findings
        ],
        "unchanged_count": len(result.unchanged_findings),
        "new_ports": result.new_ports,
        "closed_ports": result.closed_ports,
        "summary": result.summary,
    }


@router.get("/{scan_id}/report")
async def generate_report(
    scan_id: str,
    type: str = Query(
        default="executive",
        description="Report-Typ: executive, technical oder compliance",
    ),
) -> Response:
    """Generiert einen Markdown-Report fuer den angegebenen Scan."""
    from src.shared.report_generator import ReportGenerator

    db, _job = await _require_scan(scan_id)
    generator = ReportGenerator(db)

    # Report-Typ auf Generierungsmethode mappen
    generators: dict[str, object] = {
        "executive": generator.generate_executive_summary,
        "technical": generator.generate_technical_report,
        "compliance": generator.generate_compliance_report,
    }

    if type not in generators:
        raise HTTPException(
            400,
            f"Unbekannter Report-Typ: {type}. Erlaubt: executive, technical, compliance",
        )

    generate_fn = generators[type]
    report_content = await generate_fn(UUID(scan_id))

    return Response(
        content=report_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="report-{type}-{scan_id[:8]}.md"'
            ),
        },
    )


@router.get("/{scan_id}/report/pdf")
async def generate_pdf_report(
    scan_id: str,
    type: str = Query(
        default="technical",
        description="Report-Typ: executive, technical oder compliance",
    ),
) -> Response:
    """Generiert einen PDF-Report mit Autorisierungsnachweis."""
    from src.shared.pdf_generator import PdfReportGenerator

    valid_types = {"executive", "technical", "compliance"}
    if type not in valid_types:
        raise HTTPException(
            400,
            f"Unbekannter Report-Typ: {type}. Erlaubt: {', '.join(valid_types)}",
        )

    db, _job = await _require_scan(scan_id)
    generator = PdfReportGenerator(db)
    pdf_data = await generator.generate_pdf(UUID(scan_id), type)

    # Dateiname mit Ziel und Datum
    target_safe = _job.target.replace(".", "-").replace("/", "-")[:30]
    date_str = datetime.now(UTC).strftime("%Y%m%d")

    return Response(
        content=bytes(pdf_data),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="sentinelclaw-{type}-{target_safe}-{date_str}.pdf"'
            ),
        },
    )


@router.get("/{scan_id}/hosts")
async def list_discovered_hosts(scan_id: str) -> list[dict]:
    """Listet alle entdeckten Hosts eines Scans."""
    from src.shared.phase_repositories import DiscoveredHostRepository

    db, _job = await _require_scan(scan_id)
    host_repo = DiscoveredHostRepository(db)
    return await host_repo.list_by_scan(UUID(scan_id))


@router.get("/{scan_id}/ports")
async def list_open_ports(scan_id: str) -> list[dict]:
    """Listet alle offenen Ports eines Scans."""
    from src.shared.phase_repositories import OpenPortRepository

    db, _job = await _require_scan(scan_id)
    port_repo = OpenPortRepository(db)
    return await port_repo.list_by_scan(UUID(scan_id))


@router.get("/{scan_id}/phases")
async def list_scan_phases(scan_id: str) -> list[dict]:
    """Listet alle Phasen eines Scans, sortiert nach Phasennummer."""
    from src.shared.phase_repositories import ScanPhaseRepository

    db, _job = await _require_scan(scan_id)
    phase_repo = ScanPhaseRepository(db)
    return await phase_repo.list_by_scan(UUID(scan_id))

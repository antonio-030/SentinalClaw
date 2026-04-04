"""
Scan-Vergleich — vergleicht zwei Scans und zeigt das Delta.

Ermöglicht es, Fortschritte oder Regressionen zwischen zwei
Scan-Durchläufen zu erkennen: neue Findings, behobene Findings,
neu geöffnete und geschlossene Ports.

Nutzung: ScanComparator(db).compare(scan_id_a, scan_id_b)
"""

from dataclasses import dataclass, field
from uuid import UUID

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger
from src.shared.phase_repositories import OpenPortRepository
from src.shared.repositories import FindingRepository
from src.shared.types.models import Finding

logger = get_logger(__name__)


@dataclass
class ComparisonResult:
    """Ergebnis eines Scan-Vergleichs (A → B)."""

    # Findings die nur in Scan B existieren (neu aufgetaucht)
    new_findings: list[Finding] = field(default_factory=list)
    # Findings die nur in Scan A existieren (behoben)
    fixed_findings: list[Finding] = field(default_factory=list)
    # Findings die in beiden Scans vorkommen
    unchanged_findings: list[Finding] = field(default_factory=list)
    # Ports die nur in Scan B offen sind (neu geöffnet)
    new_ports: list[dict] = field(default_factory=list)
    # Ports die nur in Scan A offen waren (geschlossen)
    closed_ports: list[dict] = field(default_factory=list)
    # Zusammenfassung als Text
    summary: str = ""


def _finding_key(finding: Finding) -> str:
    """Erzeugt einen Vergleichsschlüssel aus Titel + Host + Port.

    Zwei Findings gelten als identisch, wenn Titel, Host und Port
    übereinstimmen — unabhängig von ID oder Zeitstempel.
    """
    title = (finding.title or "").strip().lower()
    host = (finding.target_host or "").strip().lower()
    port = str(finding.target_port) if finding.target_port else ""
    return f"{title}||{host}||{port}"


def _port_key(port_entry: dict) -> str:
    """Erzeugt einen Vergleichsschlüssel für einen offenen Port."""
    host = str(port_entry.get("host_address", port_entry.get("host", ""))).lower()
    port = str(port_entry.get("port", ""))
    proto = str(port_entry.get("protocol", "tcp")).lower()
    return f"{host}||{port}||{proto}"


class ScanComparator:
    """Vergleicht zwei Scans und kategorisiert die Unterschiede.

    Kategorien:
    - new:       Finding nur in Scan B (neues Problem)
    - fixed:     Finding nur in Scan A (behoben seit letztem Scan)
    - unchanged: Finding in beiden Scans (unverändert)
    """

    def __init__(self, db: DatabaseManager) -> None:
        self._finding_repo = FindingRepository(db)
        self._port_repo = OpenPortRepository(db)

    async def compare(
        self, scan_id_a: UUID, scan_id_b: UUID
    ) -> ComparisonResult:
        """Vergleicht Scan A (alt) mit Scan B (neu).

        Scan A ist der Referenz-Scan (Baseline).
        Scan B ist der neuere Scan.
        Ergebnis zeigt was sich von A nach B geändert hat.
        """
        logger.info(
            "Scan-Vergleich gestartet",
            scan_a=str(scan_id_a),
            scan_b=str(scan_id_b),
        )

        # Findings und Ports beider Scans laden
        findings_a = await self._finding_repo.list_by_scan(scan_id_a)
        findings_b = await self._finding_repo.list_by_scan(scan_id_b)
        ports_a = await self._port_repo.list_by_scan(scan_id_a)
        ports_b = await self._port_repo.list_by_scan(scan_id_b)

        # Findings vergleichen anhand des Schlüssels (Titel+Host+Port)
        new, fixed, unchanged = self._compare_findings(findings_a, findings_b)

        # Ports vergleichen
        new_ports, closed_ports = self._compare_ports(ports_a, ports_b)

        # Zusammenfassung generieren
        summary = self._build_summary(
            scan_id_a, scan_id_b,
            new, fixed, unchanged,
            new_ports, closed_ports,
        )

        logger.info(
            "Scan-Vergleich abgeschlossen",
            new_findings=len(new),
            fixed_findings=len(fixed),
            unchanged_findings=len(unchanged),
            new_ports=len(new_ports),
            closed_ports=len(closed_ports),
        )

        return ComparisonResult(
            new_findings=new,
            fixed_findings=fixed,
            unchanged_findings=unchanged,
            new_ports=new_ports,
            closed_ports=closed_ports,
            summary=summary,
        )

    @staticmethod
    def _compare_findings(
        findings_a: list[Finding],
        findings_b: list[Finding],
    ) -> tuple[list[Finding], list[Finding], list[Finding]]:
        """Kategorisiert Findings in new, fixed und unchanged."""
        # Index nach Schlüssel aufbauen
        keys_a: dict[str, Finding] = {}
        for f in findings_a:
            key = _finding_key(f)
            # Bei Duplikaten das mit höherem CVSS behalten
            if key not in keys_a or f.cvss_score > keys_a[key].cvss_score:
                keys_a[key] = f

        keys_b: dict[str, Finding] = {}
        for f in findings_b:
            key = _finding_key(f)
            if key not in keys_b or f.cvss_score > keys_b[key].cvss_score:
                keys_b[key] = f

        set_a = set(keys_a.keys())
        set_b = set(keys_b.keys())

        # Nur in B → neues Finding
        new = [keys_b[k] for k in sorted(set_b - set_a)]
        # Nur in A → behobenes Finding
        fixed = [keys_a[k] for k in sorted(set_a - set_b)]
        # In beiden → unverändert (Version aus B verwenden)
        unchanged = [keys_b[k] for k in sorted(set_a & set_b)]

        return new, fixed, unchanged

    @staticmethod
    def _compare_ports(
        ports_a: list[dict],
        ports_b: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """Kategorisiert Ports in new und closed."""
        index_a: dict[str, dict] = {}
        for p in ports_a:
            key = _port_key(p)
            index_a[key] = p

        index_b: dict[str, dict] = {}
        for p in ports_b:
            key = _port_key(p)
            index_b[key] = p

        set_a = set(index_a.keys())
        set_b = set(index_b.keys())

        # Nur in B → neuer Port
        new_ports = [index_b[k] for k in sorted(set_b - set_a)]
        # Nur in A → geschlossener Port
        closed_ports = [index_a[k] for k in sorted(set_a - set_b)]

        return new_ports, closed_ports

    @staticmethod
    def _build_summary(
        scan_id_a: UUID,
        scan_id_b: UUID,
        new: list[Finding],
        fixed: list[Finding],
        unchanged: list[Finding],
        new_ports: list[dict],
        closed_ports: list[dict],
    ) -> str:
        """Erstellt eine lesbare Zusammenfassung des Vergleichs."""
        lines: list[str] = [
            f"Scan-Vergleich: {str(scan_id_a)[:8]} → {str(scan_id_b)[:8]}",
            "",
        ]

        # Gesamtübersicht
        total_a = len(fixed) + len(unchanged)
        total_b = len(new) + len(unchanged)
        lines.append(f"Findings Scan A: {total_a}  |  Findings Scan B: {total_b}")
        lines.append(f"  Neu:         {len(new)}")
        lines.append(f"  Behoben:     {len(fixed)}")
        lines.append(f"  Unverändert: {len(unchanged)}")
        lines.append("")

        # Port-Änderungen
        lines.append("Port-Änderungen:")
        lines.append(f"  Neu geöffnet:  {len(new_ports)}")
        lines.append(f"  Geschlossen:   {len(closed_ports)}")
        lines.append("")

        # Neue Findings auflisten (sortiert nach CVSS absteigend)
        if new:
            lines.append("Neue Findings:")
            for f in sorted(new, key=lambda x: x.cvss_score, reverse=True):
                port_str = f":{f.target_port}" if f.target_port else ""
                cve_str = f" ({f.cve_id})" if f.cve_id else ""
                lines.append(
                    f"  + [{f.severity.value.upper():8s}] "
                    f"{f.title} — {f.target_host}{port_str}{cve_str}"
                )
            lines.append("")

        # Behobene Findings auflisten
        if fixed:
            lines.append("Behobene Findings:")
            for f in sorted(fixed, key=lambda x: x.cvss_score, reverse=True):
                port_str = f":{f.target_port}" if f.target_port else ""
                lines.append(
                    f"  - [{f.severity.value.upper():8s}] "
                    f"{f.title} — {f.target_host}{port_str}"
                )
            lines.append("")

        # Bewertung
        if new and not fixed:
            lines.append("Bewertung: VERSCHLECHTERT — neue Schwachstellen gefunden.")
        elif fixed and not new:
            lines.append("Bewertung: VERBESSERT — Schwachstellen wurden behoben.")
        elif new and fixed:
            lines.append("Bewertung: GEMISCHT — einige behoben, neue gefunden.")
        else:
            lines.append("Bewertung: UNVERÄNDERT — keine Änderungen bei Findings.")

        return "\n".join(lines)

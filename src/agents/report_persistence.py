"""
Report-Persistierung für den Chat-Agent.

Erkennt automatisch ob eine Agent-Antwort ein strukturierter Report ist
(OSINT, Vulnerability, etc.) und speichert ihn in der agent_reports Tabelle.
"""

import re
from datetime import UTC, datetime
from uuid import uuid4

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Report-Marker die auf einen strukturierten Report hindeuten
REPORT_MARKERS = [
    "# OSINT-Bericht", "# OSINT-Report", "# Scan-Bericht",
    "# Security-Report", "# Technischer Report",
    "# Executive Summary", "# Vulnerability Report",
    "\U0001f4ca OSINT", "\U0001f50d Reconnaissance",
]

# Mindestlänge damit nicht jede kurze Antwort als Report gespeichert wird
MIN_REPORT_LENGTH = 500


async def maybe_persist_report(response: str) -> str | None:
    """Erkennt ob die Agent-Antwort ein Report ist und speichert ihn in der DB.

    Gibt die Report-ID zurück wenn gespeichert, sonst None.
    """
    is_report = any(marker in response for marker in REPORT_MARKERS)
    if not is_report or len(response) < MIN_REPORT_LENGTH:
        return None

    title = _extract_title(response)
    target = _extract_target(title, response)
    report_type = _detect_report_type(response)

    report_id = str(uuid4())

    try:
        from src.api.server import get_db
        db = await get_db()
        conn = await db.get_connection()
        await conn.execute(
            "INSERT INTO agent_reports (id, title, report_type, content, target, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (report_id, title, report_type, response, target, datetime.now(UTC).isoformat()),
        )
        await conn.commit()
        logger.info("Agent-Report gespeichert", id=report_id, title=title, type=report_type)
        return report_id
    except Exception as error:
        logger.warning("Agent-Report nicht gespeichert", error=str(error))
        return None


async def attach_report_notice(response: str) -> str:
    """Prüft ob die Antwort ein Report ist und hängt ggf. einen Hinweis an."""
    report_id = await maybe_persist_report(response)
    if report_id:
        response += (
            "\n\n---\n*Dieser Report wurde automatisch gespeichert "
            "und ist auf der Reports-Seite verfügbar.*"
        )
    return response


def _extract_title(response: str) -> str:
    """Extrahiert den Titel aus der ersten Markdown-Überschrift."""
    for line in response.split("\n"):
        if line.startswith("# "):
            return line.lstrip("# ").strip()
    return "Agent-Report"


def _extract_target(title: str, response: str) -> str:
    """Extrahiert das Scan-Target (Domain/IP) aus Titel oder Inhalt."""
    domain_match = re.search(
        r"(?:Bericht|Report|Scan).*?[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        title + " " + response[:500],
    )
    if domain_match:
        return domain_match.group(1)
    return ""


def _detect_report_type(response: str) -> str:
    """Erkennt den Report-Typ anhand von Schlüsselwörtern."""
    if "Vulnerability" in response or "Schwachstelle" in response:
        return "vulnerability"
    if "Compliance" in response:
        return "compliance"
    if "Executive" in response:
        return "executive"
    return "osint"

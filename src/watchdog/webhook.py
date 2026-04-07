"""
Webhook-Benachrichtigung für den Watchdog.

Sendet bei Kill-Switch-Aktivierung einen POST-Request an die
konfigurierte Webhook-URL. Fehler beim Senden dürfen den Watchdog
NIEMALS stoppen — nur Logging.
"""

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


async def send_webhook_notification(
    event: str,
    reason: str,
    scan_id: str | None = None,
) -> None:
    """Sendet eine Webhook-Benachrichtigung bei Kill-Switch-Aktivierung.

    Die Webhook-URL wird aus den System-Settings geladen (key: watchdog_webhook_url).
    Fehler beim Senden stoppen den Watchdog NICHT — nur Logging.
    """
    try:
        from src.shared.settings_service import get_setting
        webhook_url = await get_setting("watchdog_webhook_url", "")
        if not webhook_url:
            logger.debug(
                "watchdog_webhook_skipped",
                reason="Keine Webhook-URL konfiguriert",
            )
            return

        payload = json.dumps({
            "event": event,
            "timestamp": datetime.now(UTC).isoformat(),
            "scan_id": scan_id,
            "reason": reason,
        }).encode("utf-8")

        request = urllib.request.Request(  # noqa: S310
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Timeout von 10 Sekunden — Webhook darf Watchdog nicht blockieren
        urllib.request.urlopen(request, timeout=10)  # noqa: S310
        logger.info("watchdog_webhook_sent", url=webhook_url, event=event)
    except urllib.error.URLError as exc:
        logger.warning("watchdog_webhook_failed", error=str(exc))
    except Exception as exc:
        # Webhook-Fehler dürfen den Watchdog niemals zum Absturz bringen
        logger.warning("watchdog_webhook_error", error=str(exc))

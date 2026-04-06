"""Globales Rate-Limiting für die SentinelClaw REST-API.

In-Memory IP-basierter Counter mit konfigurierbaren Limits pro Pfad.
Schützt vor Brute-Force und API-Missbrauch.
"""

import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Standard-Limit: 60 Anfragen pro Minute
_DEFAULT_REQUESTS_PER_MINUTE = 60

# Pfad-spezifische Limits (strengerer Schutz für teure Operationen)
_PATH_LIMITS: dict[str, int] = {
    "/api/v1/scans": 10,
    "/api/v1/chat": 20,
}

# Pfade die NICHT limitiert werden (Health-Checks, etc.)
_EXEMPT_PATHS: set[str] = {"/health"}

# Alte Einträge nach 5 Minuten entfernen
_CLEANUP_INTERVAL_SECONDS = 300


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Begrenzt API-Anfragen pro IP-Adresse (In-Memory, Sliding Window)."""

    def __init__(self, app: object) -> None:
        super().__init__(app)
        # Speichert Zeitstempel pro IP: {"1.2.3.4": [ts1, ts2, ...]}
        self._requests: dict[str, list[float]] = {}
        self._last_cleanup = time.time()

    async def dispatch(self, request: Request, call_next: object) -> Response:
        path = request.url.path

        # Öffentliche Pfade durchlassen
        if path in _EXEMPT_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60.0

        # Periodisch alte Einträge aufräumen
        if now - self._last_cleanup > _CLEANUP_INTERVAL_SECONDS:
            self._cleanup_old_entries(now)

        # Bisherige Anfragen im 1-Minuten-Fenster filtern
        key = f"{client_ip}:{path}"
        timestamps = self._requests.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]

        # Limit für diesen Pfad ermitteln
        limit = self._get_limit_for_path(path)

        if len(timestamps) >= limit:
            wait_seconds = int(timestamps[0] - window_start) + 1
            logger.warning("Rate-Limit erreicht", ip=client_ip, path=path)
            return Response(
                content=f'{{"detail":"Zu viele Anfragen. Bitte warte {wait_seconds} Sekunden."}}',
                status_code=429,
                media_type="application/json",
            )

        timestamps.append(now)
        self._requests[key] = timestamps
        return await call_next(request)

    @staticmethod
    def _get_limit_for_path(path: str) -> int:
        """Ermittelt das Rate-Limit für einen Pfad (exakte oder Prefix-Übereinstimmung)."""
        for prefix, limit in _PATH_LIMITS.items():
            if path.startswith(prefix):
                return limit
        return _DEFAULT_REQUESTS_PER_MINUTE

    def _cleanup_old_entries(self, now: float) -> None:
        """Entfernt Einträge älter als 5 Minuten."""
        cutoff = now - _CLEANUP_INTERVAL_SECONDS
        stale_keys = [k for k, ts in self._requests.items() if not ts or ts[-1] < cutoff]
        for key in stale_keys:
            del self._requests[key]
        self._last_cleanup = now

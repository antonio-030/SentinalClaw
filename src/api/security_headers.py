"""Security-Headers-Middleware für die SentinelClaw REST-API.

Setzt HTTP-Sicherheitsheader auf jede Response:
  - Content-Security-Policy (XSS-Schutz)
  - X-Frame-Options (Clickjacking-Schutz)
  - X-Content-Type-Options (MIME-Sniffing)
  - Referrer-Policy (Datenschutz)
  - Permissions-Policy (Feature-Einschränkung)
  - Strict-Transport-Security (HTTPS-Erzwingung, nur Produktion)
"""

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Fügt Sicherheitsheader zu jeder HTTP-Response hinzu."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # CSP — verhindert Inline-Scripts und fremde Ressourcen
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' wss:; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Clickjacking-Schutz
        response.headers["X-Frame-Options"] = "DENY"

        # MIME-Sniffing verhindern
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer-Policy — kein voller Referrer an Dritte
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Feature-Policy — Kamera, Mikrofon, Geolocation deaktivieren
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # HSTS — nur wenn nicht im Debug-Modus (erzwingt HTTPS)
        is_debug = os.environ.get("SENTINEL_DEBUG", "true").lower() == "true"
        if not is_debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response

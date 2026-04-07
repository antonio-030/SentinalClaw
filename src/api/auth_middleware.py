"""Auth-Middleware für SentinelClaw REST-API.

Prüft Cookie/Bearer-Auth, Token-Blacklist, CSRF-Schutz
und Session-Inaktivität für alle geschützten Endpoints.
"""

import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.shared.auth import SESSION_INACTIVITY_MINUTES, decode_token
from src.shared.config import get_settings
from src.shared.token_blacklist import token_blacklist

# Öffentliche Pfade die keine Authentifizierung erfordern
_settings = get_settings()
_PUBLIC_PATHS: set[str] = {
    "/health", "/metrics",
    "/api/v1/auth/login", "/api/v1/auth/mfa/login",
}
if _settings.debug:
    _PUBLIC_PATHS |= {"/docs", "/openapi.json", "/redoc"}

# HTTP-Methoden die den Serverzustand ändern — CSRF-Schutz erforderlich
_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "DELETE", "PATCH"}

# In-Memory: Letzte Aktivität pro Session (jti → Zeitstempel)
_session_activity: dict[str, float] = {}


def _error_response(detail: str, status_code: int) -> Response:
    """Erzeugt eine JSON-Fehlerantwort."""
    return Response(
        content=f'{{"detail":"{detail}"}}',
        status_code=status_code,
        media_type="application/json",
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """Prüft Auth-Cookie (oder Bearer-Header), Blacklist, CSRF und Inaktivität."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Öffentliche Pfade durchlassen
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        token = _extract_token(request)
        if not token:
            return _error_response("Token fehlt oder ungueltig", 401)

        payload = decode_token(token)
        if payload is None:
            return _error_response("Token abgelaufen oder ungueltig", 401)

        # Token-Revokation und Inaktivität prüfen
        jti = payload.get("jti", "")
        error = _check_session_validity(jti, request.method, request.cookies)
        if error:
            return error

        # CSRF-Schutz für zustandsändernde Requests mit Cookie-Auth
        csrf_error = _check_csrf(request)
        if csrf_error:
            return csrf_error

        # Aktivität tracken und Benutzer-Daten setzen
        if jti:
            _session_activity[jti] = time.time()
        request.state.user = payload
        return await call_next(request)


def _extract_token(request: Request) -> str:
    """Extrahiert den Auth-Token aus Cookie oder Bearer-Header."""
    token = request.cookies.get("sc_session", "")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
    return token


def _check_session_validity(
    jti: str,
    method: str,
    cookies: dict,
) -> Response | None:
    """Prüft Revokation und Inaktivitäts-Timeout. Gibt Fehler oder None zurück."""
    if jti and token_blacklist.is_revoked(jti):
        return _error_response("Session wurde beendet", 401)

    now = time.time()
    if jti and jti in _session_activity:
        last_active = _session_activity[jti]
        if (now - last_active) > SESSION_INACTIVITY_MINUTES * 60:
            return _error_response(
                "Session wegen Inaktivitaet abgelaufen", 401
            )
    return None


def _check_csrf(request: Request) -> Response | None:
    """Prüft CSRF-Token bei zustandsändernden Requests mit Cookie-Auth."""
    if (
        request.method in _STATE_CHANGING_METHODS
        and request.cookies.get("sc_session")
    ):
        csrf_cookie = request.cookies.get("sc_csrf", "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        if not csrf_cookie or csrf_cookie != csrf_header:
            return _error_response("CSRF-Token fehlt oder ungueltig", 403)
    return None

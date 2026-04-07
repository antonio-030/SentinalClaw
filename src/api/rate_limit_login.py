"""Login Rate-Limiter (In-Memory, IP-basiert).

Begrenzt fehlgeschlagene Login-Versuche pro IP-Adresse
um Brute-Force-Angriffe zu verhindern.
"""

import time
from collections import defaultdict

from src.shared.config import get_settings


class LoginRateLimiter:
    """Begrenzt fehlgeschlagene Login-Versuche pro IP-Adresse.

    Speichert Zeitstempel fehlgeschlagener Versuche und blockiert
    weitere Logins wenn das Limit innerhalb des Zeitfensters erreicht ist.
    """

    WINDOW_SECONDS = 300  # 5 Minuten

    def __init__(self, max_attempts: int = 5) -> None:
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._max_attempts = max_attempts

    def is_blocked(self, ip: str) -> bool:
        """Prueft ob die IP blockiert ist."""
        now = time.time()
        # Alte Eintraege ausserhalb des Zeitfensters entfernen
        self._attempts[ip] = [
            t for t in self._attempts[ip]
            if now - t < self.WINDOW_SECONDS
        ]
        return len(self._attempts[ip]) >= self._max_attempts

    def record_failure(self, ip: str) -> None:
        """Registriert einen fehlgeschlagenen Login-Versuch."""
        self._attempts[ip].append(time.time())

    def reset(self, ip: str) -> None:
        """Setzt den Zaehler fuer eine IP zurueck (nach erfolgreichem Login)."""
        self._attempts.pop(ip, None)


# Globale Rate-Limiter-Instanz
_rate_limiter: LoginRateLimiter | None = None


def get_rate_limiter() -> LoginRateLimiter:
    """Gibt den globalen Rate-Limiter zurueck (Lazy-Init)."""
    global _rate_limiter
    if _rate_limiter is None:
        settings = get_settings()
        _rate_limiter = LoginRateLimiter(
            max_attempts=settings.login_rate_limit_attempts
        )
    return _rate_limiter

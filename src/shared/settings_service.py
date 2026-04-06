"""
Gecachter Lese-Layer für Systemeinstellungen.

Statt direkt aus defaults.py zu lesen, nutzt der Rest des Codes
diesen Service. Werte werden beim ersten Zugriff aus der DB geladen
und im Speicher gecacht. Nach Änderungen wird der Cache invalidiert.
"""

from src.shared.database import DatabaseManager
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# In-Memory-Cache: key -> value (als String)
_cache: dict[str, str] = {}
_cache_loaded = False
_db_ref: DatabaseManager | None = None


def init_settings_service(db: DatabaseManager) -> None:
    """Registriert die DB-Referenz für den Service."""
    global _db_ref
    _db_ref = db


async def _ensure_cache() -> None:
    """Lädt alle Einstellungen in den Cache, falls noch nicht geschehen."""
    global _cache_loaded
    if _cache_loaded or _db_ref is None:
        return
    conn = await _db_ref.get_connection()
    cursor = await conn.execute("SELECT key, value FROM system_settings")
    rows = await cursor.fetchall()
    for key, value in rows:
        _cache[key] = value
    _cache_loaded = True


def invalidate_cache() -> None:
    """Leert den Cache — nächster Zugriff lädt aus der DB."""
    global _cache_loaded
    _cache.clear()
    _cache_loaded = False
    logger.debug("Settings-Cache invalidiert")


async def get_setting(key: str, default: str = "") -> str:
    """Liest eine Einstellung aus dem Cache (oder DB beim ersten Zugriff)."""
    await _ensure_cache()
    return _cache.get(key, default)


async def get_setting_int(key: str, default: int = 0) -> int:
    """Liest eine Einstellung als Integer."""
    raw = await get_setting(key, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


async def get_setting_float(key: str, default: float = 0.0) -> float:
    """Liest eine Einstellung als Float."""
    raw = await get_setting(key, str(default))
    try:
        return float(raw)
    except ValueError:
        return default


async def get_tool_timeout(tool_name: str) -> int:
    """Gibt das Timeout für ein Tool in Sekunden zurück."""
    # Mapping: Tool-Name -> Settings-Key
    key = f"timeout_{tool_name}"
    # Fallback-Defaults falls DB noch nicht gesät
    fallbacks = {"nmap": 120, "nuclei": 180, "curl": 30, "dig": 15, "whois": 15}
    return await get_setting_int(key, fallbacks.get(tool_name, 60))

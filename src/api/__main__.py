"""
Einstiegspunkt für den API-Server.

Starten mit: python -m src.api
Oder: uvicorn src.api.server:app --reload --port 3001
"""

import uvicorn

from src.shared.config import get_settings


def main() -> None:
    """Startet den FastAPI-Server."""
    settings = get_settings()
    uvicorn.run(
        "src.api.server:app",
        host="0.0.0.0",
        port=3001,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()

"""
Einstiegspunkt für den MCP-Server.

Starten mit: python -m src.mcp_server
"""

from src.mcp_server.server import create_mcp_server
from src.shared.config import get_settings
from src.shared.logging_setup import setup_logging


def main() -> None:
    """Startet den MCP-Server."""
    settings = get_settings()
    setup_logging(settings.log_level)

    mcp = create_mcp_server()
    mcp.run()


if __name__ == "__main__":
    main()

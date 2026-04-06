"""
WebSocket-Verbindungsmanager für SentinelClaw.

Verwaltet aktive WebSocket-Verbindungen und ermöglicht
Echtzeit-Push von Agent-Antworten, Approval-Requests und Scan-Updates.
"""

import json
from datetime import UTC, datetime

from fastapi import WebSocket

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Verwaltet aktive WebSocket-Verbindungen pro User."""

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: str) -> None:
        """Akzeptiert eine neue WebSocket-Verbindung."""
        await websocket.accept()
        if user_id not in self._connections:
            self._connections[user_id] = []
        self._connections[user_id].append(websocket)
        logger.info("WebSocket verbunden", user=user_id, total=self.connection_count)

    def disconnect(self, websocket: WebSocket, user_id: str) -> None:
        """Entfernt eine geschlossene Verbindung."""
        if user_id in self._connections:
            self._connections[user_id] = [
                ws for ws in self._connections[user_id] if ws != websocket
            ]
            if not self._connections[user_id]:
                del self._connections[user_id]
        logger.info("WebSocket getrennt", user=user_id, total=self.connection_count)

    async def send_to_user(self, user_id: str, event: str, data: dict) -> int:
        """Sendet eine Nachricht an alle Verbindungen eines Users."""
        message = json.dumps({
            "event": event,
            "data": data,
            "timestamp": datetime.now(UTC).isoformat(),
        })
        sent = 0
        dead: list[WebSocket] = []

        for ws in self._connections.get(user_id, []):
            try:
                await ws.send_text(message)
                sent += 1
            except Exception:
                dead.append(ws)

        # Tote Verbindungen aufräumen
        for ws in dead:
            self.disconnect(ws, user_id)

        return sent

    async def broadcast(self, event: str, data: dict) -> int:
        """Sendet eine Nachricht an ALLE verbundenen User."""
        sent = 0
        for user_id in list(self._connections.keys()):
            sent += await self.send_to_user(user_id, event, data)
        return sent

    @property
    def connection_count(self) -> int:
        """Anzahl aller aktiven Verbindungen."""
        return sum(len(conns) for conns in self._connections.values())

    @property
    def connected_users(self) -> list[str]:
        """Liste aller verbundenen User-IDs."""
        return list(self._connections.keys())


# Singleton-Instanz für die gesamte Anwendung
ws_manager = ConnectionManager()

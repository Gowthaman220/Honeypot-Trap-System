import json
from typing import List, Dict, Any
from fastapi import WebSocket
from app.core.logger import logger


class WebSocketManager:
    """Manages active WebSocket dashboard connections and broadcasts telemetry updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message_type: str, data: Dict[str, Any]):
        """Broadcast payload to all connected clients asynchronously."""
        if not self.active_connections:
            return

        payload = {
            "type": message_type,
            "data": data
        }
        text = json.dumps(payload, default=str)

        stale_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(text)
            except Exception as e:
                logger.error(f"Error sending message to WebSocket client: {e}")
                stale_connections.append(connection)

        for stale in stale_connections:
            self.disconnect(stale)


ws_manager = WebSocketManager()

# backend/app/websocket/__init__.py
"""WebSocket module: Hub and connection manager."""

from backend.app.websocket.hub import WebSocketHub

__all__ = ["WebSocketHub"]

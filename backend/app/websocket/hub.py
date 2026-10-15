"""WebSocket connection hub and telemetry broadcast manager."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect

from backend.app.api.schemas import WebSocketTelemetryFrame, TelemetryUpdatePayload
from backend.app.core.drone_engine import DroneStateSnapshot

logger = logging.getLogger("drone_security.websocket_hub")


class WebSocketHub:
    """Manages active WebSocket client connections and broadcasts real-time telemetry frames."""

    def __init__(self) -> None:
        self._active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._broadcast_seq: int = 0

    @property
    def active_connections_count(self) -> int:
        """Return number of currently connected WebSocket clients."""
        return len(self._active_connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept an incoming WebSocket connection and register it."""
        await websocket.accept()
        async with self._lock:
            self._active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active clients: {len(self._active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a disconnected WebSocket client."""
        async with self._lock:
            self._active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Remaining clients: {len(self._active_connections)}")

    def build_telemetry_frame(self, snapshot: DroneStateSnapshot) -> dict[str, Any]:
        """Construct the standardized TELEMETRY_UPDATE frame dictionary."""
        self._broadcast_seq += 1
        return {
            "type": "TELEMETRY_UPDATE",
            "seq": self._broadcast_seq,
            "timestamp": time.time(),
            "payload": {
                "state_version": snapshot.state_version,
                "flight_state": snapshot.flight_state.value,
                "x": round(snapshot.x, 3),
                "y": round(snapshot.y, 3),
                "z": round(snapshot.z, 3),
                "latitude": round(snapshot.latitude, 6),
                "longitude": round(snapshot.longitude, 6),
                "altitude_msl": round(snapshot.altitude_msl, 2),
                "heading": round(snapshot.heading, 1),
                "speed": round(snapshot.speed, 2),
                "battery_percent": round(snapshot.battery_level, 2),
            },
        }

    async def send_initial_telemetry(self, websocket: WebSocket, snapshot: DroneStateSnapshot) -> bool:
        """Send immediate baseline telemetry to a newly connected client."""
        frame = self.build_telemetry_frame(snapshot)
        try:
            await websocket.send_text(json.dumps(frame))
            return True
        except Exception as e:
            logger.warning(f"Failed to send initial telemetry to client: {e}")
            await self.disconnect(websocket)
            return False

    async def broadcast_telemetry(self, snapshot: DroneStateSnapshot) -> None:
        """Broadcast authoritative telemetry frame to all active clients concurrently."""
        if not self._active_connections:
            return

        frame = self.build_telemetry_frame(snapshot)
        payload_text = json.dumps(frame)

        async with self._lock:
            clients = list(self._active_connections)

        if not clients:
            return

        # Broadcast concurrently without allowing one failing client to block others
        tasks = [self._safe_send(ws, payload_text) for ws in clients]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect broken connections for cleanup
        broken_clients = [
            clients[i] for i, res in enumerate(results) if isinstance(res, Exception) or res is False
        ]
        if broken_clients:
            async with self._lock:
                for ws in broken_clients:
                    self._active_connections.discard(ws)
            logger.info(f"Cleaned up {len(broken_clients)} broken WebSocket connections.")

    async def _safe_send(self, websocket: WebSocket, text: str) -> bool:
        """Safely send text frame with a timeout to prevent slow-client deadlock."""
        try:
            await asyncio.wait_for(websocket.send_text(text), timeout=1.0)
            return True
        except Exception:
            return False

    async def handle_client_messages(self, websocket: WebSocket) -> None:
        """Handle incoming upstream messages from client (e.g. PING)."""
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                except Exception:
                    continue

                if isinstance(msg, dict) and msg.get("type") == "PING":
                    pong_frame = {
                        "type": "PONG",
                        "timestamp": time.time(),
                    }
                    await websocket.send_text(json.dumps(pong_frame))
        except WebSocketDisconnect:
            await self.disconnect(websocket)
        except Exception as e:
            logger.debug(f"Client connection closed with exception: {e}")
            await self.disconnect(websocket)

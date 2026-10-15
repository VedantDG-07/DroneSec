"""Telemetry service managing background simulation tick loop, telemetry buffer, and WebSocket broadcasts."""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from typing import Any, Deque, Optional

from backend.app.core.drone_engine import DroneEngine, DroneStateSnapshot
from backend.app.websocket.hub import WebSocketHub

logger = logging.getLogger("drone_security.telemetry_service")


class TelemetryService:
    """Coordinates simulation ticking, in-memory telemetry buffering, and real-time WebSocket distribution."""

    def __init__(
        self,
        drone_engine: DroneEngine,
        ws_hub: WebSocketHub,
        tick_rate_hz: float = 20.0,
        broadcast_interval_seconds: float = 0.1,
        max_buffer_size: int = 500,
        state_lock: Optional[asyncio.Lock] = None,
    ) -> None:
        self.drone_engine = drone_engine
        self.ws_hub = ws_hub
        self.tick_rate_hz = tick_rate_hz
        self.broadcast_interval = broadcast_interval_seconds
        self.state_lock = state_lock or asyncio.Lock()

        self._buffer: Deque[dict[str, Any]] = collections.deque(maxlen=max_buffer_size)
        self._loop_task: Optional[asyncio.Task[None]] = None
        self._running: bool = False
        self._last_tick_time: float = 0.0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_tick_timestamp(self) -> float:
        return self._last_tick_time

    def get_loop_status(self) -> dict[str, Any]:
        """Return operational metrics for health status monitoring."""
        return {
            "running": self._running,
            "tick_rate_hz": self.tick_rate_hz,
            "last_tick_timestamp": self._last_tick_time,
        }

    def record_snapshot(self, snapshot: DroneStateSnapshot) -> dict[str, Any]:
        """Format and append a state snapshot to the rolling telemetry buffer."""
        record = {
            "state_version": snapshot.state_version,
            "timestamp": snapshot.timestamp,
            "flight_state": snapshot.flight_state.value,
            "armed": snapshot.armed,
            "x": round(snapshot.x, 3),
            "y": round(snapshot.y, 3),
            "z": round(snapshot.z, 3),
            "latitude": round(snapshot.latitude, 6),
            "longitude": round(snapshot.longitude, 6),
            "altitude_msl": round(snapshot.altitude_msl, 2),
            "heading": round(snapshot.heading, 1),
            "speed": round(snapshot.speed, 2),
            "battery_level": round(snapshot.battery_level, 2),
        }
        self._buffer.append(record)
        return record

    async def record_and_broadcast(self, snapshot: DroneStateSnapshot) -> None:
        """Buffer snapshot and push immediate update frame across WebSocket hub."""
        self.record_snapshot(snapshot)
        await self.ws_hub.broadcast_telemetry(snapshot)

    def get_recent_telemetry(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return rolling buffer of recent telemetry samples (most recent first)."""
        clamped_limit = max(1, min(limit, len(self._buffer)))
        items = list(self._buffer)
        items.reverse()
        return items[:clamped_limit]

    def start_background_loop(self) -> None:
        """Spawn the asynchronous background simulation tick and broadcast task."""
        if self._running or self._loop_task is not None:
            return
        self._running = True
        self._loop_task = asyncio.create_task(self._simulation_loop())
        logger.info(f"Simulation tick loop started at {self.tick_rate_hz} Hz.")

    async def stop_background_loop(self) -> None:
        """Gracefully stop the background simulation loop task."""
        self._running = False
        if self._loop_task is not None:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
            self._loop_task = None
        logger.info("Simulation tick loop stopped.")

    async def _simulation_loop(self) -> None:
        """Continuous background tick loop advancing kinematic state and broadcasting telemetry."""
        dt = 1.0 / self.tick_rate_hz
        last_broadcast_time = time.monotonic()

        while self._running:
            start_tick = time.monotonic()
            self._last_tick_time = time.time()

            # Execute simulation tick under lock
            async with self.state_lock:
                self.drone_engine.tick(dt)
                snapshot = self.drone_engine.get_state_snapshot()

            self.record_snapshot(snapshot)

            # Broadcast at configured telemetry cadence (e.g. 10 Hz)
            now = time.monotonic()
            if (now - last_broadcast_time) >= self.broadcast_interval:
                last_broadcast_time = now
                await self.ws_hub.broadcast_telemetry(snapshot)

            # Calculate sleep duration to preserve target frequency without drift
            elapsed = time.monotonic() - start_tick
            sleep_duration = max(0.0, dt - elapsed)
            await asyncio.sleep(sleep_duration)

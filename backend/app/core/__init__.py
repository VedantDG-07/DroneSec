# backend/app/core/__init__.py
"""Core simulation package: kinematics, coordinate transforms, and flight state machine."""

from backend.app.core.coordinate_service import (
    CoordinateService,
    GeographicCoordinates,
    LocalCoordinates,
)
from backend.app.core.flight_fsm import (
    FlightFSM,
    FlightState,
    IllegalStateTransitionError,
    TransitionResult,
)
from backend.app.core.drone_engine import (
    CommandResult,
    DroneCommand,
    DroneEngine,
    DroneStateSnapshot,
)

__all__ = [
    "CoordinateService",
    "LocalCoordinates",
    "GeographicCoordinates",
    "FlightFSM",
    "FlightState",
    "IllegalStateTransitionError",
    "TransitionResult",
    "DroneEngine",
    "DroneCommand",
    "CommandResult",
    "DroneStateSnapshot",
]

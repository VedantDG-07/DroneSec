"""Authoritative Drone Simulation Engine.

Owns and mutates the authoritative state vector of the virtual drone.
Implements deterministic stepped movement, geofencing, battery depletion,
and strict atomic command validation according to docs/requirements.md (FR-A.1 to FR-A.6).
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from backend.app.core.coordinate_service import CoordinateService, GeographicCoordinates
from backend.app.core.flight_fsm import FlightFSM, FlightState, TransitionResult


# Simulation and safety limits
DEFAULT_STEP_DISTANCE_METERS: float = 2.0
DEFAULT_TAKEOFF_ALTITUDE_METERS: float = 5.0
GEOFENCE_X_MIN: float = -100.0
GEOFENCE_X_MAX: float = 100.0
GEOFENCE_Z_MIN: float = -100.0
GEOFENCE_Z_MAX: float = 100.0
GEOFENCE_Y_MIN: float = 0.0
GEOFENCE_Y_MAX: float = 50.0

# Battery model constants
INITIAL_BATTERY_LEVEL: float = 100.0
TAKEOFF_BATTERY_BURN_PERCENT: float = 1.0
MOVEMENT_BURN_PERCENT_PER_METER: float = 0.1
IDLE_BURN_PERCENT_PER_SECOND: float = 0.02
LOW_BATTERY_THRESHOLD: float = 15.0
CRITICAL_BATTERY_THRESHOLD: float = 5.0


class DroneCommand(str, Enum):
    """Enumeration of all supported drone flight commands."""

    ARM = "ARM"
    DISARM = "DISARM"
    TAKEOFF = "TAKEOFF"
    LAND = "LAND"
    MOVE_FORWARD = "MOVE_FORWARD"
    MOVE_BACKWARD = "MOVE_BACKWARD"
    MOVE_LEFT = "MOVE_LEFT"
    MOVE_RIGHT = "MOVE_RIGHT"
    MOVE_UP = "MOVE_UP"
    MOVE_DOWN = "MOVE_DOWN"
    STOP = "STOP"
    EMERGENCY_STOP = "EMERGENCY_STOP"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class DroneStateSnapshot:
    """Immutable snapshot of the authoritative drone state vector."""

    state_version: int
    timestamp: float
    flight_state: FlightState
    armed: bool
    x: float
    y: float
    z: float
    latitude: float
    longitude: float
    altitude_msl: float
    heading: float
    speed: float
    battery_level: float
    last_command_id: Optional[str] = None


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a command execution attempt.
    
    Attributes:
        success: True if the command was accepted and executed.
        command: The command that was attempted.
        message: Descriptive summary of execution or rejection reason.
        state_version: State version of the engine following the operation.
        error_code: Machine-readable rejection code (None if success=True).
    """

    success: bool
    command: DroneCommand
    message: str
    state_version: int
    error_code: Optional[str] = None


class DroneEngine:
    """Authoritative drone simulation engine.
    
    Invariants:
        1. The engine owns the authoritative ground truth for all drone state variables.
        2. Any command rejected by validation leaves all state variables and state_version
           completely untouched (strict atomicity).
        3. Local position is strictly clamped to the geofence boundary envelope.
        4. Battery depletion conforms to documented takeoff, movement, and idle rates.
    """

    def __init__(
        self,
        coordinate_service: Optional[CoordinateService] = None,
        initial_battery: float = INITIAL_BATTERY_LEVEL,
        takeoff_altitude: float = DEFAULT_TAKEOFF_ALTITUDE_METERS,
        step_distance: float = DEFAULT_STEP_DISTANCE_METERS,
        clock_func: Optional[callable] = None,
    ) -> None:
        self._coord_service = coordinate_service or CoordinateService()
        self._takeoff_altitude = float(takeoff_altitude)
        self._default_step_distance = float(step_distance)
        self._clock = clock_func or time.time

        # Authoritative State Vector
        self._state_version: int = 0
        self._fsm = FlightFSM(initial_state=FlightState.DISARMED)
        self._armed: bool = False
        self._x: float = 0.0
        self._y: float = 0.0
        self._z: float = 0.0
        self._heading: float = 0.0  # 0 deg = North (+Z)
        self._speed: float = 0.0
        self._battery_level: float = float(initial_battery)
        self._last_command_id: Optional[str] = None
        self._last_update_timestamp: float = self._clock()

    # --- Read-Only Property Accessors ---

    @property
    def state_version(self) -> int:
        return self._state_version

    @property
    def flight_state(self) -> FlightState:
        return self._fsm.current_state

    @property
    def armed(self) -> bool:
        return self._armed

    @property
    def x(self) -> float:
        return self._x

    @property
    def y(self) -> float:
        return self._y

    @property
    def z(self) -> float:
        return self._z

    @property
    def heading(self) -> float:
        return self._heading

    @property
    def speed(self) -> float:
        return self._speed

    @property
    def battery_level(self) -> float:
        return self._battery_level

    @property
    def last_command_id(self) -> Optional[str]:
        return self._last_command_id

    def get_state_snapshot(self) -> DroneStateSnapshot:
        """Return an immutable snapshot of the authoritative drone state vector."""
        geo = self._coord_service.local_to_geographic(self._x, self._y, self._z)
        return DroneStateSnapshot(
            state_version=self._state_version,
            timestamp=self._last_update_timestamp,
            flight_state=self._fsm.current_state,
            armed=self._armed,
            x=self._x,
            y=self._y,
            z=self._z,
            latitude=geo.latitude,
            longitude=geo.longitude,
            altitude_msl=geo.altitude_msl,
            heading=self._heading,
            speed=self._speed,
            battery_level=self._battery_level,
            last_command_id=self._last_command_id,
        )

    # --- Authoritative Command Dispatcher ---

    def execute_command(
        self,
        command: DroneCommand,
        distance_meters: Optional[float] = None,
        command_id: Optional[str] = None,
    ) -> CommandResult:
        """Execute a flight command atomically.
        
        If any validation check fails, the pre-operation state is 100% preserved.
        Only a successful state change increments state_version.
        """
        if not isinstance(command, DroneCommand):
            try:
                command = DroneCommand(command)
            except ValueError:
                return CommandResult(
                    success=False,
                    command=command,  # type: ignore[arg-type]
                    message=f"Unknown command: '{command}'",
                    state_version=self._state_version,
                    error_code="UNKNOWN_COMMAND",
                )

        if command == DroneCommand.ARM:
            return self._handle_arm(command_id)
        elif command == DroneCommand.DISARM:
            return self._handle_disarm(command_id)
        elif command == DroneCommand.TAKEOFF:
            return self._handle_takeoff(command_id)
        elif command == DroneCommand.LAND:
            return self._handle_land(command_id)
        elif command in {
            DroneCommand.MOVE_FORWARD,
            DroneCommand.MOVE_BACKWARD,
            DroneCommand.MOVE_LEFT,
            DroneCommand.MOVE_RIGHT,
            DroneCommand.MOVE_UP,
            DroneCommand.MOVE_DOWN,
        }:
            return self._handle_move(command, distance_meters, command_id)
        elif command == DroneCommand.STOP:
            return self._handle_stop(command_id)
        elif command == DroneCommand.EMERGENCY_STOP:
            return self._handle_emergency_stop(command_id)
        else:
            return CommandResult(
                success=False,
                command=command,
                message=f"Unhandled command: {command.value}",
                state_version=self._state_version,
                error_code="UNHANDLED_COMMAND",
            )

    # --- Internal Command Handlers ---

    def _handle_arm(self, command_id: Optional[str]) -> CommandResult:
        if self._fsm.current_state != FlightState.DISARMED:
            return CommandResult(
                success=False,
                command=DroneCommand.ARM,
                message=f"Cannot ARM while in state {self._fsm.current_state.value}. Must be DISARMED.",
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )
        if self._battery_level <= LOW_BATTERY_THRESHOLD:
            return CommandResult(
                success=False,
                command=DroneCommand.ARM,
                message=f"Cannot ARM with battery at {self._battery_level:.1f}% (must be > {LOW_BATTERY_THRESHOLD}%).",
                state_version=self._state_version,
                error_code="BATTERY_LOW",
            )

        # Transition state
        trans = self._fsm.transition_to(FlightState.ARMED, reason="Manual ARM command")
        if not trans.success:
            return CommandResult(
                success=False,
                command=DroneCommand.ARM,
                message=trans.reason,
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        self._armed = True
        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=DroneCommand.ARM,
            message="Drone armed successfully.",
            state_version=self._state_version,
        )

    def _handle_disarm(self, command_id: Optional[str]) -> CommandResult:
        if self._fsm.is_airborne and self._y > 0.0:
            return CommandResult(
                success=False,
                command=DroneCommand.DISARM,
                message=f"Mid-air disarm prohibited! Drone is at altitude {self._y:.1f}m in state {self._fsm.current_state.value}.",
                state_version=self._state_version,
                error_code="PROHIBITED_ACTION",
            )

        if not self._fsm.can_transition(FlightState.DISARMED):
            return CommandResult(
                success=False,
                command=DroneCommand.DISARM,
                message=f"Cannot DISARM from state {self._fsm.current_state.value}.",
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        trans = self._fsm.transition_to(FlightState.DISARMED, reason="Manual DISARM command")
        if not trans.success:
            return CommandResult(
                success=False,
                command=DroneCommand.DISARM,
                message=trans.reason,
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        self._armed = False
        self._speed = 0.0
        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=DroneCommand.DISARM,
            message="Drone disarmed successfully.",
            state_version=self._state_version,
        )

    def _handle_takeoff(self, command_id: Optional[str]) -> CommandResult:
        if self._fsm.current_state != FlightState.ARMED:
            return CommandResult(
                success=False,
                command=DroneCommand.TAKEOFF,
                message=f"Cannot TAKEOFF from state {self._fsm.current_state.value}. Drone must be ARMED.",
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )
        if self._battery_level <= LOW_BATTERY_THRESHOLD:
            return CommandResult(
                success=False,
                command=DroneCommand.TAKEOFF,
                message=f"Cannot TAKEOFF with battery at {self._battery_level:.1f}%.",
                state_version=self._state_version,
                error_code="BATTERY_LOW",
            )

        # Transition: ARMED -> TAKING_OFF -> HOVERING
        trans1 = self._fsm.transition_to(FlightState.TAKING_OFF, reason="Initiate takeoff climb")
        if not trans1.success:
            return CommandResult(
                success=False,
                command=DroneCommand.TAKEOFF,
                message=trans1.reason,
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        # Ascend to takeoff altitude
        self._y = self._takeoff_altitude
        self._battery_level = max(0.0, self._battery_level - TAKEOFF_BATTERY_BURN_PERCENT)

        trans2 = self._fsm.transition_to(FlightState.HOVERING, reason="Takeoff altitude reached")
        if not trans2.success:
            # Rollback if secondary transition fails
            self._fsm.reset(FlightState.ARMED)
            self._y = 0.0
            return CommandResult(
                success=False,
                command=DroneCommand.TAKEOFF,
                message=trans2.reason,
                state_version=self._state_version,
                error_code="TRANSITION_FAILED",
            )

        self._speed = 0.0
        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=DroneCommand.TAKEOFF,
            message=f"Takeoff successful. Drone hovering at altitude {self._y:.1f}m.",
            state_version=self._state_version,
        )

    def _handle_land(self, command_id: Optional[str]) -> CommandResult:
        if self._fsm.current_state not in {FlightState.HOVERING, FlightState.MOVING}:
            return CommandResult(
                success=False,
                command=DroneCommand.LAND,
                message=f"Cannot LAND from state {self._fsm.current_state.value}.",
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        trans1 = self._fsm.transition_to(FlightState.LANDING, reason="Initiate landing descent")
        if not trans1.success:
            return CommandResult(
                success=False,
                command=DroneCommand.LAND,
                message=trans1.reason,
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        # Descend to ground level
        self._y = 0.0
        self._speed = 0.0

        # Touchdown transition to ARMED
        trans2 = self._fsm.transition_to(FlightState.ARMED, reason="Touchdown reached")
        if not trans2.success:
            return CommandResult(
                success=False,
                command=DroneCommand.LAND,
                message=trans2.reason,
                state_version=self._state_version,
                error_code="TRANSITION_FAILED",
            )

        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=DroneCommand.LAND,
            message="Landing successful. Drone landed on ground and armed.",
            state_version=self._state_version,
        )

    def _handle_move(
        self,
        command: DroneCommand,
        distance_meters: Optional[float],
        command_id: Optional[str],
    ) -> CommandResult:
        step = self._default_step_distance if distance_meters is None else distance_meters

        # Validate step parameter
        if not (math.isfinite(step) and step > 0.0):
            return CommandResult(
                success=False,
                command=command,
                message=f"Movement distance must be a positive finite number. Got {step}",
                state_version=self._state_version,
                error_code="INVALID_PARAMETER",
            )

        # Check flight state: Must be airborne to move horizontally
        if self._fsm.current_state not in {FlightState.HOVERING, FlightState.MOVING}:
            return CommandResult(
                success=False,
                command=command,
                message=f"Cannot move horizontally in state {self._fsm.current_state.value}. Must be HOVERING.",
                state_version=self._state_version,
                error_code="INVALID_STATE_TRANSITION",
            )

        # Check battery limit
        if self._battery_level <= LOW_BATTERY_THRESHOLD:
            return CommandResult(
                success=False,
                command=command,
                message=f"Horizontal movement rejected: battery is low ({self._battery_level:.1f}% <= {LOW_BATTERY_THRESHOLD}%).",
                state_version=self._state_version,
                error_code="BATTERY_LOW",
            )

        # Compute proposed target position and heading based on command
        target_x = self._x
        target_y = self._y
        target_z = self._z
        target_heading = self._heading

        if command == DroneCommand.MOVE_FORWARD:
            target_z += step
            target_heading = 0.0  # North (+Z)
        elif command == DroneCommand.MOVE_BACKWARD:
            target_z -= step
            target_heading = 180.0  # South (-Z)
        elif command == DroneCommand.MOVE_LEFT:
            target_x -= step
            target_heading = 270.0  # West (-X)
        elif command == DroneCommand.MOVE_RIGHT:
            target_x += step
            target_heading = 90.0  # East (+X)
        elif command == DroneCommand.MOVE_UP:
            target_y += step
            # Heading is unchanged during vertical movement
        elif command == DroneCommand.MOVE_DOWN:
            target_y -= step
            # Heading is unchanged during vertical movement

        # Validate geofence boundaries strictly
        if not (GEOFENCE_X_MIN <= target_x <= GEOFENCE_X_MAX):
            return CommandResult(
                success=False,
                command=command,
                message=(
                    f"Command rejected: target X={target_x:.2f}m exceeds geofence "
                    f"[{GEOFENCE_X_MIN}m, {GEOFENCE_X_MAX}m]."
                ),
                state_version=self._state_version,
                error_code="BOUNDARY_LIMIT_EXCEEDED",
            )
        if not (GEOFENCE_Z_MIN <= target_z <= GEOFENCE_Z_MAX):
            return CommandResult(
                success=False,
                command=command,
                message=(
                    f"Command rejected: target Z={target_z:.2f}m exceeds geofence "
                    f"[{GEOFENCE_Z_MIN}m, {GEOFENCE_Z_MAX}m]."
                ),
                state_version=self._state_version,
                error_code="BOUNDARY_LIMIT_EXCEEDED",
            )
        if not (GEOFENCE_Y_MIN < target_y <= GEOFENCE_Y_MAX):
            return CommandResult(
                success=False,
                command=command,
                message=(
                    f"Command rejected: target altitude Y={target_y:.2f}m exceeds geofence "
                    f"({GEOFENCE_Y_MIN}m, {GEOFENCE_Y_MAX}m]."
                ),
                state_version=self._state_version,
                error_code="BOUNDARY_LIMIT_EXCEEDED",
            )

        # Apply state transition through MOVING to HOVERING upon step completion
        if self._fsm.current_state != FlightState.MOVING:
            trans1 = self._fsm.transition_to(FlightState.MOVING, reason=f"Executing {command.value}")
            if not trans1.success:
                return CommandResult(
                    success=False,
                    command=command,
                    message=trans1.reason,
                    state_version=self._state_version,
                    error_code="INVALID_STATE_TRANSITION",
                )

        # Update authoritative state vector
        self._x = target_x
        self._y = target_y
        self._z = target_z
        self._heading = target_heading
        self._speed = 0.0  # Discrete stepped model stabilizes to hover

        # Calculate movement battery burn
        burn = step * MOVEMENT_BURN_PERCENT_PER_METER
        self._battery_level = max(0.0, self._battery_level - burn)

        # Return to HOVERING after step
        self._fsm.transition_to(FlightState.HOVERING, reason="Step displacement completed")

        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=command,
            message=f"{command.value} executed. Position: ({self._x:.1f}, {self._y:.1f}, {self._z:.1f})m.",
            state_version=self._state_version,
        )

    def _handle_stop(self, command_id: Optional[str]) -> CommandResult:
        if self._fsm.current_state in {FlightState.MOVING, FlightState.HOVERING}:
            self._fsm.transition_to(FlightState.HOVERING, reason="Manual STOP command")
            self._speed = 0.0
            self._last_command_id = command_id
            self._last_update_timestamp = self._clock()
            self._state_version += 1
            return CommandResult(
                success=True,
                command=DroneCommand.STOP,
                message="Drone stopped. Hovering in place.",
                state_version=self._state_version,
            )

        return CommandResult(
            success=False,
            command=DroneCommand.STOP,
            message=f"Cannot STOP from state {self._fsm.current_state.value}.",
            state_version=self._state_version,
            error_code="INVALID_STATE_TRANSITION",
        )

    def _handle_emergency_stop(self, command_id: Optional[str]) -> CommandResult:
        if not self._fsm.is_airborne and self._y == 0.0:
            # Already on ground; ensure disarmed
            self._armed = False
            self._fsm.reset(FlightState.DISARMED)
            self._last_command_id = command_id
            self._last_update_timestamp = self._clock()
            self._state_version += 1
            return CommandResult(
                success=True,
                command=DroneCommand.EMERGENCY_STOP,
                message="Emergency stop confirmed on ground. Drone disarmed.",
                state_version=self._state_version,
            )

        # Airborne emergency descent
        self._fsm.transition_to(FlightState.EMERGENCY_LANDING, reason="Emergency stop initiated")
        self._y = 0.0
        self._speed = 0.0
        self._armed = False
        self._fsm.transition_to(FlightState.DISARMED, reason="Emergency landing touchdown")

        self._last_command_id = command_id
        self._last_update_timestamp = self._clock()
        self._state_version += 1

        return CommandResult(
            success=True,
            command=DroneCommand.EMERGENCY_STOP,
            message="Emergency landing executed. Drone landed at ground level and disarmed.",
            state_version=self._state_version,
        )

    # --- Simulation Tick & Idle Depletion ---

    def tick(self, dt: float) -> None:
        """Advance simulation clock by dt seconds.
        
        Handles idle battery depletion and critical battery emergency failsafes.
        """
        if not (math.isfinite(dt) and dt > 0.0):
            return

        self._last_update_timestamp = self._clock()

        # Idle battery burn applies when armed or in flight
        if self._armed or self._fsm.is_airborne:
            idle_burn = dt * IDLE_BURN_PERCENT_PER_SECOND
            self._battery_level = max(0.0, self._battery_level - idle_burn)

        # Critical battery failsafe trigger
        if self._battery_level <= CRITICAL_BATTERY_THRESHOLD and self._fsm.is_airborne:
            self._fsm.transition_to(FlightState.EMERGENCY_LANDING, reason="Critical battery failsafe")
            self._y = 0.0
            self._speed = 0.0
            self._armed = False
            self._fsm.transition_to(FlightState.DISARMED, reason="Failsafe touchdown")
            self._state_version += 1

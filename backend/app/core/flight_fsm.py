"""Authoritative flight state machine for drone simulation.

Implements states and valid transitions strictly according to docs/requirements.md (FR-A.4).
Decoupled from web frameworks, HTTP codes, and networking.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FlightState(str, Enum):
    """Enumeration of all valid flight states for the virtual drone."""

    DISARMED = "DISARMED"
    ARMED = "ARMED"
    TAKING_OFF = "TAKING_OFF"
    HOVERING = "HOVERING"
    MOVING = "MOVING"
    LANDING = "LANDING"
    EMERGENCY_LANDING = "EMERGENCY_LANDING"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class TransitionResult:
    """Represents the outcome of a state transition attempt.
    
    Attributes:
        success: True if transition was accepted, False if rejected.
        from_state: State of the FSM prior to transition attempt.
        to_state: Target state requested (if success=True, this is current_state).
        reason: Explanatory message for success or rejection.
    """

    success: bool
    from_state: FlightState
    to_state: FlightState
    reason: str


class IllegalStateTransitionError(ValueError):
    """Raised when an illegal flight state transition is attempted in strict mode."""

    def __init__(self, from_state: FlightState, to_state: FlightState, message: str = "") -> None:
        self.from_state = from_state
        self.to_state = to_state
        base_msg = f"Illegal flight state transition from {from_state.value} to {to_state.value}."
        full_msg = f"{base_msg} {message}".strip() if message else base_msg
        super().__init__(full_msg)


class FlightFSM:
    """Finite State Machine governing drone flight phases and safety interlocks.
    
    Valid transition map (strictly adheres to FR-A.4):
        DISARMED           -> ARMED
        ARMED              -> DISARMED, TAKING_OFF
        TAKING_OFF         -> HOVERING, EMERGENCY_LANDING
        HOVERING           -> MOVING, LANDING, EMERGENCY_LANDING, HOVERING (idempotent STOP)
        MOVING             -> HOVERING, LANDING, EMERGENCY_LANDING, MOVING (continuous step)
        LANDING            -> ARMED (touchdown), DISARMED (touchdown + disarm), EMERGENCY_LANDING
        EMERGENCY_LANDING  -> DISARMED (touchdown)
    """

    # Mapping of source state to allowed target states
    VALID_TRANSITIONS: dict[FlightState, frozenset[FlightState]] = {
        FlightState.DISARMED: frozenset({FlightState.ARMED}),
        FlightState.ARMED: frozenset({FlightState.DISARMED, FlightState.TAKING_OFF}),
        FlightState.TAKING_OFF: frozenset({FlightState.HOVERING, FlightState.EMERGENCY_LANDING}),
        FlightState.HOVERING: frozenset(
            {
                FlightState.MOVING,
                FlightState.LANDING,
                FlightState.EMERGENCY_LANDING,
                FlightState.HOVERING,  # Idempotent STOP / hold
            }
        ),
        FlightState.MOVING: frozenset(
            {
                FlightState.HOVERING,
                FlightState.LANDING,
                FlightState.EMERGENCY_LANDING,
                FlightState.MOVING,  # Subsequent move step
            }
        ),
        FlightState.LANDING: frozenset(
            {
                FlightState.ARMED,
                FlightState.DISARMED,
                FlightState.EMERGENCY_LANDING,
            }
        ),
        FlightState.EMERGENCY_LANDING: frozenset({FlightState.DISARMED}),
    }

    def __init__(self, initial_state: FlightState = FlightState.DISARMED) -> None:
        if not isinstance(initial_state, FlightState):
            raise TypeError(f"initial_state must be a FlightState enum. Got {type(initial_state).__name__}")
        self._current_state: FlightState = initial_state

    @property
    def current_state(self) -> FlightState:
        """Return the current authoritative flight state."""
        return self._current_state

    @property
    def is_airborne(self) -> bool:
        """Return True if the drone is in an airborne phase."""
        return self._current_state in {
            FlightState.TAKING_OFF,
            FlightState.HOVERING,
            FlightState.MOVING,
            FlightState.LANDING,
            FlightState.EMERGENCY_LANDING,
        }

    @property
    def is_grounded(self) -> bool:
        """Return True if the drone is on the ground."""
        return self._current_state in {FlightState.DISARMED, FlightState.ARMED}

    def get_valid_transitions(self) -> frozenset[FlightState]:
        """Return the set of valid states reachable from the current state."""
        return self.VALID_TRANSITIONS.get(self._current_state, frozenset())

    def can_transition(self, target_state: FlightState) -> bool:
        """Check whether transitioning to target_state is permitted without mutating state."""
        if not isinstance(target_state, FlightState):
            return False
        return target_state in self.get_valid_transitions()

    def transition_to(self, target_state: FlightState, reason: str = "") -> TransitionResult:
        """Attempt to transition to target_state.
        
        If valid:
            Mutates current_state and returns TransitionResult(success=True).
        If invalid:
            Preserves current_state and returns TransitionResult(success=False).
        """
        if not isinstance(target_state, FlightState):
            return TransitionResult(
                success=False,
                from_state=self._current_state,
                to_state=target_state,  # type: ignore[arg-type]
                reason=f"Target state must be a FlightState enum, got {type(target_state).__name__}",
            )

        from_state = self._current_state

        if not self.can_transition(target_state):
            valid_targets = ", ".join(s.value for s in self.get_valid_transitions())
            err_msg = (
                f"Prohibited transition from {from_state.value} to {target_state.value}. "
                f"Valid transitions from {from_state.value} are: [{valid_targets}]."
            )
            return TransitionResult(
                success=False,
                from_state=from_state,
                to_state=target_state,
                reason=err_msg,
            )

        # Apply state transition
        self._current_state = target_state
        success_msg = f"Transitioned from {from_state.value} to {target_state.value}."
        if reason:
            success_msg = f"{success_msg} ({reason})"

        return TransitionResult(
            success=True,
            from_state=from_state,
            to_state=target_state,
            reason=success_msg,
        )

    def transition_to_or_raise(self, target_state: FlightState, reason: str = "") -> TransitionResult:
        """Attempt transition, raising IllegalStateTransitionError if transition is prohibited."""
        result = self.transition_to(target_state, reason=reason)
        if not result.success:
            raise IllegalStateTransitionError(
                from_state=result.from_state,
                to_state=result.to_state,
                message=result.reason,
            )
        return result

    def reset(self, state: FlightState = FlightState.DISARMED) -> None:
        """Reset the FSM to a specific state (default DISARMED)."""
        if not isinstance(state, FlightState):
            raise TypeError(f"state must be a FlightState enum. Got {type(state).__name__}")
        self._current_state = state

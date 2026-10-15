"""Unit tests for the FlightFSM state machine."""

import pytest

from backend.app.core.flight_fsm import (
    FlightFSM,
    FlightState,
    IllegalStateTransitionError,
    TransitionResult,
)


@pytest.fixture
def fsm() -> FlightFSM:
    return FlightFSM()


def test_initial_state_is_disarmed(fsm: FlightFSM):
    assert fsm.current_state == FlightState.DISARMED
    assert fsm.is_grounded is True
    assert fsm.is_airborne is False


def test_custom_initial_state():
    custom_fsm = FlightFSM(initial_state=FlightState.ARMED)
    assert custom_fsm.current_state == FlightState.ARMED


def test_invalid_initial_state_type():
    with pytest.raises(TypeError):
        FlightFSM(initial_state="NOT_AN_ENUM")  # type: ignore


@pytest.mark.parametrize(
    "from_state, to_state",
    [
        (FlightState.DISARMED, FlightState.ARMED),
        (FlightState.ARMED, FlightState.DISARMED),
        (FlightState.ARMED, FlightState.TAKING_OFF),
        (FlightState.TAKING_OFF, FlightState.HOVERING),
        (FlightState.TAKING_OFF, FlightState.EMERGENCY_LANDING),
        (FlightState.HOVERING, FlightState.MOVING),
        (FlightState.HOVERING, FlightState.LANDING),
        (FlightState.HOVERING, FlightState.EMERGENCY_LANDING),
        (FlightState.HOVERING, FlightState.HOVERING),
        (FlightState.MOVING, FlightState.HOVERING),
        (FlightState.MOVING, FlightState.LANDING),
        (FlightState.MOVING, FlightState.EMERGENCY_LANDING),
        (FlightState.MOVING, FlightState.MOVING),
        (FlightState.LANDING, FlightState.ARMED),
        (FlightState.LANDING, FlightState.DISARMED),
        (FlightState.LANDING, FlightState.EMERGENCY_LANDING),
        (FlightState.EMERGENCY_LANDING, FlightState.DISARMED),
    ],
)
def test_all_legal_transitions(from_state: FlightState, to_state: FlightState):
    """Every allowed transition defined in FR-A.4 must succeed and update current_state."""
    fsm = FlightFSM(initial_state=from_state)
    assert fsm.can_transition(to_state) is True

    result = fsm.transition_to(to_state, reason="Test transition")
    assert isinstance(result, TransitionResult)
    assert result.success is True
    assert result.from_state == from_state
    assert result.to_state == to_state
    assert fsm.current_state == to_state


@pytest.mark.parametrize(
    "from_state, to_state",
    [
        (FlightState.DISARMED, FlightState.TAKING_OFF),     # Cannot takeoff while disarmed
        (FlightState.DISARMED, FlightState.HOVERING),       # Cannot teleport to hover
        (FlightState.DISARMED, FlightState.MOVING),         # Cannot move while disarmed
        (FlightState.DISARMED, FlightState.LANDING),        # Already landed
        (FlightState.ARMED, FlightState.MOVING),            # Must takeoff before moving
        (FlightState.ARMED, FlightState.HOVERING),          # Must takeoff before hovering
        (FlightState.HOVERING, FlightState.DISARMED),       # Mid-air disarm prohibited!
        (FlightState.MOVING, FlightState.DISARMED),         # Mid-air disarm prohibited!
        (FlightState.MOVING, FlightState.ARMED),            # Cannot land directly to armed without landing phase
        (FlightState.TAKING_OFF, FlightState.DISARMED),     # Cannot disarm during takeoff
        (FlightState.EMERGENCY_LANDING, FlightState.HOVERING), # Cannot abort emergency landing to hover
        (FlightState.EMERGENCY_LANDING, FlightState.MOVING),   # Cannot move during emergency landing
        (FlightState.EMERGENCY_LANDING, FlightState.ARMED),    # Must disarm upon emergency touchdown
    ],
)
def test_prohibited_transitions_rejected_and_state_preserved(
    from_state: FlightState, to_state: FlightState
):
    """Prohibited transitions must fail and preserve the current state without mutation."""
    fsm = FlightFSM(initial_state=from_state)
    assert fsm.can_transition(to_state) is False

    result = fsm.transition_to(to_state)
    assert result.success is False
    assert result.from_state == from_state
    assert result.to_state == to_state
    assert fsm.current_state == from_state  # INVARIANT: State must NOT change


def test_transition_to_or_raise():
    """transition_to_or_raise must succeed for legal transitions and raise for illegal ones."""
    fsm = FlightFSM(initial_state=FlightState.ARMED)
    result = fsm.transition_to_or_raise(FlightState.TAKING_OFF)
    assert result.success is True
    assert fsm.current_state == FlightState.TAKING_OFF

    with pytest.raises(IllegalStateTransitionError) as exc_info:
        fsm.transition_to_or_raise(FlightState.DISARMED)
    assert exc_info.value.from_state == FlightState.TAKING_OFF
    assert exc_info.value.to_state == FlightState.DISARMED
    assert fsm.current_state == FlightState.TAKING_OFF


def test_airborne_and_grounded_properties():
    fsm = FlightFSM()
    
    assert fsm.is_grounded is True
    assert fsm.is_airborne is False

    fsm.transition_to(FlightState.ARMED)
    assert fsm.is_grounded is True
    assert fsm.is_airborne is False

    fsm.transition_to(FlightState.TAKING_OFF)
    assert fsm.is_grounded is False
    assert fsm.is_airborne is True

    fsm.transition_to(FlightState.HOVERING)
    assert fsm.is_grounded is False
    assert fsm.is_airborne is True

    fsm.transition_to(FlightState.MOVING)
    assert fsm.is_grounded is False
    assert fsm.is_airborne is True

    fsm.transition_to(FlightState.LANDING)
    assert fsm.is_grounded is False
    assert fsm.is_airborne is True

    fsm.transition_to(FlightState.ARMED)
    assert fsm.is_grounded is True
    assert fsm.is_airborne is False


def test_fsm_reset():
    fsm = FlightFSM(initial_state=FlightState.HOVERING)
    fsm.reset(FlightState.DISARMED)
    assert fsm.current_state == FlightState.DISARMED


def test_invalid_target_type(fsm: FlightFSM):
    result = fsm.transition_to("INVALID_TYPE")  # type: ignore
    assert result.success is False
    assert fsm.current_state == FlightState.DISARMED

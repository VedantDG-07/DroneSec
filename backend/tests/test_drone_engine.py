"""Unit tests for the DroneEngine authoritative simulation core."""

import math
import pytest

from backend.app.core.drone_engine import (
    DroneCommand,
    DroneEngine,
    DroneStateSnapshot,
    CommandResult,
    GEOFENCE_X_MAX,
    GEOFENCE_X_MIN,
    GEOFENCE_Z_MAX,
    GEOFENCE_Z_MIN,
    DEFAULT_STEP_DISTANCE_METERS,
    DEFAULT_TAKEOFF_ALTITUDE_METERS,
    TAKEOFF_BATTERY_BURN_PERCENT,
    MOVEMENT_BURN_PERCENT_PER_METER,
    LOW_BATTERY_THRESHOLD,
    CRITICAL_BATTERY_THRESHOLD,
)
from backend.app.core.flight_fsm import FlightState


@pytest.fixture
def engine() -> DroneEngine:
    return DroneEngine()


@pytest.fixture
def airborne_engine() -> DroneEngine:
    """Fixture providing a drone armed and hovering at takeoff altitude."""
    eng = DroneEngine()
    eng.execute_command(DroneCommand.ARM)
    eng.execute_command(DroneCommand.TAKEOFF)
    return eng


def test_initial_state(engine: DroneEngine):
    """Initial drone state must strictly match blueprint specifications."""
    assert engine.state_version == 0
    assert engine.flight_state == FlightState.DISARMED
    assert engine.armed is False
    assert engine.x == 0.0
    assert engine.y == 0.0
    assert engine.z == 0.0
    assert engine.heading == 0.0
    assert engine.speed == 0.0
    assert engine.battery_level == 100.0

    snapshot = engine.get_state_snapshot()
    assert isinstance(snapshot, DroneStateSnapshot)
    assert snapshot.state_version == 0
    assert snapshot.flight_state == FlightState.DISARMED
    assert snapshot.armed is False
    assert snapshot.x == 0.0
    assert snapshot.y == 0.0
    assert snapshot.z == 0.0


def test_standard_flight_lifecycle(engine: DroneEngine):
    """Test full operational lifecycle: ARM -> TAKEOFF -> MOVE -> LAND -> DISARM."""
    # 1. ARM
    res_arm = engine.execute_command(DroneCommand.ARM)
    assert res_arm.success is True
    assert engine.flight_state == FlightState.ARMED
    assert engine.armed is True
    assert engine.state_version == 1

    # 2. TAKEOFF
    res_to = engine.execute_command(DroneCommand.TAKEOFF)
    assert res_to.success is True
    assert engine.flight_state == FlightState.HOVERING
    assert engine.y == DEFAULT_TAKEOFF_ALTITUDE_METERS
    assert engine.battery_level == 100.0 - TAKEOFF_BATTERY_BURN_PERCENT
    assert engine.state_version == 2

    # 3. MOVE_FORWARD (default 2.0m)
    res_mv = engine.execute_command(DroneCommand.MOVE_FORWARD)
    assert res_mv.success is True
    assert engine.z == 2.0
    assert engine.heading == 0.0  # North
    assert engine.flight_state == FlightState.HOVERING
    assert engine.state_version == 3

    # 4. LAND
    res_land = engine.execute_command(DroneCommand.LAND)
    assert res_land.success is True
    assert engine.y == 0.0
    assert engine.flight_state == FlightState.ARMED
    assert engine.state_version == 4

    # 5. DISARM
    res_disarm = engine.execute_command(DroneCommand.DISARM)
    assert res_disarm.success is True
    assert engine.flight_state == FlightState.DISARMED
    assert engine.armed is False
    assert engine.state_version == 5


@pytest.mark.parametrize(
    "command, expected_dx, expected_dz, expected_heading",
    [
        (DroneCommand.MOVE_FORWARD, 0.0, 2.0, 0.0),      # North: +Z, 0 deg
        (DroneCommand.MOVE_BACKWARD, 0.0, -2.0, 180.0),  # South: -Z, 180 deg
        (DroneCommand.MOVE_LEFT, -2.0, 0.0, 270.0),      # West: -X, 270 deg
        (DroneCommand.MOVE_RIGHT, 2.0, 0.0, 90.0),       # East: +X, 90 deg
    ],
)
def test_movement_in_all_directions(
    airborne_engine: DroneEngine,
    command: DroneCommand,
    expected_dx: float,
    expected_dz: float,
    expected_heading: float,
):
    """Verify displacement and heading orientation for all 4 horizontal directions."""
    initial_x = airborne_engine.x
    initial_z = airborne_engine.z

    result = airborne_engine.execute_command(command, distance_meters=2.0)
    assert result.success is True
    assert airborne_engine.x == pytest.approx(initial_x + expected_dx, abs=1e-6)
    assert airborne_engine.z == pytest.approx(initial_z + expected_dz, abs=1e-6)
    assert airborne_engine.heading == expected_heading


def test_movement_custom_distance(airborne_engine: DroneEngine):
    """Custom distance parameters must be applied accurately."""
    result = airborne_engine.execute_command(DroneCommand.MOVE_RIGHT, distance_meters=10.5)
    assert result.success is True
    assert airborne_engine.x == pytest.approx(10.5, abs=1e-6)
    assert airborne_engine.heading == 90.0


def test_movement_while_landed_prohibited(engine: DroneEngine):
    """Movement while landed (DISARMED or ARMED on ground) must be strictly rejected."""
    # Attempt move while DISARMED
    res1 = engine.execute_command(DroneCommand.MOVE_FORWARD)
    assert res1.success is False
    assert res1.error_code == "INVALID_STATE_TRANSITION"
    assert engine.z == 0.0

    # Arm drone on ground, then attempt move
    engine.execute_command(DroneCommand.ARM)
    res2 = engine.execute_command(DroneCommand.MOVE_FORWARD)
    assert res2.success is False
    assert res2.error_code == "INVALID_STATE_TRANSITION"
    assert engine.z == 0.0


@pytest.mark.parametrize(
    "invalid_distance",
    [-1.0, 0.0, -50.0, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_movement_parameters_rejected(airborne_engine: DroneEngine, invalid_distance: float):
    """Non-positive or non-finite distance parameters must fail validation with state preserved."""
    initial_v = airborne_engine.state_version
    initial_x = airborne_engine.x

    res = airborne_engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=invalid_distance)
    assert res.success is False
    assert res.error_code == "INVALID_PARAMETER"
    assert airborne_engine.state_version == initial_v
    assert airborne_engine.x == initial_x


def test_geofence_boundaries_enforced(airborne_engine: DroneEngine):
    """Commands that would breach the [-100, 100] horizontal envelope must be rejected."""
    # Move to near boundary
    res1 = airborne_engine.execute_command(DroneCommand.MOVE_RIGHT, distance_meters=99.0)
    assert res1.success is True
    assert airborne_engine.x == 99.0
    v1 = airborne_engine.state_version

    # Attempt move that would push X to 101.0 (exceeds 100.0)
    res2 = airborne_engine.execute_command(DroneCommand.MOVE_RIGHT, distance_meters=2.0)
    assert res2.success is False
    assert res2.error_code == "BOUNDARY_LIMIT_EXCEEDED"
    assert airborne_engine.x == 99.0  # Unchanged!
    assert airborne_engine.state_version == v1  # Not incremented!

    # Attempt move that would push Z past 100.0
    res3 = airborne_engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=101.0)
    assert res3.success is False
    assert res3.error_code == "BOUNDARY_LIMIT_EXCEEDED"
    assert airborne_engine.z == 0.0
    assert airborne_engine.state_version == v1


def test_battery_depletion_rules(airborne_engine: DroneEngine):
    """Verify takeoff, movement, and idle battery calculations."""
    # airborne_engine has already taken off -> 99.0%
    expected_battery = 100.0 - TAKEOFF_BATTERY_BURN_PERCENT
    assert airborne_engine.battery_level == pytest.approx(expected_battery, abs=1e-6)

    # 10m move -> 10 * 0.1% = 1.0%
    airborne_engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=10.0)
    expected_battery -= 10.0 * MOVEMENT_BURN_PERCENT_PER_METER
    assert airborne_engine.battery_level == pytest.approx(expected_battery, abs=1e-6)

    # Idle tick: 50 seconds at 0.02%/s = 1.0%
    airborne_engine.tick(50.0)
    expected_battery -= 50.0 * 0.02
    assert airborne_engine.battery_level == pytest.approx(expected_battery, abs=1e-6)


def test_low_battery_rejection():
    """Battery <= 15% must prevent arming and prevent horizontal flight."""
    eng = DroneEngine(initial_battery=15.0)

    # Cannot ARM when battery <= 15%
    res_arm = eng.execute_command(DroneCommand.ARM)
    assert res_arm.success is False
    assert res_arm.error_code == "BATTERY_LOW"
    assert eng.armed is False

    # Create airborne drone with 15.5% then drain to 15.0%
    eng_air = DroneEngine(initial_battery=16.5)
    eng_air.execute_command(DroneCommand.ARM)
    eng_air.execute_command(DroneCommand.TAKEOFF)  # Burns 1.0%, now 15.5%

    # Draining 0.5% with 5m move brings battery to 15.0%
    eng_air.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=5.0)
    assert eng_air.battery_level == pytest.approx(15.0, abs=1e-6)

    # Now horizontal movement must be rejected
    res_mv = eng_air.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=1.0)
    assert res_mv.success is False
    assert res_mv.error_code == "BATTERY_LOW"

    # But LAND must still be accepted for safety
    res_land = eng_air.execute_command(DroneCommand.LAND)
    assert res_land.success is True
    assert eng_air.y == 0.0


def test_critical_battery_failsafe(airborne_engine: DroneEngine):
    """When battery drops to <= 5.0%, simulation tick must trigger emergency landing."""
    # Force battery to 5.0%
    airborne_engine._battery_level = 5.0
    airborne_engine.tick(0.1)

    assert airborne_engine.flight_state == FlightState.DISARMED
    assert airborne_engine.y == 0.0
    assert airborne_engine.armed is False


def test_emergency_stop(airborne_engine: DroneEngine):
    """EMERGENCY_STOP while airborne must immediately force touchdown and disarm."""
    res = airborne_engine.execute_command(DroneCommand.EMERGENCY_STOP)
    assert res.success is True
    assert airborne_engine.y == 0.0
    assert airborne_engine.armed is False
    assert airborne_engine.flight_state == FlightState.DISARMED


def test_atomic_rejection_invariant_across_all_failure_modes(airborne_engine: DroneEngine):
    """CRITICAL INVARIANT: Any rejected command must leave the authoritative state 100% unchanged."""
    initial_snapshot = airborne_engine.get_state_snapshot()

    # Case 1: Prohibited state transition (cannot takeoff while already hovering)
    res1 = airborne_engine.execute_command(DroneCommand.TAKEOFF)
    assert res1.success is False
    assert airborne_engine.get_state_snapshot() == initial_snapshot

    # Case 2: Geofence violation
    res2 = airborne_engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=500.0)
    assert res2.success is False
    assert airborne_engine.get_state_snapshot() == initial_snapshot

    # Case 3: Invalid parameter (negative distance)
    res3 = airborne_engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=-10.0)
    assert res3.success is False
    assert airborne_engine.get_state_snapshot() == initial_snapshot

    # Case 4: Mid-air disarm attempt
    res4 = airborne_engine.execute_command(DroneCommand.DISARM)
    assert res4.success is False
    assert airborne_engine.get_state_snapshot() == initial_snapshot


def test_command_sequence_repeatability():
    """Identical command sequences executed on two independent engines must yield bitwise identical states."""
    eng1 = DroneEngine()
    eng2 = DroneEngine()

    commands = [
        (DroneCommand.ARM, None),
        (DroneCommand.TAKEOFF, None),
        (DroneCommand.MOVE_FORWARD, 4.0),
        (DroneCommand.MOVE_RIGHT, 6.0),
        (DroneCommand.MOVE_BACKWARD, 2.0),
        (DroneCommand.STOP, None),
        (DroneCommand.MOVE_LEFT, 3.0),
        (DroneCommand.LAND, None),
        (DroneCommand.DISARM, None),
    ]

    for cmd, dist in commands:
        r1 = eng1.execute_command(cmd, distance_meters=dist)
        r2 = eng2.execute_command(cmd, distance_meters=dist)
        assert r1.success == r2.success
        assert r1.state_version == r2.state_version

    s1 = eng1.get_state_snapshot()
    s2 = eng2.get_state_snapshot()

    assert s1.state_version == s2.state_version
    assert s1.flight_state == s2.flight_state
    assert s1.armed == s2.armed
    assert s1.x == s2.x
    assert s1.y == s2.y
    assert s1.z == s2.z
    assert s1.heading == s2.heading
    assert s1.battery_level == s2.battery_level

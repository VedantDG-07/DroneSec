"""Regression tests covering the three confirmed bug fixes.

Bug A - Incorrect command error logs:
    Backend StandardResponse uses { status: "success"|"error" }, not { success: bool }.
    Confirms the HTTP response body shape so the frontend status check is validated.

Bug B - MOVE_UP / MOVE_DOWN UNKNOWN_COMMAND:
    DroneCommand enum now includes MOVE_UP and MOVE_DOWN.
    Vertical movement must obey Y-axis geofence (0, 50]m, battery burn, atomicity,
    and use the 'distance_meters' parameter key.

Bug C - Attack simulator events not appearing in log:
    Attack runs are persisted in attack_runs table and surfaced by LogQueryRepository
    under category='ATTACK'. GET /api/logs must return ATTACK-category entries after
    a scenario completes.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.core.drone_engine import (
    DroneCommand,
    DroneEngine,
    GEOFENCE_Y_MAX,
    GEOFENCE_Y_MIN,
    DEFAULT_TAKEOFF_ALTITUDE_METERS,
    MOVEMENT_BURN_PERCENT_PER_METER,
)
from backend.app.core.flight_fsm import FlightState
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


# ---------------------------------------------------------------------------
# Shared Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_app(tmp_path: Path):
    """Isolated FastAPI app with its own in-memory database for each test."""
    db_file = tmp_path / "regression_test.db"
    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        rate_limit_capacity=100,
        rate_limit_refill_rate=50.0,
        security_mode="UNSECURED",
    )
    db_mgr = DatabaseManager(str(db_file))
    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def airborne_engine() -> DroneEngine:
    """Engine fixture that is armed and hovering."""
    eng = DroneEngine()
    eng.execute_command(DroneCommand.ARM)
    eng.execute_command(DroneCommand.TAKEOFF)
    return eng


# ===========================================================================
# BUG A - Correct response envelope shape
# ===========================================================================

class TestBugA_ResponseEnvelopeShape:
    """Backend must return { status: 'success'|'error' }, never a bare 'success' boolean."""

    def test_successful_command_returns_status_success(self, test_app: TestClient):
        """A valid ARM command must return a JSON body with status == 'success'."""
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "ARM", "client_id": "TEST"},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body, "Response body must have a 'status' field"
        assert body["status"] == "success"
        assert "data" in body
        # No bare 'success' boolean at top level
        assert "success" not in body

    def test_rejected_command_returns_status_error(self, test_app: TestClient):
        """Rejecting a command must return status == 'error' with non-empty code and message."""
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "TAKEOFF", "client_id": "TEST"},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body["status"] == "error"
        assert "error" in body
        err = body["error"]
        assert err.get("code"), "Error body must have a non-empty 'code'"
        assert err.get("message"), "Error body must have a non-empty 'message'"

    def test_drone_state_response_has_status_success(self, test_app: TestClient):
        """GET /api/drone/state must also use the 'status' envelope."""
        resp = test_app.get("/api/drone/state")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert "success" not in body


# ===========================================================================
# BUG B - MOVE_UP / MOVE_DOWN vertical movement
# ===========================================================================

class TestBugB_VerticalMovement:
    """MOVE_UP and MOVE_DOWN must be recognised, execute correctly, and obey all safety rules."""

    def test_move_up_and_down_are_valid_commands(self):
        """DroneCommand enum must include MOVE_UP and MOVE_DOWN."""
        assert hasattr(DroneCommand, "MOVE_UP"), "MOVE_UP missing from DroneCommand enum"
        assert hasattr(DroneCommand, "MOVE_DOWN"), "MOVE_DOWN missing from DroneCommand enum"
        assert DroneCommand("MOVE_UP") == DroneCommand.MOVE_UP
        assert DroneCommand("MOVE_DOWN") == DroneCommand.MOVE_DOWN

    def test_move_up_increases_altitude(self, airborne_engine: DroneEngine):
        """MOVE_UP must increase Y and leave X/Z unchanged."""
        initial_y = airborne_engine.y
        result = airborne_engine.execute_command(DroneCommand.MOVE_UP, distance_meters=3.0)

        assert result.success is True
        assert airborne_engine.y == pytest.approx(initial_y + 3.0, abs=1e-6)
        assert airborne_engine.x == 0.0
        assert airborne_engine.z == 0.0
        assert airborne_engine.flight_state == FlightState.HOVERING

    def test_move_down_decreases_altitude(self, airborne_engine: DroneEngine):
        """MOVE_DOWN must decrease Y."""
        airborne_engine.execute_command(DroneCommand.MOVE_UP, distance_meters=10.0)
        y_before = airborne_engine.y

        result = airborne_engine.execute_command(DroneCommand.MOVE_DOWN, distance_meters=4.0)

        assert result.success is True
        assert airborne_engine.y == pytest.approx(y_before - 4.0, abs=1e-6)

    def test_move_up_respects_geofence_ceiling(self, airborne_engine: DroneEngine):
        """MOVE_UP that would exceed GEOFENCE_Y_MAX must be rejected atomically."""
        airborne_engine.execute_command(DroneCommand.MOVE_UP, distance_meters=44.0)
        assert airborne_engine.y == pytest.approx(49.0, abs=1e-6)
        v_before = airborne_engine.state_version

        result = airborne_engine.execute_command(DroneCommand.MOVE_UP, distance_meters=2.0)

        assert result.success is False
        assert result.error_code == "BOUNDARY_LIMIT_EXCEEDED"
        assert airborne_engine.y == pytest.approx(49.0, abs=1e-6)
        assert airborne_engine.state_version == v_before

    def test_move_down_respects_geofence_floor(self, airborne_engine: DroneEngine):
        """MOVE_DOWN that would push Y to <= 0m must be rejected atomically."""
        v_before = airborne_engine.state_version
        result = airborne_engine.execute_command(DroneCommand.MOVE_DOWN, distance_meters=6.0)

        assert result.success is False
        assert result.error_code == "BOUNDARY_LIMIT_EXCEEDED"
        assert airborne_engine.y == pytest.approx(DEFAULT_TAKEOFF_ALTITUDE_METERS, abs=1e-6)
        assert airborne_engine.state_version == v_before

    def test_vertical_move_burns_battery(self, airborne_engine: DroneEngine):
        """MOVE_UP must deplete battery by step * MOVEMENT_BURN_PERCENT_PER_METER."""
        battery_before = airborne_engine.battery_level
        airborne_engine.execute_command(DroneCommand.MOVE_UP, distance_meters=5.0)
        expected_burn = 5.0 * MOVEMENT_BURN_PERCENT_PER_METER
        assert airborne_engine.battery_level == pytest.approx(battery_before - expected_burn, abs=1e-6)

    def test_vertical_move_while_grounded_is_rejected(self):
        """MOVE_UP/MOVE_DOWN must be rejected when the drone is not airborne."""
        eng = DroneEngine()

        res_up = eng.execute_command(DroneCommand.MOVE_UP, distance_meters=2.0)
        assert res_up.success is False
        assert res_up.error_code == "INVALID_STATE_TRANSITION"

        eng.execute_command(DroneCommand.ARM)
        res_down = eng.execute_command(DroneCommand.MOVE_DOWN, distance_meters=2.0)
        assert res_down.success is False
        assert res_down.error_code == "INVALID_STATE_TRANSITION"

    def test_move_up_via_api_returns_status_success(self, test_app: TestClient):
        """POST /api/drone/command MOVE_UP must return 200 and status=='success' when airborne."""
        for cmd in ("ARM", "TAKEOFF"):
            test_app.post(
                "/api/drone/command",
                json={"command": cmd},
                headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
            )
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "MOVE_UP", "parameters": {"distance_meters": 3.0}},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_move_down_via_api_returns_status_success(self, test_app: TestClient):
        """POST /api/drone/command MOVE_DOWN must succeed when there is altitude to descend."""
        for cmd in ("ARM", "TAKEOFF"):
            test_app.post(
                "/api/drone/command",
                json={"command": cmd},
                headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
            )
        test_app.post(
            "/api/drone/command",
            json={"command": "MOVE_UP", "parameters": {"distance_meters": 5.0}},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "MOVE_DOWN", "parameters": {"distance_meters": 3.0}},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_distance_meters_parameter_key_accepted(self, test_app: TestClient):
        """command_service must accept 'distance_meters' (canonical key) for move commands."""
        for cmd in ("ARM", "TAKEOFF"):
            test_app.post(
                "/api/drone/command",
                json={"command": cmd},
                headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
            )
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "MOVE_FORWARD", "parameters": {"distance_meters": 5.0}},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    def test_legacy_distance_parameter_key_accepted(self, test_app: TestClient):
        """command_service must still accept the legacy 'distance' key for backward compatibility."""
        for cmd in ("ARM", "TAKEOFF"):
            test_app.post(
                "/api/drone/command",
                json={"command": cmd},
                headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
            )
        resp = test_app.post(
            "/api/drone/command",
            json={"command": "MOVE_FORWARD", "parameters": {"distance": 5.0}},
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"


# ===========================================================================
# BUG C - Attack events persisted and returned by /api/logs
# ===========================================================================

class TestBugC_AttackEventLog:
    """Completed attack scenarios must produce ATTACK-category log entries via GET /api/logs."""

    def test_attack_run_appears_in_api_logs(self, test_app: TestClient):
        """After executing any attack scenario, GET /api/logs must include an ATTACK category entry."""
        resp = test_app.post("/api/attacks/malformed_payload")
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

        logs_resp = test_app.get("/api/logs?limit=100")
        assert logs_resp.status_code == 200
        logs = logs_resp.json()["data"]

        attack_logs = [l for l in logs if l.get("category") == "ATTACK"]
        assert len(attack_logs) >= 1, (
            "At least one ATTACK-category log entry must be present after an attack scenario"
        )

    def test_attack_log_entry_has_required_fields(self, test_app: TestClient):
        """Each ATTACK log entry must include the fields required for the event console."""
        test_app.post("/api/attacks/unauthorized_command",
                      json={"parameters": {"target_command": "ARM"}})

        logs_resp = test_app.get("/api/logs?limit=100")
        logs = logs_resp.json()["data"]
        attack_logs = [l for l in logs if l.get("category") == "ATTACK"]
        assert len(attack_logs) >= 1

        entry = attack_logs[0]
        assert "timestamp" in entry
        assert entry["category"] == "ATTACK"
        assert "severity" in entry
        assert "attack_result" in entry

    def test_attack_log_category_filter_works(self, test_app: TestClient):
        """GET /api/logs?category=ATTACK must return only ATTACK-category entries."""
        test_app.post("/api/attacks/malformed_payload")

        resp = test_app.get("/api/logs?category=ATTACK&limit=50")
        assert resp.status_code == 200
        logs = resp.json()["data"]

        for entry in logs:
            assert entry["category"] == "ATTACK"

    def test_attack_response_envelope_uses_status_field(self, test_app: TestClient):
        """POST /api/attacks/{type} must return { status: 'success', data: {...} }."""
        resp = test_app.post("/api/attacks/malformed_payload")
        assert resp.status_code == 200
        body = resp.json()

        assert body.get("status") == "success"
        assert "data" in body
        assert "success" not in body

    def test_multiple_attack_runs_all_appear_in_log(self, test_app: TestClient):
        """Multiple sequential attack scenarios must each produce a separate log entry."""
        test_app.post("/api/attacks/malformed_payload")
        test_app.post("/api/attacks/unauthorized_command",
                      json={"parameters": {"target_command": "ARM"}})

        logs_resp = test_app.get("/api/logs?limit=100")
        logs = logs_resp.json()["data"]
        attack_logs = [l for l in logs if l.get("category") == "ATTACK"]
        assert len(attack_logs) >= 2

    def test_attack_history_endpoint_returns_records(self, test_app: TestClient):
        """GET /api/attacks/history must return executed scenarios."""
        test_app.post("/api/attacks/malformed_payload")

        resp = test_app.get("/api/attacks/history?limit=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert len(body["data"]) >= 1

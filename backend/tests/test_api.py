"""Integration tests for FastAPI REST endpoints per docs/api-contract.md."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.core.drone_engine import DroneEngine
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


@pytest.fixture
def test_client(tmp_path: Path):
    """Fixture providing a FastAPI TestClient with an isolated temporary database."""
    db_file = tmp_path / "test_api_simulation.db"
    db_mgr = DatabaseManager(str(db_file))
    
    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
    )
    
    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client


def test_health_endpoint(test_client: TestClient):
    """GET /health must return 200 with standard success envelope and operational status."""
    response = test_client.get("/health")
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "success"
    assert "timestamp" in payload

    data = payload["data"]
    assert data["system_status"] == "OPERATIONAL"
    assert data["uptime_seconds"] >= 0.0
    assert data["simulation_loop"]["running"] is True
    assert data["database"]["status"] == "CONNECTED"
    assert data["database"]["wal_mode"] is True


def test_get_initial_drone_state(test_client: TestClient):
    """GET /api/drone/state must return initial authoritative state snapshot."""
    response = test_client.get("/api/drone/state")
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["state_version"] == 0
    assert data["flight_state"] == "DISARMED"
    assert data["armed"] is False
    assert data["position"] == {"x": 0.0, "y": 0.0, "z": 0.0}
    assert data["battery"]["level_percent"] == 100.0
    assert data["battery"]["state_of_health"] == "GOOD"


def test_command_execution_lifecycle(test_client: TestClient):
    """Test standard sequence: ARM -> TAKEOFF -> MOVE_FORWARD -> LAND -> DISARM."""
    # 1. ARM
    res_arm = test_client.post("/api/drone/command", json={"command": "ARM"})
    assert res_arm.status_code == 200
    arm_data = res_arm.json()["data"]
    assert arm_data["command"] == "ARM"
    assert arm_data["execution_status"] == "EXECUTED"
    assert arm_data["state_version_after"] == 1

    # 2. TAKEOFF
    res_to = test_client.post("/api/drone/command", json={"command": "TAKEOFF"})
    assert res_to.status_code == 200
    to_data = res_to.json()["data"]
    assert to_data["execution_status"] == "EXECUTED"
    assert to_data["state_version_after"] == 2
    assert to_data["drone_position"]["y"] == 5.0

    # 3. MOVE_FORWARD
    res_mv = test_client.post(
        "/api/drone/command",
        json={"command": "MOVE_FORWARD", "parameters": {"distance_meters": 4.0}},
    )
    assert res_mv.status_code == 200
    mv_data = res_mv.json()["data"]
    assert mv_data["state_version_after"] == 3
    assert mv_data["drone_position"]["z"] == 4.0

    # 4. LAND
    res_land = test_client.post("/api/drone/command", json={"command": "LAND"})
    assert res_land.status_code == 200
    land_data = res_land.json()["data"]
    assert land_data["drone_position"]["y"] == 0.0
    assert land_data["state_version_after"] == 4

    # 5. DISARM
    res_disarm = test_client.post("/api/drone/command", json={"command": "DISARM"})
    assert res_disarm.status_code == 200
    assert res_disarm.json()["data"]["state_version_after"] == 5


def test_rejected_command_invalid_state_transition(test_client: TestClient):
    """Attempting TAKEOFF while DISARMED must return 400 and preserve state."""
    # Read initial state
    init_state = test_client.get("/api/drone/state").json()["data"]
    assert init_state["state_version"] == 0

    response = test_client.post("/api/drone/command", json={"command": "TAKEOFF"})
    assert response.status_code == 400

    err_payload = response.json()
    assert err_payload["status"] == "error"
    assert err_payload["error"]["code"] == "INVALID_STATE_TRANSITION"

    # Invariant: State version and coordinates must remain untouched
    post_state = test_client.get("/api/drone/state").json()["data"]
    assert post_state["state_version"] == 0
    assert post_state["flight_state"] == "DISARMED"
    assert post_state["position"] == {"x": 0.0, "y": 0.0, "z": 0.0}


def test_rejected_command_geofence_breach(test_client: TestClient):
    """Attempting movement beyond geofence must return 400 BOUNDARY_LIMIT_EXCEEDED."""
    test_client.post("/api/drone/command", json={"command": "ARM"})
    test_client.post("/api/drone/command", json={"command": "TAKEOFF"})
    state_before = test_client.get("/api/drone/state").json()["data"]

    # Exceed boundary
    response = test_client.post(
        "/api/drone/command",
        json={"command": "MOVE_FORWARD", "parameters": {"distance_meters": 500.0}},
    )
    assert response.status_code == 400
    err = response.json()["error"]
    assert err["code"] == "BOUNDARY_LIMIT_EXCEEDED"

    # Assert invariant: position unchanged
    state_after = test_client.get("/api/drone/state").json()["data"]
    assert state_after["state_version"] == state_before["state_version"]
    assert state_after["position"] == state_before["position"]


def test_unknown_command_rejected(test_client: TestClient):
    """Unknown command must return 400 with code UNKNOWN_COMMAND."""
    response = test_client.post("/api/drone/command", json={"command": "DO_A_FLIP"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "UNKNOWN_COMMAND"


def test_extra_fields_rejected_by_schema(test_client: TestClient):
    """Unexpected payload fields must be rejected by Pydantic schema validation (HTTP 422)."""
    response = test_client.post(
        "/api/drone/command",
        json={"command": "ARM", "hacked_field": True},
    )
    assert response.status_code == 422
    err_payload = response.json()
    assert err_payload["status"] == "error"
    assert err_payload["error"]["code"] == "INVALID_SCHEMA"


def test_get_telemetry_buffer(test_client: TestClient):
    """GET /api/drone/telemetry must return rolling telemetry list with limit support."""
    # Execute a command to populate telemetry
    test_client.post("/api/drone/command", json={"command": "ARM"})

    response = test_client.get("/api/drone/telemetry?limit=5")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert isinstance(payload["data"], list)
    assert len(payload["data"]) >= 1


def test_get_logs_endpoint(test_client: TestClient):
    """GET /api/logs must return recorded command executions and support filtering."""
    # Submit one valid and one rejected command
    test_client.post("/api/drone/command", json={"command": "ARM"})
    test_client.post("/api/drone/command", json={"command": "TAKEOFF"}) # rejected (already disarmed? wait, ARM then TAKEOFF is valid)
    test_client.post("/api/drone/command", json={"command": "UNKNOWN"}) # rejected

    response = test_client.get("/api/logs?limit=10")
    assert response.status_code == 200
    logs = response.json()["data"]
    assert len(logs) >= 3

    # Filter by category
    res_cmd = test_client.get("/api/logs?category=COMMAND")
    assert res_cmd.status_code == 200
    for item in res_cmd.json()["data"]:
        assert item["category"] == "COMMAND"


def test_get_security_status_endpoint(test_client: TestClient):
    """GET /api/security/status must return UNSECURED configuration in Phase 2."""
    response = test_client.get("/api/security/status")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["current_mode"] == "UNSECURED"
    assert data["active_key_id"] is None
    assert data["replay_protection"]["enabled"] is False


def test_concurrent_command_submissions(test_client: TestClient):
    """Simultaneous command submissions must be serialized atomically without race conditions."""
    from concurrent.futures import ThreadPoolExecutor

    # Prepare drone: ARM and TAKEOFF
    res1 = test_client.post("/api/drone/command", json={"command": "ARM"})
    res2 = test_client.post("/api/drone/command", json={"command": "TAKEOFF"})
    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res2.json()["data"]["state_version_after"] == 2

    # Issue 10 concurrent MOVE_FORWARD (1.0m each) commands across 5 threads
    def send_move(index: int):
        return test_client.post(
            "/api/drone/command",
            json={"command": "MOVE_FORWARD", "parameters": {"distance_meters": 1.0}},
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        responses = list(executor.map(send_move, range(10)))

    # All 10 commands must succeed
    for r in responses:
        assert r.status_code == 200
        assert r.json()["data"]["execution_status"] == "EXECUTED"

    # All state versions must be distinct and span from 3 to 12
    state_versions = [r.json()["data"]["state_version_after"] for r in responses]
    assert len(set(state_versions)) == 10
    assert sorted(state_versions) == list(range(3, 13))

    # Authoritative state in the engine must match final state version 12 and z = 10.0m
    final_state = test_client.get("/api/drone/state").json()["data"]
    assert final_state["state_version"] == 12
    assert final_state["position"]["z"] == 10.0

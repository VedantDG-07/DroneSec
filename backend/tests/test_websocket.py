"""Integration tests for WebSocket hub and real-time telemetry streaming per docs/api-contract.md."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


@pytest.fixture
def ws_client_fixture(tmp_path: Path):
    """Fixture providing TestClient with an isolated test database and fast tick rate."""
    db_file = tmp_path / "test_ws_simulation.db"
    db_mgr = DatabaseManager(str(db_file))

    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=10.0,  # Prevent periodic ticker from interleaving with command frames
        simulation_tick_rate_hz=20.0,
    )

    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client, app


def test_websocket_connection_and_initial_telemetry(ws_client_fixture):
    """Client must connect successfully and immediately receive baseline telemetry."""
    client, app = ws_client_fixture

    with client.websocket_connect("/ws/telemetry") as ws:
        # Initial frame sent upon connection
        frame = ws.receive_json()
        assert frame["type"] == "TELEMETRY_UPDATE"
        assert "seq" in frame
        assert "timestamp" in frame

        payload = frame["payload"]
        assert payload["state_version"] == 0
        assert payload["flight_state"] == "DISARMED"
        assert payload["x"] == 0.0
        assert payload["y"] == 0.0
        assert payload["z"] == 0.0
        assert payload["battery_percent"] == 100.0


def test_websocket_ping_pong_heartbeat(ws_client_fixture):
    """Client sending PING must receive PONG with timestamp."""
    client, app = ws_client_fixture

    with client.websocket_connect("/ws/telemetry") as ws:
        # Discard initial telemetry frame
        _ = ws.receive_json()

        # Send PING frame
        ws.send_text(json.dumps({"type": "PING", "timestamp": 123456.78}))

        # Wait for PONG
        pong_frame = ws.receive_json()
        assert pong_frame["type"] == "PONG"
        assert "timestamp" in pong_frame


def test_websocket_receives_update_after_successful_command(ws_client_fixture):
    """When a command executes successfully, subscribed WebSocket clients receive updated state."""
    client, app = ws_client_fixture

    with client.websocket_connect("/ws/telemetry") as ws:
        # Read initial baseline frame
        init_frame = ws.receive_json()
        assert init_frame["payload"]["state_version"] == 0

        # Execute ARM command via REST
        res_arm = client.post("/api/drone/command", json={"command": "ARM"})
        assert res_arm.status_code == 200

        # WebSocket must receive TELEMETRY_UPDATE with state_version == 1
        arm_frame = ws.receive_json()
        assert arm_frame["type"] == "TELEMETRY_UPDATE"
        assert arm_frame["payload"]["state_version"] == 1
        assert arm_frame["payload"]["flight_state"] == "ARMED"

        # Execute TAKEOFF command via REST
        res_to = client.post("/api/drone/command", json={"command": "TAKEOFF"})
        assert res_to.status_code == 200

        to_frame = ws.receive_json()
        assert to_frame["payload"]["state_version"] == 2
        assert to_frame["payload"]["flight_state"] == "HOVERING"
        assert to_frame["payload"]["y"] == 5.0


def test_no_false_telemetry_event_on_rejected_command(ws_client_fixture):
    """Rejected commands must NOT emit a state-change event with mutated state version."""
    client, app = ws_client_fixture

    with client.websocket_connect("/ws/telemetry") as ws:
        init_frame = ws.receive_json()
        assert init_frame["payload"]["state_version"] == 0

        # Submit invalid command (cannot TAKEOFF while DISARMED)
        res_err = client.post("/api/drone/command", json={"command": "TAKEOFF"})
        assert res_err.status_code == 400

        # Submit valid command
        client.post("/api/drone/command", json={"command": "ARM"})
        next_frame = ws.receive_json()

        # Next received frame MUST be the ARM event with state_version 1 (NOT from the failed takeoff!)
        assert next_frame["payload"]["state_version"] == 1
        assert next_frame["payload"]["flight_state"] == "ARMED"


def test_multiple_simultaneous_websocket_observers(ws_client_fixture):
    """Multiple WebSocket observers must all receive identical broadcast updates concurrently."""
    client, app = ws_client_fixture

    with client.websocket_connect("/ws/telemetry") as ws1:
        with client.websocket_connect("/ws/telemetry") as ws2:
            # Both get initial telemetry
            f1_init = ws1.receive_json()
            f2_init = ws2.receive_json()
            assert f1_init["payload"]["state_version"] == 0
            assert f2_init["payload"]["state_version"] == 0

            # Execute command
            client.post("/api/drone/command", json={"command": "ARM"})

            f1_arm = ws1.receive_json()
            f2_arm = ws2.receive_json()

            assert f1_arm["payload"]["state_version"] == 1
            assert f2_arm["payload"]["state_version"] == 1
            assert f1_arm["payload"]["flight_state"] == "ARMED"
            assert f2_arm["payload"]["flight_state"] == "ARMED"


def test_websocket_disconnect_cleanup(ws_client_fixture):
    """Disconnecting a client must clean up connection registry without impacting the hub."""
    client, app = ws_client_fixture
    hub = app.state.ws_hub

    initial_count = hub.active_connections_count
    assert initial_count == 0

    with client.websocket_connect("/ws/telemetry") as ws:
        _ = ws.receive_json()
        assert hub.active_connections_count == 1

    # Context manager exit disconnects client
    assert hub.active_connections_count == 0


def test_periodic_telemetry_streaming_loop(tmp_path: Path):
    """When periodic telemetry interval is fast (0.05s), background loop streams consecutive frames."""
    db_file = tmp_path / "test_periodic.db"
    db_mgr = DatabaseManager(str(db_file))
    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.04,  # Fast 25 Hz telemetry interval
        simulation_tick_rate_hz=25.0,
    )
    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        with client.websocket_connect("/ws/telemetry") as ws:
            # Initial frame
            f1 = ws.receive_json()
            # Next frames arrive from background loop without any command issued
            f2 = ws.receive_json()
            f3 = ws.receive_json()

            assert f1["type"] == "TELEMETRY_UPDATE"
            assert f2["type"] == "TELEMETRY_UPDATE"
            assert f3["type"] == "TELEMETRY_UPDATE"
            # Sequence numbers must be strictly increasing
            assert f3["seq"] > f2["seq"] > f1["seq"]

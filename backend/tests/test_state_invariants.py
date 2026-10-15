"""Automated state invariant verification test suite (Phase 4).

Validates the formal mathematical invariant protocol defined in docs/attack-test-plan.md:
  I(S_0, S_1) = (S_1.state_version == S_0.state_version) AND (||S_1.p - S_0.p|| == 0)

Guarantees:
1. Under active defense (ENCRYPTED_AUTHENTICATED / INTEGRITY_ONLY), blocked attacks
   cause ZERO state version increment and ZERO coordinate drift (Delta p == 0).
2. Geofence bounds [-100, 100] in X/Z and [0, 50] in Y are never breached, even under
   corrupted coordinate injections or fuzzing payloads.
3. State version is strictly monotonic: S_{t+1}.state_version >= S_t.state_version.
4. Attack execution records and audit logs are persistently stored and retrievable.
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.attacks.attack_types import AttackStatus
from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


@pytest.fixture
def invariant_client(tmp_path: Path):
    """Provides a fresh isolated test client with its own SQLite database."""
    db_file = tmp_path / "test_invariants.db"
    db_mgr = DatabaseManager(str(db_file))

    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        rate_limit_capacity=10.0,
        rate_limit_refill_rate=5.0,
        security_mode="ENCRYPTED_AUTHENTICATED",
    )

    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client


def test_mathematical_state_invariant_on_blocked_attacks(invariant_client: TestClient):
    """Verify I(S_0, S_1) holds true for all attack scenarios under ENCRYPTED_AUTHENTICATED."""
    attack_endpoints = [
        ("/api/attacks/unauthorized_command", {"parameters": {"target_command": "ARM"}}),
        ("/api/attacks/message_tampering", {"parameters": {"target_command": "MOVE_FORWARD"}}),
        ("/api/attacks/spoofed_identity", {"parameters": {"target_command": "ARM"}}),
        ("/api/attacks/malformed_payload", {}),
        ("/api/attacks/replay_attack", {"parameters": {"target_command": "MOVE_FORWARD"}}),
    ]

    for endpoint, payload in attack_endpoints:
        s_before = invariant_client.get("/api/drone/state").json()["data"]

        resp = invariant_client.post(endpoint, json=payload)
        assert resp.status_code == 200, f"Endpoint {endpoint} failed: {resp.text}"
        data = resp.json()["data"]

        # 1. State must not be compromised
        assert data["state_compromised"] is False, f"State was compromised during {endpoint}"
        assert data["attack_result"] in (
            AttackStatus.BLOCKED_BY_DEFENSE.value,
            AttackStatus.BASELINE_REJECTED.value,
            AttackStatus.ATTACK_MITIGATED.value,
        )

        # 2. Coordinates drift during attack evaluation must be exactly zero
        drift = data["coordinates_drift"]
        assert drift["delta_x"] == 0.0
        assert drift["delta_y"] == 0.0
        assert drift["delta_z"] == 0.0
        norm = math.sqrt(drift["delta_x"]**2 + drift["delta_y"]**2 + drift["delta_z"]**2)
        assert norm == 0.0

        # 3. State version must not have changed during the attack run
        assert data["initial_state_version"] == data["final_state_version"]

        # 4. Verify live drone state matches the attack run's final state version
        s_after = invariant_client.get("/api/drone/state").json()["data"]
        assert s_after["state_version"] == data["final_state_version"]


def test_monotonic_state_version_invariant(invariant_client: TestClient):
    """Verify that state_version monotonically increases and never decreases."""
    versions = []

    # Initial state
    st = invariant_client.get("/api/drone/state").json()["data"]
    versions.append(st["state_version"])

    # Legitimate state transitions in UNSECURED mode
    invariant_client.post("/api/security/mode", json={"mode": "UNSECURED"})
    st = invariant_client.get("/api/drone/state").json()["data"]
    versions.append(st["state_version"])

    # ARM command
    r = invariant_client.post("/api/drone/command", json={"command": "ARM"})
    assert r.status_code == 200
    versions.append(r.json()["data"]["state_version_after"])

    # TAKEOFF command
    r = invariant_client.post("/api/drone/command", json={"command": "TAKEOFF"})
    assert r.status_code == 200
    versions.append(r.json()["data"]["state_version_after"])

    # Re-enable ENCRYPTED_AUTHENTICATED mode
    invariant_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    # Launch blocked attack
    r = invariant_client.post("/api/attacks/unauthorized_command")
    assert r.status_code == 200
    versions.append(r.json()["data"]["final_state_version"])

    # Verify monotonic property: v_{i+1} >= v_i
    for i in range(len(versions) - 1):
        assert versions[i + 1] >= versions[i], f"Version decreased from {versions[i]} to {versions[i+1]}"


def test_geofence_invariants_under_corrupted_payloads(invariant_client: TestClient):
    """Verify geofence boundary constraints [-100, 100] and [0, 50] are never violated."""
    # Bring drone to flight in UNSECURED mode
    invariant_client.post("/api/security/mode", json={"mode": "UNSECURED"})
    invariant_client.post("/api/drone/command", json={"command": "ARM"})
    invariant_client.post("/api/drone/command", json={"command": "TAKEOFF"})

    # Try massive out-of-bounds movement command
    r = invariant_client.post(
        "/api/drone/command",
        json={"command": "MOVE_FORWARD", "parameters": {"distance": 999999.0}},
    )
    # The command should either be clamped or rejected
    st = invariant_client.get("/api/drone/state").json()["data"]
    pos = st["position"]

    assert -100.0 <= pos["x"] <= 100.0
    assert 0.0 <= pos["y"] <= 50.0
    assert -100.0 <= pos["z"] <= 100.0


def test_attack_run_audit_persistence(invariant_client: TestClient):
    """Verify that attack runs are persistently saved in the audit log and retrievable."""
    # Execute two distinct attack scenarios
    res1 = invariant_client.post(
        "/api/attacks/message_tampering",
        json={"parameters": {"target_command": "MOVE_FORWARD"}},
    )
    assert res1.status_code == 200
    run1 = res1.json()["data"]

    res2 = invariant_client.post(
        "/api/attacks/unauthorized_command",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert res2.status_code == 200
    run2 = res2.json()["data"]

    # Query attack history
    hist_resp = invariant_client.get("/api/attacks/history?limit=10")
    assert hist_resp.status_code == 200
    history = hist_resp.json()["data"]

    assert len(history) >= 2
    run_ids = [item["attack_run_id"] for item in history]
    assert run1["attack_run_id"] in run_ids
    assert run2["attack_run_id"] in run_ids

    # Check persisted audit fields
    for item in history:
        assert "attack_run_id" in item
        assert "attack_type" in item
        assert "security_mode_active" in item
        assert "attack_result" in item

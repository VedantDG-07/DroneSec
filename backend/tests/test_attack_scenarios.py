"""Automated test suite for the six cyberattack simulation scenarios (Phase 4).

Verifies vulnerability demonstration in UNSECURED mode and 100% defense mitigation
in ENCRYPTED_AUTHENTICATED and INTEGRITY_ONLY security operating modes.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.attacks.attack_types import AttackScenarioType, AttackStatus
from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


@pytest.fixture
def attack_client(tmp_path: Path):
    """Fixture providing a test client configured with an isolated database."""
    db_file = tmp_path / "test_attacks_sim.db"
    db_mgr = DatabaseManager(str(db_file))

    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        rate_limit_capacity=10.0,
        rate_limit_refill_rate=5.0,
        security_mode="UNSECURED",
    )

    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client


# ======================================================================
# UNSECURED Mode: Exploits Must Succeed (Vulnerabilities Demonstrated)
# ======================================================================

def test_atk01_unauthorized_command_unsecured(attack_client: TestClient):
    """ATK-01 in UNSECURED mode: Injected command executes without credentials."""
    # Ensure drone is DISARMED
    state_res = attack_client.get("/api/drone/state").json()["data"]
    assert state_res["flight_state"] == "DISARMED"
    init_version = state_res["state_version"]

    resp = attack_client.post(
        "/api/attacks/unauthorized_command",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "UNAUTHORIZED_COMMAND"
    assert data["security_mode_active"] == "UNSECURED"
    assert data["attack_result"] == AttackStatus.SUCCESSFUL_EXPLOIT.value
    assert data["state_compromised"] is True
    assert data["final_state_version"] > init_version


def test_atk02_message_tampering_unsecured(attack_client: TestClient):
    """ATK-02 in UNSECURED mode: Tampered command executes with zero signature checking."""
    init_state = attack_client.get("/api/drone/state").json()["data"]

    resp = attack_client.post(
        "/api/attacks/message_tampering",
        json={"parameters": {"target_command": "ARM", "tamper_coordinate_delta": 500.0}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "MESSAGE_TAMPERING"
    assert data["security_mode_active"] == "UNSECURED"
    assert data["attack_result"] == AttackStatus.SUCCESSFUL_EXPLOIT.value
    assert data["state_compromised"] is True


def test_atk03_command_replay_unsecured(attack_client: TestClient):
    """ATK-03 in UNSECURED mode: Replayed command executes again because replay protection is disabled."""
    resp = attack_client.post(
        "/api/attacks/replay_attack",
        json={"parameters": {"target_command": "MOVE_FORWARD"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "COMMAND_REPLAY"
    assert data["security_mode_active"] == "UNSECURED"
    assert data["attack_result"] == AttackStatus.SUCCESSFUL_EXPLOIT.value
    assert data["state_compromised"] is True


def test_atk04_sender_spoofing_unsecured(attack_client: TestClient):
    """ATK-04 in UNSECURED mode: Spoofed GCS identity accepted without authentication."""
    resp = attack_client.post(
        "/api/attacks/spoofed_identity",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "SENDER_SPOOFING"
    assert data["security_mode_active"] == "UNSECURED"
    assert data["attack_result"] == AttackStatus.SUCCESSFUL_EXPLOIT.value
    assert data["state_compromised"] is True


def test_atk05_malformed_fuzzing_unsecured(attack_client: TestClient):
    """ATK-05 in UNSECURED mode: Invalid syntax and bad commands rejected by engine/schema baseline."""
    resp = attack_client.post("/api/attacks/malformed_payload")
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "MALFORMED_FUZZING"
    assert data["state_compromised"] is False
    assert data["attack_result"] in (AttackStatus.BASELINE_REJECTED.value, AttackStatus.BLOCKED_BY_DEFENSE.value)


# ======================================================================
# ENCRYPTED_AUTHENTICATED Mode: Attacks Must Be Blocked (Invariants Held)
# ======================================================================

def test_atk01_unauthorized_command_blocked_in_secured_mode(attack_client: TestClient):
    """ATK-01 in ENCRYPTED_AUTHENTICATED mode: Missing Bearer token triggers AUTH_TOKEN_MISSING."""
    attack_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    init_state = attack_client.get("/api/drone/state").json()["data"]
    init_version = init_state["state_version"]

    resp = attack_client.post(
        "/api/attacks/unauthorized_command",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "UNAUTHORIZED_COMMAND"
    assert data["security_mode_active"] == "ENCRYPTED_AUTHENTICATED"
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value
    assert data["defense_triggered"] == "AUTH_TOKEN_MISSING"
    assert data["state_compromised"] is False
    assert data["initial_state_version"] == init_version
    assert data["final_state_version"] == init_version
    assert data["coordinates_drift"] == {"delta_x": 0.0, "delta_y": 0.0, "delta_z": 0.0}


def test_atk02_message_tampering_blocked_in_secured_mode(attack_client: TestClient):
    """ATK-02 in ENCRYPTED_AUTHENTICATED mode: Corrupted ciphertext bit flips trigger CRYPTO_DECRYPTION_FAILED."""
    attack_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    resp = attack_client.post(
        "/api/attacks/message_tampering",
        json={"parameters": {"target_command": "ARM", "tamper_coordinate_delta": 500.0}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "MESSAGE_TAMPERING"
    assert data["security_mode_active"] == "ENCRYPTED_AUTHENTICATED"
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value
    assert data["defense_triggered"] == "CRYPTO_DECRYPTION_FAILED"
    assert data["state_compromised"] is False


def test_atk03_command_replay_blocked_in_secured_mode(attack_client: TestClient):
    """ATK-03 in ENCRYPTED_AUTHENTICATED mode: Replayed sequence number caught by sliding window."""
    attack_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    resp = attack_client.post(
        "/api/attacks/replay_attack",
        json={"parameters": {"target_command": "MOVE_FORWARD"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "COMMAND_REPLAY"
    assert data["security_mode_active"] == "ENCRYPTED_AUTHENTICATED"
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value
    assert data["defense_triggered"] == "REPLAY_ATTACK_DETECTED"
    assert data["state_compromised"] is False


def test_atk04_sender_spoofing_blocked_in_secured_mode(attack_client: TestClient):
    """ATK-04 in ENCRYPTED_AUTHENTICATED mode: Claiming rogue identity triggers SPOOFED_GCS_IDENTITY."""
    attack_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    resp = attack_client.post(
        "/api/attacks/spoofed_identity",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "SENDER_SPOOFING"
    assert data["security_mode_active"] == "ENCRYPTED_AUTHENTICATED"
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value
    assert data["defense_triggered"] == "SPOOFED_GCS_IDENTITY"
    assert data["state_compromised"] is False


def test_atk05_malformed_fuzzing_blocked_in_secured_mode(attack_client: TestClient):
    """ATK-05 in ENCRYPTED_AUTHENTICATED mode: Fuzzing rejected before state mutation."""
    attack_client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

    resp = attack_client.post("/api/attacks/malformed_payload")
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "MALFORMED_FUZZING"
    assert data["state_compromised"] is False
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value


def test_atk06_bounded_flooding_rate_limited(attack_client: TestClient):
    """ATK-06: Burst exceeding token bucket capacity triggers RATE_LIMIT_EXCEEDED."""
    resp = attack_client.post(
        "/api/attacks/command_flood",
        json={"parameters": {"flood_count": 30}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["attack_type"] == "BOUNDED_FLOODING"
    assert data["defense_triggered"] == "RATE_LIMIT_EXCEEDED"
    assert data["attack_result"] == AttackStatus.ATTACK_MITIGATED.value


# ======================================================================
# INTEGRITY_ONLY Mode: Tampering Blocked by HMAC
# ======================================================================

def test_atk02_tampering_blocked_in_integrity_only(attack_client: TestClient):
    """ATK-02 in INTEGRITY_ONLY mode: Tampered payload caught by HMAC verification."""
    attack_client.post("/api/security/mode", json={"mode": "INTEGRITY_ONLY"})

    resp = attack_client.post(
        "/api/attacks/message_tampering",
        json={"parameters": {"target_command": "ARM"}},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert data["security_mode_active"] == "INTEGRITY_ONLY"
    assert data["attack_result"] == AttackStatus.BLOCKED_BY_DEFENSE.value
    assert data["defense_triggered"] == "HMAC_VERIFICATION_FAILED"
    assert data["state_compromised"] is False


# ======================================================================
# Attack History & Validation
# ======================================================================

def test_attack_history_endpoint(attack_client: TestClient):
    """GET /api/attacks/history returns previously executed attack records."""
    attack_client.post("/api/attacks/unauthorized_command")
    attack_client.post("/api/attacks/malformed_payload")

    resp = attack_client.get("/api/attacks/history?limit=10&offset=0")
    assert resp.status_code == 200
    history = resp.json()["data"]

    assert len(history) >= 2
    types = [item["attack_type"] for item in history]
    assert "MALFORMED_FUZZING" in types
    assert "UNAUTHORIZED_COMMAND" in types


def test_invalid_attack_type_returns_400(attack_client: TestClient):
    """POST /api/attacks/non_existent_vector returns 400 with INVALID_ATTACK_TYPE."""
    resp = attack_client.post("/api/attacks/quantum_laser_attack")
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["code"] == "INVALID_ATTACK_TYPE"

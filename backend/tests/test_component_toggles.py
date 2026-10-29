"""Tests for dynamic security component attach/detach controls."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager
from backend.app.security.crypto_service import CryptoService
from backend.app.security.message_protocol import pack_encrypted_command


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    db_file = tmp_path / "test_components.db"
    db_mgr = DatabaseManager(str(db_file))
    cfg = AppConfig(
        db_path=str(db_file),
        security_mode="ENCRYPTED_AUTHENTICATED",
        timestamp_freshness_window_seconds=10.0,
        rate_limit_capacity=20.0,
        rate_limit_refill_rate=10.0,
    )
    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as test_client:
        yield test_client


def test_component_toggle_api(client: TestClient):
    """Test POST /api/security/component dynamically toggles components."""
    # 1. Query initial status
    resp = client.get("/api/security/status")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["components"]["encryption"] is True
    assert data["components"]["anti_replay"] is True

    # 2. Detach encryption
    resp = client.post(
        "/api/security/component",
        json={"component": "encryption", "enabled": False, "reason": "Test detachment"},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp.status_code == 200
    res_data = resp.json()["data"]
    assert res_data["component"] == "encryption"
    assert res_data["enabled"] is False
    assert res_data["components"]["encryption"] is False

    # Check status endpoint reflects it
    resp = client.get("/api/security/status")
    assert resp.json()["data"]["components"]["encryption"] is False
    assert resp.json()["data"]["algorithms"]["encryption"] == "NONE"

    # 3. Re-attach encryption
    resp = client.post(
        "/api/security/component",
        json={"component": "encryption", "enabled": True},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["enabled"] is True


def test_anti_replay_toggle_behavior(client: TestClient):
    """When anti-replay is attached, duplicates are rejected; when detached, duplicates pass."""
    app = client.app
    crypto_service: CryptoService = app.state.crypto_service

    # Build an encrypted ARM command (packet 1)
    now = time.time()
    packet1 = pack_encrypted_command(
        crypto_service=crypto_service,
        command="ARM",
        parameters=None,
        sender_id="GCS-PRIMARY",
        sequence_number=1,
        timestamp=now,
    )

    # 1. Send first time -> should pass and ARM drone
    resp1 = client.post(
        "/api/drone/command",
        json=packet1,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp1.status_code == 200

    # 2. Replay identical packet -> should be rejected by anti-replay (403)
    resp2 = client.post(
        "/api/drone/command",
        json=packet1,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp2.status_code == 403
    assert resp2.json()["error"]["code"] == "REPLAY_ATTACK_DETECTED"

    # 3. Disarm drone with a legitimate DISARM command (packet 2)
    packet2 = pack_encrypted_command(
        crypto_service=crypto_service,
        command="DISARM",
        parameters=None,
        sender_id="GCS-PRIMARY",
        sequence_number=2,
        timestamp=time.time(),
    )
    resp_disarm = client.post(
        "/api/drone/command",
        json=packet2,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp_disarm.status_code == 200

    # 4. Detach anti-replay component
    resp = client.post(
        "/api/security/component",
        json={"component": "anti_replay", "enabled": False},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp.status_code == 200

    # 5. Replay packet 1 (ARM) again -> now accepted since anti-replay is detached!
    resp3 = client.post(
        "/api/drone/command",
        json=packet1,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp3.status_code == 200
    assert resp3.json()["data"]["execution_status"] == "EXECUTED"


def test_sender_auth_toggle_behavior(client: TestClient):
    """When sender auth is attached, bad tokens are rejected; when detached, they are allowed."""
    app = client.app
    crypto_service: CryptoService = app.state.crypto_service

    packet = pack_encrypted_command(
        crypto_service=crypto_service,
        command="ARM",
        parameters=None,
        sender_id="GCS-PRIMARY",
        sequence_number=10,
        timestamp=time.time(),
    )

    # 1. With sender_auth attached (default), bad token is rejected (401)
    resp = client.post(
        "/api/drone/command",
        json=packet,
        headers={"Authorization": "Bearer INVALID_TOKEN_123"},
    )
    assert resp.status_code == 401

    # 2. Detach sender_auth
    client.post(
        "/api/security/component",
        json={"component": "sender_auth", "enabled": False},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )

    # 3. Bad token or missing token is now allowed through
    resp = client.post(
        "/api/drone/command",
        json=packet,
        headers={"Authorization": "Bearer INVALID_TOKEN_123"},
    )
    assert resp.status_code == 200


def test_rate_limiting_toggle_behavior(client: TestClient):
    """When rate limiter is detached, token-bucket burst limit is not enforced."""
    # Detach rate limiter
    client.post(
        "/api/security/component",
        json={"component": "rate_limiting", "enabled": False},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )

    app = client.app
    crypto_service: CryptoService = app.state.crypto_service

    # Burst 10 requests (capacity was 3)
    for i in range(1, 10):
        packet = pack_encrypted_command(
            crypto_service=crypto_service,
            command="STOP",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=100 + i,
            timestamp=time.time(),
        )
        resp = client.post(
            "/api/drone/command",
            json=packet,
            headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
        )
        # None should be 429
        assert resp.status_code != 429


def test_encryption_toggle_tampering(client: TestClient):
    """When encryption is attached, tampered ciphertext is rejected; when detached, plaintext can be sent."""
    app = client.app
    crypto_service: CryptoService = app.state.crypto_service

    # With encryption attached (default):
    packet = pack_encrypted_command(
        crypto_service=crypto_service,
        command="STOP",
        parameters=None,
        sender_id="GCS-PRIMARY",
        sequence_number=50,
        timestamp=time.time(),
    )
    # Tamper with ciphertext (ensure guaranteed bit change)
    ct = packet["ciphertext"]
    packet["ciphertext"] = ("B" if ct[0] == "A" else "A") + ct[1:]
    resp = client.post(
        "/api/drone/command",
        json=packet,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "CRYPTO_DECRYPTION_FAILED"

    # Detach encryption:
    client.post(
        "/api/security/component",
        json={"component": "encryption", "enabled": False},
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )

    # Now plaintext command packed by GCS is accepted:
    pack_resp = client.post("/api/drone/command/pack", json={"command": "ARM"})
    plaintext_packet = pack_resp.json()["data"]["payload"]
    assert "ciphertext" not in plaintext_packet  # Verifies it's plaintext!
    inner = plaintext_packet.get("command") or plaintext_packet.get("payload", {}).get("command")
    assert inner == "ARM"

    resp = client.post(
        "/api/drone/command",
        json=plaintext_packet,
        headers={"Authorization": "Bearer gcs-sim-token-secret-2026"},
    )
    assert resp.status_code == 200


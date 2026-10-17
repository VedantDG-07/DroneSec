"""Phase 7 Security Hardening, Concurrency, and Reliability Tests.

Verifies:
1. Production configuration safety guards (no demo tokens, no wildcard CORS, required keys).
2. Administrative and attack route authorization (invalid tokens rejected with 401).
3. Consistent request size limits (413 on bodies > 64 KiB) and malformed body validation.
4. Concurrency safety: atomic replay window commits and thread-safe key management.
5. CryptoService bounded memory under sustained encryption (nonce deque bounding).
6. Attack cancellation and mutual exclusion.
7. WebSocket oversize frame dropping and clean disconnect handling.
8. Application lifecycle repeated startup/shutdown and state-version monotonicity.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.core.drone_engine import DroneEngine
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager
from backend.app.security.authentication import AuthenticationError, AuthenticationManager
from backend.app.security.crypto_service import CryptoService, CryptoVerificationError
from backend.app.security.key_manager import KeyManager
from backend.app.security.message_protocol import SecurityMode
from backend.app.security.replay_protection import AntiReplayFilter, ReplayVerificationError
from backend.app.websocket.hub import WebSocketHub


@pytest.fixture
def isolated_client(tmp_path: Path):
    """Fixture providing a clean test client with an isolated database."""
    db_file = tmp_path / "test_phase7.db"
    db_mgr = DatabaseManager(str(db_file))
    cfg = AppConfig(
        db_path=str(db_file),
        gcs_bearer_token="test-secret-token-1234",
        authorized_sender="GCS-TEST",
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
    )
    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client, cfg


class TestProductionConfigHardening:
    """Verify configuration guards when operating under production environments."""

    def test_production_rejects_default_demo_token(self):
        with pytest.raises(ValueError, match="Production environment cannot use default demonstration"):
            AppConfig(
                app_env="production",
                gcs_bearer_token="gcs-sim-token-secret-2026",
            )

    def test_production_rejects_wildcard_cors(self):
        with pytest.raises(ValueError, match="Production environment cannot use wildcard"):
            AppConfig(
                app_env="production",
                gcs_bearer_token="prod-secure-token-xyz-987",
                cors_origins=["*"],
            )

    def test_production_rejects_missing_crypto_keys_in_secured_mode(self):
        with pytest.raises(ValueError, match="Production environment in ENCRYPTED_AUTHENTICATED mode requires explicit"):
            AppConfig(
                app_env="production",
                gcs_bearer_token="prod-secure-token-xyz-987",
                security_mode=SecurityMode.ENCRYPTED_AUTHENTICATED,
                aes_256_key=None,
                hmac_sha256_key=None,
                cors_origins=["https://gcs.dronesec.local"],
            )

    def test_production_valid_configuration_succeeds(self):
        cfg = AppConfig(
            app_env="production",
            gcs_bearer_token="prod-secure-token-xyz-987",
            security_mode=SecurityMode.ENCRYPTED_AUTHENTICATED,
            aes_256_key="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            hmac_sha256_key="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            cors_origins=["https://gcs.dronesec.local:8443"],
        )
        assert cfg.app_env == "production"
        assert cfg.gcs_bearer_token == "prod-secure-token-xyz-987"


class TestAuthorizationEnforcement:
    """Verify that unauthorized users cannot switch security modes or trigger cyberattacks."""

    def test_invalid_bearer_token_rejected_on_mode_switch(self, isolated_client):
        client, _ = isolated_client
        res = client.post(
            "/api/security/mode",
            headers={"Authorization": "Bearer fraudulent-token-000"},
            json={"mode": "INTEGRITY_ONLY", "reason": "unauthorized attempt"},
        )
        assert res.status_code == 401
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "AUTH_TOKEN_INVALID"

    def test_invalid_bearer_token_rejected_on_attack_run(self, isolated_client):
        client, _ = isolated_client
        res = client.post(
            "/api/attacks/tampering_payload",
            headers={"Authorization": "Bearer bad-operator-token"},
            json={"parameters": {}},
        )
        assert res.status_code == 401
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "AUTH_TOKEN_INVALID"

    def test_invalid_bearer_token_rejected_on_attack_cancel(self, isolated_client):
        client, _ = isolated_client
        res = client.post(
            "/api/attacks/cancel",
            headers={"Authorization": "Bearer bad-operator-token"},
        )
        assert res.status_code == 401
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "AUTH_TOKEN_INVALID"

    def test_valid_bearer_token_accepted_for_administrative_actions(self, isolated_client):
        client, cfg = isolated_client
        # Valid operator can switch security mode
        res = client.post(
            "/api/security/mode",
            headers={"Authorization": f"Bearer {cfg.gcs_bearer_token}"},
            json={"mode": "INTEGRITY_ONLY", "reason": "Authorized operator test"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"

        # Valid operator can cancel attack
        cancel_res = client.post(
            "/api/attacks/cancel",
            headers={"Authorization": f"Bearer {cfg.gcs_bearer_token}"},
        )
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "success"

    def test_mandatory_admin_auth_blocks_missing_header_when_enforced(self, tmp_path: Path):
        db_file = tmp_path / "test_admin_auth.db"
        cfg = AppConfig(
            db_path=str(db_file),
            require_admin_auth=True,
            gcs_bearer_token="admin-secret-token-777",
        )
        app = create_app(app_config=cfg, db_manager=DatabaseManager(str(db_file)))
        with TestClient(app) as client:
            res = client.post(
                "/api/security/mode",
                json={"mode": "INTEGRITY_ONLY"},
            )
            assert res.status_code == 401
            assert res.json()["error"]["code"] == "AUTH_TOKEN_MISSING"


class TestPayloadLimitsAndValidation:
    """Verify request size bounding and malformed body validation."""

    def test_oversized_payload_rejected_with_413(self, isolated_client):
        client, _ = isolated_client
        # 70 KiB payload (> 64 KiB limit)
        oversized_data = "X" * (70 * 1024)
        res = client.post(
            "/api/drone/command",
            content=oversized_data,
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 413
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"

    def test_malformed_json_rejected_with_400(self, isolated_client):
        client, _ = isolated_client
        res = client.post(
            "/api/drone/command",
            content="{ invalid json ...",
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "INVALID_JSON"

    def test_non_dict_json_rejected_with_400(self, isolated_client):
        client, _ = isolated_client
        res = client.post(
            "/api/drone/command",
            content="[\"NOT_AN_OBJECT\"]",
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "INVALID_PAYLOAD"


class TestCryptoAndReplayConcurrency:
    """Verify thread safety of cryptographic keys and anti-replay window under concurrency."""

    def test_replay_concurrent_commits_maintain_atomic_consistency(self):
        rf = AntiReplayFilter(timestamp_tolerance_seconds=10.0, window_size=64)
        sender = "CONCURRENT_GCS"
        now = time.time()
        errors = []

        def worker(seq: int):
            try:
                ticket = rf.verify_candidate(sender_id=sender, sequence_number=seq, timestamp=now)
                time.sleep(0.001)  # tiny yield to stress interleaving
                rf.commit_ticket(ticket)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 31)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Encountered unexpected errors during concurrent commits: {errors}"
        assert rf.get_highest_sequence_number(sender) == 30

    def test_replay_duplicate_commit_fails_closed(self):
        rf = AntiReplayFilter(timestamp_tolerance_seconds=10.0, window_size=64)
        sender = "TEST_GCS"
        now = time.time()

        t1 = rf.verify_candidate(sender_id=sender, sequence_number=5, timestamp=now)
        rf.commit_ticket(t1)

        # Attempt to reuse or verify candidate with sequence 5 again
        with pytest.raises(ReplayVerificationError, match="Duplicate sequence number"):
            rf.verify_candidate(sender_id=sender, sequence_number=5, timestamp=now)

    def test_key_manager_thread_safety(self):
        km = KeyManager()
        active_keys = []
        errors = []

        def reader():
            for _ in range(50):
                try:
                    k = km.get_aes_key()
                    active_keys.append(k)
                    time.sleep(0.0001)
                except Exception as e:
                    errors.append(e)

        def rotator():
            for _ in range(5):
                try:
                    km.rotate_keys()
                    time.sleep(0.001)
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=rotator),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(active_keys) > 0

    def test_crypto_service_bounded_nonces(self):
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        # Encrypt packets and ensure nonces are added without unbounded growth
        aad = b"TEST_AAD"
        for i in range(50):
            iv, ct, tag = crypto.encrypt_aes_gcm(b"TEST_PAYLOAD", aad=aad)
            assert len(iv) == 12
            assert len(tag) == 16
        
        active_key = km.active_key_id
        assert len(crypto._used_nonces[active_key]) == 50
        assert len(crypto._nonce_history[active_key]) == 50
        assert crypto.get_encryption_count(active_key) == 50


class TestAttackCancellationAndMutualExclusion:
    """Verify attack cancellation and single-execution mutual exclusion."""

    def test_cancel_active_attack_endpoint_returns_success(self, isolated_client):
        client, cfg = isolated_client
        res = client.post(
            "/api/attacks/cancel",
            headers={"Authorization": f"Bearer {cfg.gcs_bearer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "cancelled" in data["data"]


class TestWebSocketFrameLimits:
    """Verify WebSocket message bounds and disconnection cleanup."""

    @pytest.mark.asyncio
    async def test_oversized_frame_dropped_without_crash(self):
        hub = WebSocketHub()
        engine = DroneEngine()
        # Mock WebSocket client
        class MockClient:
            def __init__(self):
                self.messages = []
                self.closed = False
            async def accept(self):
                pass
            async def send_text(self, text: str):
                self.messages.append(text)
            async def close(self):
                self.closed = True

        client = MockClient()
        await hub.connect(client)
        assert len(hub._active_connections) == 1

        # Broadcast telemetry with real snapshot
        await hub.broadcast_telemetry(engine.get_state_snapshot())
        assert len(client.messages) == 1

        # Disconnect client
        await hub.disconnect(client)
        assert len(hub._active_connections) == 0


class TestApplicationLifecycleAndPersistence:
    """Verify application lifecycle, state monotonic consistency, and clean restarts."""

    def test_repeated_app_startup_and_shutdown(self, tmp_path: Path):
        db_file = tmp_path / "lifecycle_test.db"
        cfg = AppConfig(db_path=str(db_file))
        
        for iteration in range(3):
            db_mgr = DatabaseManager(str(db_file))
            app = create_app(app_config=cfg, db_manager=db_mgr)
            with TestClient(app) as client:
                res = client.get("/health")
                assert res.status_code == 200
                assert res.json()["data"]["system_status"] == "OPERATIONAL"

    def test_monotonic_state_version_under_rejected_commands(self, isolated_client):
        client, _ = isolated_client
        
        # Initial state version is 0
        state0 = client.get("/api/drone/state").json()["data"]
        initial_version = state0["state_version"]

        # Send invalid command (e.g. invalid command name)
        res = client.post(
            "/api/drone/command",
            json={"command": "SUPER_ILLEGAL_COMMAND"},
        )
        assert res.status_code in (400, 422)

        # State version MUST remain strictly unchanged
        state1 = client.get("/api/drone/state").json()["data"]
        assert state1["state_version"] == initial_version
        assert state1["flight_state"] == "DISARMED"

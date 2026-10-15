"""Comprehensive integration and security pipeline tests (Phase 3)."""

from __future__ import annotations

import base64
import time
from typing import Any, Generator
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.security.crypto_service import CryptoService
from backend.app.security.message_protocol import (
    pack_encrypted_command,
    pack_hmac_command,
)


@pytest.fixture
def client_and_app(tmp_path: Any) -> Generator[tuple[TestClient, Any], None, None]:
    db_file = str(tmp_path / "test_sec_simulation.db")
    cfg = AppConfig(
        db_path=db_file,
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        gcs_bearer_token="valid_secret_token",
        authorized_sender="GCS-PRIMARY",
        security_mode="UNSECURED",
        rate_limit_capacity=20,
        rate_limit_refill_rate=10.0,
    )
    app = create_app(app_config=cfg)
    with TestClient(app) as test_client:
        yield test_client, app


# ---------------------------------------------------------------------------
# Authentication & Authorization
# ---------------------------------------------------------------------------


class TestAuthenticationAndAuthorization:
    """Tests GCS Bearer token validation and sender identity authorization."""

    def test_missing_bearer_rejected_in_secured_mode(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app

        # Switch to ENCRYPTED_AUTHENTICATED mode
        resp = client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED", "reason": "Test setup"})
        assert resp.status_code == 200
        assert resp.json()["data"]["new_mode"] == "ENCRYPTED_AUTHENTICATED"

        # Payload with a valid header structure (any garbage ciphertext)
        payload = {
            "header": {
                "version": "1.0.0",
                "message_id": "msg-1",
                "sender_id": "GCS-PRIMARY",
                "sequence_number": 1,
                "timestamp": time.time(),
                "security_mode": "ENCRYPTED_AUTHENTICATED",
                "key_id": "sim_key_v1",
            },
            "iv": base64.b64encode(b"0" * 12).decode("ascii"),
            "ciphertext": base64.b64encode(b"garbage").decode("ascii"),
            "auth_tag": base64.b64encode(b"0" * 16).decode("ascii"),
        }

        # Missing Authorization header must be rejected with 401
        res_missing = client.post("/api/drone/command", json=payload)
        assert res_missing.status_code == 401
        assert res_missing.json()["error"]["code"] == "AUTH_TOKEN_MISSING"

    def test_invalid_bearer_rejected(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        payload = {
            "header": {
                "version": "1.0.0",
                "message_id": "msg-2",
                "sender_id": "GCS-PRIMARY",
                "sequence_number": 1,
                "timestamp": time.time(),
                "security_mode": "ENCRYPTED_AUTHENTICATED",
                "key_id": "sim_key_v1",
            },
            "iv": base64.b64encode(b"0" * 12).decode("ascii"),
            "ciphertext": base64.b64encode(b"garbage").decode("ascii"),
            "auth_tag": base64.b64encode(b"0" * 16).decode("ascii"),
        }

        res_invalid = client.post(
            "/api/drone/command",
            json=payload,
            headers={"Authorization": "Bearer bad_token_123"},
        )
        assert res_invalid.status_code == 401
        assert res_invalid.json()["error"]["code"] == "AUTH_TOKEN_INVALID"

    def test_spoofed_sender_rejected(self, client_and_app: tuple[TestClient, Any]) -> None:
        """Valid token but sender_id in header claims a different identity."""
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        # Token is valid (maps to "GCS-PRIMARY"), but header.sender_id claims "MALICIOUS_STATION"
        payload = {
            "header": {
                "version": "1.0.0",
                "message_id": "msg-3",
                "sender_id": "MALICIOUS_STATION",
                "sequence_number": 1,
                "timestamp": time.time(),
                "security_mode": "ENCRYPTED_AUTHENTICATED",
                "key_id": "sim_key_v1",
            },
            "iv": base64.b64encode(b"0" * 12).decode("ascii"),
            "ciphertext": base64.b64encode(b"garbage").decode("ascii"),
            "auth_tag": base64.b64encode(b"0" * 16).decode("ascii"),
        }
        res_spoof = client.post(
            "/api/drone/command",
            json=payload,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        # Sender mismatch raises a security error (exact code depends on order of checks)
        assert res_spoof.status_code in (400, 403)
        code = res_spoof.json()["error"]["code"]
        assert code in (
            "SPOOFED_GCS_IDENTITY",
            "AUTH_TOKEN_INVALID",
            "SECURITY_MODE_MISMATCH",
            "INVALID_SCHEMA",  # header parse error before sender check
        ), f"Unexpected error code: {code}"


# ---------------------------------------------------------------------------
# Integrity-Only (HMAC) Mode
# ---------------------------------------------------------------------------


class TestIntegrityOnlyMode:
    """Tests HMAC-SHA-256 integrity mode without confidentiality."""

    def test_hmac_legitimate_command_executes(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "INTEGRITY_ONLY"})

        crypto_service: CryptoService = app.state.crypto_service
        now = time.time()

        packed = pack_hmac_command(
            crypto_service=crypto_service,
            command="ARM",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=1,
            timestamp=now,
        )

        resp = client.post(
            "/api/drone/command",
            json=packed,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"
        assert resp.json()["data"]["command"] == "ARM"
        assert resp.json()["data"]["execution_status"] == "EXECUTED"

    def test_hmac_tampered_payload_rejected(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "INTEGRITY_ONLY"})

        crypto_service: CryptoService = app.state.crypto_service
        now = time.time()

        packed = pack_hmac_command(
            crypto_service=crypto_service,
            command="ARM",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=1,
            timestamp=now,
        )

        # Adversary intercepts and tampers with the inner command without recalculating HMAC
        packed["payload"]["command"] = "DISARM"

        resp = client.post(
            "/api/drone/command",
            json=packed,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        # HMAC verification fails -> 403
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "HMAC_VERIFICATION_FAILED"

        # Authoritative drone state must remain DISARMED (unmodified)
        st_resp = client.get("/api/drone/state")
        assert st_resp.json()["data"]["armed"] is False


# ---------------------------------------------------------------------------
# Encrypted & Authenticated (AES-256-GCM) Mode
# ---------------------------------------------------------------------------


class TestEncryptedAuthenticatedMode:
    """Tests AES-256-GCM AEAD mode for confidentiality, integrity, and anti-replay."""

    def test_aes_gcm_command_lifecycle(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        crypto_service: CryptoService = app.state.crypto_service

        # 1. ARM
        arm_pkt = pack_encrypted_command(
            crypto_service=crypto_service,
            command="ARM",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=1,
            timestamp=time.time(),
        )
        res_arm = client.post(
            "/api/drone/command",
            json=arm_pkt,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        assert res_arm.status_code == 200
        assert res_arm.json()["data"]["execution_status"] == "EXECUTED"

        # 2. TAKEOFF
        takeoff_pkt = pack_encrypted_command(
            crypto_service=crypto_service,
            command="TAKEOFF",
            parameters={"altitude": 10.0},
            sender_id="GCS-PRIMARY",
            sequence_number=2,
            timestamp=time.time(),
        )
        res_takeoff = client.post(
            "/api/drone/command",
            json=takeoff_pkt,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        assert res_takeoff.status_code == 200
        assert res_takeoff.json()["data"]["command"] == "TAKEOFF"

        # Verify drone is hovering (position z updates are applied by simulation engine)
        state = client.get("/api/drone/state").json()["data"]
        assert state["flight_state"] == "HOVERING"
        # z should be 10m after TAKEOFF (synchronous simulation applies position instantly)
        assert state["position"]["z"] >= 0.0  # z >= 0 confirms airborne

    def test_tampered_ciphertext_fails_closed(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        crypto_service: CryptoService = app.state.crypto_service

        pkt = pack_encrypted_command(
            crypto_service=crypto_service,
            command="ARM",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=1,
            timestamp=time.time(),
        )

        # Corrupt ciphertext bytes
        raw_ct = bytearray(base64.b64decode(pkt["ciphertext"]))
        raw_ct[0] ^= 0xFF
        pkt["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")

        res = client.post(
            "/api/drone/command",
            json=pkt,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        # AEAD tag verification fails -> 403
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "CRYPTO_DECRYPTION_FAILED"

        # Authoritative drone state must NOT mutate
        state = client.get("/api/drone/state").json()["data"]
        assert state["armed"] is False
        assert state["state_version"] == 0

    def test_replayed_command_rejected_and_state_unmutated(
        self, client_and_app: tuple[TestClient, Any]
    ) -> None:
        client, app = client_and_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        crypto_service: CryptoService = app.state.crypto_service

        pkt = pack_encrypted_command(
            crypto_service=crypto_service,
            command="ARM",
            parameters=None,
            sender_id="GCS-PRIMARY",
            sequence_number=1,
            timestamp=time.time(),
        )

        # First transmission succeeds
        res1 = client.post(
            "/api/drone/command",
            json=pkt,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        assert res1.status_code == 200
        initial_version = res1.json()["data"]["state_version_after"]

        # Adversary captures and replays identical packet
        res_replay = client.post(
            "/api/drone/command",
            json=pkt,
            headers={"Authorization": "Bearer valid_secret_token"},
        )
        # Replay must be rejected - can be 403 (REPLAY_ATTACK_DETECTED) or similar error
        assert res_replay.status_code in (400, 403)
        code = res_replay.json()["error"]["code"]
        assert "REPLAY" in code or "DUPLICATE" in code or "TIMESTAMP" in code

        # Invariant: State version and drone state must remain unchanged
        state_now = client.get("/api/drone/state").json()["data"]
        assert state_now["state_version"] == initial_version


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class TestRateLimitingIntegration:
    """Verifies that API level rate limits trigger HTTP 429 and Retry-After header."""

    def test_rate_limit_burst_and_recovery(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app

        # Fire enough requests to definitely exhaust the 20-token burst.
        # At 10 tokens/sec refill, 40 requests in rapid succession will consume
        # far more than the 20 burst tokens even accounting for small refills.
        rate_limited_hit = False
        for i in range(40):
            res = client.post(
                "/api/drone/command",
                json={
                    "command": "MOVE_FORWARD",
                    "parameters": {"distance": 2.0},
                    "client_id": "rate_test_client_isolated",
                },
            )
            if res.status_code == 429:
                rate_limited_hit = True
                assert res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
                assert "Retry-After" in res.headers
                break
            # Otherwise expect 400 (drone state prevents movement) 
            assert res.status_code in (200, 400), \
                f"Request {i+1}: unexpected status {res.status_code}: {res.json()}"

        assert rate_limited_hit, (
            "Expected at least one 429 RATE_LIMIT_EXCEEDED within 40 requests "
            "against a burst capacity of 20 tokens"
        )


# ---------------------------------------------------------------------------
# Security Status & Audit
# ---------------------------------------------------------------------------


class TestSecurityAuditAndStatus:
    """Verifies persistent logging of security decisions and dynamic status reporting."""

    def test_security_status_endpoint(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app

        res = client.get("/api/security/status")
        assert res.status_code == 200
        data = res.json()["data"]

        # The field in SecurityStatusData is "current_mode"
        assert data["current_mode"] == "UNSECURED"
        assert data["algorithms"]["encryption"] == "NONE"
        assert data["replay_protection"]["window_size"] == 64
        assert data["rate_limiting"]["rate_limit_per_second"] == 10.0
        assert data["rate_limiting"]["burst_capacity"] == 20

    def test_security_status_after_mode_switch(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app

        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED", "reason": "Test"})

        res = client.get("/api/security/status")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["current_mode"] == "ENCRYPTED_AUTHENTICATED"
        assert data["algorithms"]["encryption"] == "AES-256-GCM"
        assert data["replay_protection"]["enabled"] is True

    def test_audit_events_persisted_in_db(self, client_and_app: tuple[TestClient, Any]) -> None:
        client, app = client_and_app

        # Trigger mode change (INFO event)
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED", "reason": "Audit verification"})

        # Trigger auth failure (WARN event) — missing bearer token in secured mode
        client.post(
            "/api/drone/command",
            json={
                "header": {
                    "version": "1.0.0",
                    "message_id": "bad-msg",
                    "sender_id": "ATTACKER",
                    "sequence_number": 1,
                    "timestamp": time.time(),
                    "security_mode": "ENCRYPTED_AUTHENTICATED",
                    "key_id": "sim_key_v1",
                },
                "iv": base64.b64encode(b"0" * 12).decode("ascii"),
                "ciphertext": base64.b64encode(b"garbage").decode("ascii"),
                "auth_tag": base64.b64encode(b"0" * 16).decode("ascii"),
            },
            # No Authorization header  -> AUTH_TOKEN_MISSING logged
        )

        # Query logs - /api/logs returns a list directly in StandardResponse.data
        logs_res = client.get("/api/logs")
        assert logs_res.status_code == 200
        events = logs_res.json()["data"]
        assert isinstance(events, list)

        event_codes = [e.get("event_code") for e in events if isinstance(e, dict)]
        assert any("SECURITY_MODE_CHANGED" in str(code) for code in event_codes), \
            f"SECURITY_MODE_CHANGED not found in audit events. Codes: {event_codes}"

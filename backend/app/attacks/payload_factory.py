"""Payload factory: craft malicious and legitimate frames for all six attack scenarios.

All methods are pure functions; they do NOT submit any HTTP request or mutate any state.
The factory is deterministic when explicit sequence numbers and timestamps are provided.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any, Optional

from backend.app.security.crypto_service import CryptoService
from backend.app.security.message_protocol import (
    SecurityMode,
    pack_encrypted_command,
    pack_hmac_command,
)


class PayloadFactory:
    """Constructs attack and legitimate test payloads for all six scenarios.

    Safety: Methods only build payload dicts. They do not make HTTP requests,
    touch the drone engine, or advance any security state.
    """

    def __init__(self, crypto_service: CryptoService) -> None:
        self._crypto = crypto_service

    # ------------------------------------------------------------------
    # ATK-01: Unauthorized Command Injection
    # ------------------------------------------------------------------

    def unauthorized_missing_bearer(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Encrypted command packet with NO Authorization header (omitted), or unsecured raw command."""
        if security_mode == "UNSECURED":
            return {"command": command, "parameters": parameters, "client_id": "ATK01_CLIENT"}
        ts = timestamp if timestamp is not None else time.time()
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )

    def unauthorized_invalid_bearer(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Encrypted command packet intended to be submitted with a wrong Bearer token."""
        if security_mode == "UNSECURED":
            return {"command": command, "parameters": parameters, "client_id": "ATK01_CLIENT"}
        ts = timestamp if timestamp is not None else time.time()
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )

    # ------------------------------------------------------------------
    # ATK-02: Message Tampering
    # ------------------------------------------------------------------

    def tampered_ciphertext(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        byte_offset: int = 0,
        flip_mask: int = 0xFF,
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """AES-GCM packet with a bit-flipped ciphertext byte, or tampered payload in unsecured/integrity mode."""
        if security_mode == "UNSECURED":
            params = parameters or {"distance": 500.0}
            return {"command": command, "parameters": params, "client_id": "ATK02_CLIENT"}
        if security_mode == "INTEGRITY_ONLY":
            return self.tampered_hmac_payload(command=command, seq=seq, timestamp=timestamp, sender_id=sender_id)

        ts = timestamp if timestamp is not None else time.time()
        pkt = pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )
        raw = bytearray(base64.b64decode(pkt["ciphertext"]))
        raw[byte_offset % max(len(raw), 1)] ^= flip_mask
        pkt["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        return pkt

    def tampered_auth_tag(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """AES-GCM packet with a fully zeroed authentication tag."""
        ts = timestamp if timestamp is not None else time.time()
        pkt = pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )
        pkt["auth_tag"] = base64.b64encode(b"\x00" * 16).decode("ascii")
        return pkt

    def tampered_hmac_payload(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        injected_command: str = "DISARM",
    ) -> dict[str, Any]:
        """HMAC-signed packet whose inner command has been replaced without re-signing."""
        ts = timestamp if timestamp is not None else time.time()
        pkt = pack_hmac_command(
            crypto_service=self._crypto,
            command=command,
            parameters=None,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )
        pkt["payload"]["command"] = injected_command  # Tamper without re-computing HMAC
        return pkt

    # ------------------------------------------------------------------
    # ATK-03: Replay Attack
    # ------------------------------------------------------------------

    def captured_replay_packet(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        sender_id: str = "GCS-PRIMARY",
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Build a packet that will be stored and replayed a second time."""
        if security_mode == "UNSECURED":
            return {"command": command, "parameters": parameters, "client_id": "ATK03_CLIENT"}
        ts = timestamp if timestamp is not None else time.time()
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )

    def stale_timestamp_packet(
        self,
        command: str = "ARM",
        seq: int = 1,
        stale_seconds: float = 10.0,
        sender_id: str = "GCS-PRIMARY",
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Packet with a timestamp older than the freshness window (default 5 s)."""
        if security_mode == "UNSECURED":
            return {"command": command, "parameters": parameters, "client_id": "ATK03_CLIENT"}
        stale_ts = time.time() - stale_seconds
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=stale_ts,
        )

    # ------------------------------------------------------------------
    # ATK-04: Sender Spoofing
    # ------------------------------------------------------------------

    def spoofed_sender_packet(
        self,
        command: str = "ARM",
        seq: int = 1,
        timestamp: Optional[float] = None,
        legitimate_sender_id: str = "GCS-PRIMARY",
        spoofed_sender_id: str = "ROGUE-GCS",
        security_mode: str = "ENCRYPTED_AUTHENTICATED",
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Encrypted packet claiming a different sender_id than the authenticated token maps to."""
        if security_mode == "UNSECURED":
            return {"command": command, "parameters": parameters, "client_id": spoofed_sender_id}
        ts = timestamp if timestamp is not None else time.time()
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=parameters,
            sender_id=spoofed_sender_id,  # Mismatched identity claim
            sequence_number=seq,
            timestamp=ts,
        )

    # ------------------------------------------------------------------
    # ATK-05: Malformed Payload / Fuzzing
    # ------------------------------------------------------------------

    def fuzz_unknown_command(self) -> dict[str, Any]:
        """Unknown command string in UNSECURED mode."""
        return {"command": "DO_BARREL_ROLL", "parameters": None}

    def fuzz_missing_command_field(self) -> dict[str, Any]:
        """Missing 'command' field entirely."""
        return {"parameters": {"altitude": 5.0}}

    def fuzz_wrong_type_parameters(self) -> dict[str, Any]:
        """Parameters is a string instead of a dict."""
        return {"command": "TAKEOFF", "parameters": "not_a_dict"}

    def fuzz_oversized_payload(self, target_bytes: int = 5_000) -> dict[str, Any]:
        """Payload with an oversized parameters blob and unknown command."""
        return {
            "command": "FUZZ_OVERSIZED",
            "parameters": {"padding": "X" * target_bytes},
        }

    def fuzz_invalid_json_string(self) -> str:
        """Raw malformed JSON string (not a dict)."""
        return '{"command": "ARM", "parameters": INVALID}'

    def fuzz_coordinate_overflow(self) -> dict[str, Any]:
        """Move command with geofence-violating coordinate."""
        return {"command": "MOVE_FORWARD", "parameters": {"distance": 1e9}}

    def fuzz_negative_altitude(self) -> dict[str, Any]:
        """Takeoff with negative altitude."""
        return {"command": "TAKEOFF", "parameters": {"altitude": -100.0}}

    def fuzz_empty_body(self) -> dict[str, Any]:
        """Empty JSON object — no fields at all."""
        return {}

    def fuzz_null_command(self) -> dict[str, Any]:
        """Null value for 'command' field."""
        return {"command": None, "parameters": None}

    def all_fuzz_cases(self) -> list[dict[str, Any]]:
        """Returns all fuzz case payloads as a list of dicts (or raw strings)."""
        return [
            self.fuzz_unknown_command(),
            self.fuzz_missing_command_field(),
            self.fuzz_wrong_type_parameters(),
            self.fuzz_oversized_payload(),
            self.fuzz_coordinate_overflow(),
            self.fuzz_negative_altitude(),
            self.fuzz_empty_body(),
            self.fuzz_null_command(),
        ]

    # ------------------------------------------------------------------
    # ATK-06: Bounded Flooding
    # ------------------------------------------------------------------

    def flood_batch(
        self,
        count: int = 30,
        command: str = "ARM",
        client_id: str = "FLOOD_CLIENT",
        seq_start: int = 1,
    ) -> list[dict[str, Any]]:
        """Generate a bounded batch of UNSECURED command payloads for flooding tests.

        Args:
            count: Number of packets to generate. Capped at MAX_FLOOD_REQUESTS.
            command: The command to inject.
            client_id: Rate-bucket client identifier.
            seq_start: Starting sequence counter.
        """
        from backend.app.attacks.attack_types import MAX_FLOOD_REQUESTS

        count = min(count, MAX_FLOOD_REQUESTS)
        return [
            {"command": command, "parameters": None, "client_id": client_id}
            for _ in range(count)
        ]

    # ------------------------------------------------------------------
    # Legitimate (positive) control packets
    # ------------------------------------------------------------------

    def legitimate_encrypted(
        self,
        command: str,
        seq: int,
        sender_id: str = "GCS-PRIMARY",
        timestamp: Optional[float] = None,
    ) -> dict[str, Any]:
        """Valid, correctly signed AES-GCM command packet."""
        ts = timestamp if timestamp is not None else time.time()
        return pack_encrypted_command(
            crypto_service=self._crypto,
            command=command,
            parameters=None,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )

    def legitimate_hmac(
        self,
        command: str,
        seq: int,
        sender_id: str = "GCS-PRIMARY",
        timestamp: Optional[float] = None,
    ) -> dict[str, Any]:
        """Valid, correctly signed HMAC-SHA-256 command packet."""
        ts = timestamp if timestamp is not None else time.time()
        return pack_hmac_command(
            crypto_service=self._crypto,
            command=command,
            parameters=None,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
        )

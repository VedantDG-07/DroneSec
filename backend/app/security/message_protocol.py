"""Message protocol definitions, versioned security envelopes, and canonical serialization."""

from __future__ import annotations

import base64
import json
import math
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class SecurityMode(str, Enum):
    """Supported security operational modes."""

    UNSECURED = "UNSECURED"
    INTEGRITY_ONLY = "INTEGRITY_ONLY"
    ENCRYPTED_AUTHENTICATED = "ENCRYPTED_AUTHENTICATED"

    def __str__(self) -> str:
        return self.value


class SecurityHeader(BaseModel):
    """Standard authenticated header bound to protected application frames."""

    model_config = ConfigDict(extra="forbid")

    message_id: str
    sender_id: str
    sequence_number: int = Field(ge=0)
    timestamp: float
    security_mode: SecurityMode
    key_id: str = "sim_key_v1"

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if not math.isfinite(self.timestamp):
            raise ValueError(f"Header timestamp must be a finite real number. Got {self.timestamp}")


def canonicalize_header(header: SecurityHeader) -> bytes:
    """Serialize SecurityHeader into deterministic, canonical JSON bytes for AAD binding."""
    header_dict = header.model_dump(mode="json")
    return json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonicalize_payload(payload: dict[str, Any]) -> bytes:
    """Serialize command payload dictionary into deterministic canonical JSON bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EncryptedCommandRequest(BaseModel):
    """Application-layer encrypted command frame per docs/api-contract.md."""

    model_config = ConfigDict(extra="forbid")

    header: SecurityHeader
    iv: str  # Base64-encoded 12-byte nonce
    ciphertext: str  # Base64-encoded ciphertext
    auth_tag: str  # Base64-encoded 16-byte authentication tag
    signature: Optional[str] = None


class HmacSignedCommandRequest(BaseModel):
    """Application-layer HMAC signed command frame for integrity demonstration."""

    model_config = ConfigDict(extra="forbid")

    header: SecurityHeader
    payload: dict[str, Any]
    signature: str  # Base64-encoded HMAC-SHA-256 signature


def pack_encrypted_command(
    crypto_service: Any,
    command: str,
    parameters: Optional[dict[str, Any]],
    sender_id: str,
    sequence_number: int,
    timestamp: float,
    key_id: str = "sim_key_v1",
    message_id: Optional[str] = None,
    nonce: Optional[bytes] = None,
) -> dict[str, Any]:
    """Helper utility constructing an EncryptedCommandRequest payload dictionary."""
    import uuid

    mid = message_id or str(uuid.uuid4())
    header = SecurityHeader(
        message_id=mid,
        sender_id=sender_id,
        sequence_number=sequence_number,
        timestamp=timestamp,
        security_mode=SecurityMode.ENCRYPTED_AUTHENTICATED,
        key_id=key_id,
    )
    aad_bytes = canonicalize_header(header)

    inner_payload = {"command": command}
    if parameters is not None:
        inner_payload["parameters"] = parameters
    plaintext_bytes = canonicalize_payload(inner_payload)

    iv, ct, tag = crypto_service.encrypt_aes_gcm(
        plaintext=plaintext_bytes,
        aad=aad_bytes,
        key_id=key_id,
        nonce=nonce,
    )

    return {
        "header": header.model_dump(mode="json"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "auth_tag": base64.b64encode(tag).decode("ascii"),
        "signature": None,
    }


def pack_hmac_command(
    crypto_service: Any,
    command: str,
    parameters: Optional[dict[str, Any]],
    sender_id: str,
    sequence_number: int,
    timestamp: float,
    key_id: str = "sim_key_v1",
    message_id: Optional[str] = None,
) -> dict[str, Any]:
    """Helper utility constructing an HmacSignedCommandRequest payload dictionary."""
    import uuid

    mid = message_id or str(uuid.uuid4())
    header = SecurityHeader(
        message_id=mid,
        sender_id=sender_id,
        sequence_number=sequence_number,
        timestamp=timestamp,
        security_mode=SecurityMode.INTEGRITY_ONLY,
        key_id=key_id,
    )
    header_bytes = canonicalize_header(header)

    inner_payload = {"command": command}
    if parameters is not None:
        inner_payload["parameters"] = parameters
    payload_bytes = canonicalize_payload(inner_payload)

    # Combined data to authenticate: header_bytes | payload_bytes
    data_to_sign = header_bytes + b"|" + payload_bytes
    sig = crypto_service.sign_hmac(data_to_sign, key_id=key_id)

    return {
        "header": header.model_dump(mode="json"),
        "payload": inner_payload,
        "signature": base64.b64encode(sig).decode("ascii"),
    }

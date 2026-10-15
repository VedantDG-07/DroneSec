# backend/app/security/__init__.py
"""Modular security and cryptographic engine package."""

from backend.app.security.authentication import AuthenticationError, AuthenticationManager
from backend.app.security.crypto_service import CryptoService, CryptoVerificationError
from backend.app.security.key_manager import KeyManager
from backend.app.security.message_protocol import (
    EncryptedCommandRequest,
    HmacSignedCommandRequest,
    SecurityHeader,
    SecurityMode,
    canonicalize_header,
    canonicalize_payload,
    pack_encrypted_command,
    pack_hmac_command,
)
from backend.app.security.rate_limiter import RateLimitResult, TokenBucketRateLimiter
from backend.app.security.replay_protection import (
    AntiReplayFilter,
    ReplayCheckTicket,
    ReplayVerificationError,
)
from backend.app.security.security_service import (
    SecurityPipelineError,
    SecurityService,
    SecurityVerificationResult,
)

__all__ = [
    "AuthenticationError",
    "AuthenticationManager",
    "CryptoService",
    "CryptoVerificationError",
    "KeyManager",
    "SecurityHeader",
    "SecurityMode",
    "EncryptedCommandRequest",
    "HmacSignedCommandRequest",
    "canonicalize_header",
    "canonicalize_payload",
    "pack_encrypted_command",
    "pack_hmac_command",
    "RateLimitResult",
    "TokenBucketRateLimiter",
    "AntiReplayFilter",
    "ReplayCheckTicket",
    "ReplayVerificationError",
    "SecurityPipelineError",
    "SecurityService",
    "SecurityVerificationResult",
]

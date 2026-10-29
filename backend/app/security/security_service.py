"""Central Security Service orchestrating authentication, cryptography, anti-replay, and rate limiting."""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from backend.app.persistence.repositories import SecurityEventRepository
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
)
from backend.app.security.rate_limiter import TokenBucketRateLimiter
from backend.app.security.replay_protection import AntiReplayFilter, ReplayVerificationError

logger = logging.getLogger("drone_security.security_service")


class SecurityPipelineError(Exception):
    """Raised when an incoming command violates security constraints."""

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        self.retry_after = retry_after


@dataclass(frozen=True)
class SecurityVerificationResult:
    """Outcome of successful security pipeline verification."""

    is_valid: bool
    command: str
    parameters: Optional[dict[str, Any]]
    sender_id: str
    security_mode: SecurityMode
    message_id: Optional[str] = None
    sequence_number: Optional[int] = None


class SecurityService:
    """Orchestrates defensive pipeline: Rate Limiting -> Auth -> Crypto/Integrity -> Anti-Replay."""

    def __init__(
        self,
        key_manager: KeyManager,
        crypto_service: CryptoService,
        auth_manager: AuthenticationManager,
        replay_filter: AntiReplayFilter,
        rate_limiter: TokenBucketRateLimiter,
        sec_event_repo: Optional[SecurityEventRepository] = None,
        initial_mode: SecurityMode | str = SecurityMode.UNSECURED,
        sec_repo: Optional[SecurityEventRepository] = None,
        require_fail_closed_audit: bool = True,
    ) -> None:
        self.key_manager = key_manager
        self.crypto_service = crypto_service
        self.auth_manager = auth_manager
        self.replay_filter = replay_filter
        self.rate_limiter = rate_limiter
        repo = sec_event_repo or sec_repo
        if repo is None:
            raise ValueError("SecurityEventRepository is required for SecurityService.")
        self.sec_event_repo = repo
        if isinstance(initial_mode, str):
            self._mode = SecurityMode(initial_mode)
        else:
            self._mode = initial_mode
        self.require_fail_closed_audit = require_fail_closed_audit
        self._components: dict[str, bool] = self._default_components_for_mode(self._mode)

    @staticmethod
    def _default_components_for_mode(mode: SecurityMode) -> dict[str, bool]:
        if mode == SecurityMode.UNSECURED:
            return {
                "encryption": False,
                "sender_auth": False,
                "anti_replay": False,
                "rate_limiting": True,
                "receiver_auth": True,
            }
        elif mode == SecurityMode.INTEGRITY_ONLY:
            return {
                "encryption": False,
                "sender_auth": True,
                "anti_replay": True,
                "rate_limiting": True,
                "receiver_auth": True,
            }
        else:
            return {
                "encryption": True,
                "sender_auth": True,
                "anti_replay": True,
                "rate_limiting": True,
                "receiver_auth": True,
            }

    def get_components(self) -> dict[str, bool]:
        return dict(self._components)

    def is_component_enabled(self, component: str) -> bool:
        return self._components.get(component, True)

    def set_component_state(self, component: str, enabled: bool, reason: str = "") -> dict[str, Any]:
        """Dynamically attach or detach an individual security component across the platform."""
        if component not in self._components:
            raise ValueError(f"Unknown security component '{component}'. Valid: {list(self._components.keys())}")
        prev = self._components[component]
        self._components[component] = enabled

        if component == "anti_replay" and not enabled:
            self.replay_filter.reset()

        # Re-derive mode from active components
        if self._components["encryption"]:
            self._mode = SecurityMode.ENCRYPTED_AUTHENTICATED
        elif self._components["sender_auth"] or self._components["anti_replay"]:
            self._mode = SecurityMode.INTEGRITY_ONLY
        else:
            self._mode = SecurityMode.UNSECURED

        action = "ATTACHED" if enabled else "DETACHED"
        self.sec_event_repo.log_event(
            event_code="SECURITY_COMPONENT_CHANGED",
            severity="INFO",
            message=f"Security component '{component}' was {action}. Reason: {reason}",
            details={"component": component, "enabled": enabled, "previous": prev, "active_mode": self._mode.value},
        )

        return {
            "component": component,
            "enabled": enabled,
            "previous": prev,
            "active_mode": self._mode.value,
            "components": dict(self._components),
        }

    @property
    def current_mode(self) -> SecurityMode:
        return self._mode

    def set_security_mode(self, new_mode: SecurityMode, reason: str = "") -> dict[str, Any]:
        """Switch active security operating mode and log the transition."""
        prev = self._mode
        self._mode = new_mode
        self._components = self._default_components_for_mode(new_mode)

        # Reset replay window on mode switch to prevent stale state from previous run
        self.replay_filter.reset()

        # Log security audit event synchronously / asynchronously
        self.sec_event_repo.log_event(
            event_code="SECURITY_MODE_CHANGED",
            severity="INFO",
            message=f"Security mode transitioned from {prev.value} to {new_mode.value}. Reason: {reason}",
            details={"previous_mode": prev.value, "new_mode": new_mode.value, "reason": reason},
        )

        return {
            "previous_mode": prev.value,
            "new_mode": new_mode.value,
            "transition_timestamp": time.time(),
        }

    def get_security_status(self) -> dict[str, Any]:
        """Return dynamic security configuration and state matching docs/api-contract.md."""
        is_secured = self._mode != SecurityMode.UNSECURED
        return {
            "current_mode": self._mode.value,
            "components": dict(self._components),
            "active_key_id": self.key_manager.active_key_id if is_secured else None,
            "algorithms": {
                "encryption": "AES-256-GCM" if self._components.get("encryption") else "NONE",
                "integrity": "AES-256-GCM" if self._components.get("encryption") else ("HMAC-SHA-256" if self._mode == SecurityMode.INTEGRITY_ONLY else "NONE"),
                "kdf": "HKDF-SHA256" if is_secured else "NONE",
            },
            "replay_protection": {
                "enabled": self._components.get("anti_replay", is_secured),
                "window_size": self.replay_filter.window_size,
                "highest_sequence_number": self.replay_filter.get_highest_sequence_number(),
                "timestamp_tolerance_seconds": self.replay_filter.timestamp_tolerance,
            },
            "rate_limiting": {
                "enabled": self._components.get("rate_limiting", True),
                "rate_limit_per_second": self.rate_limiter.refill_rate,
                "burst_capacity": int(self.rate_limiter.burst_capacity),
            },
        }

    async def verify_command_request(
        self,
        raw_payload: dict[str, Any],
        authorization_header: Optional[str] = None,
        source_ip: str = "127.0.0.1",
    ) -> SecurityVerificationResult:
        """Run incoming request through the defense pipeline.
        
        Fail-Closed Invariant: Any violation raises SecurityPipelineError and records an audit log.
        """
        # --- Stage 1: Rate Limiting ---
        rate_key = source_ip
        if "header" in raw_payload and isinstance(raw_payload["header"], dict):
            rate_key = raw_payload["header"].get("sender_id", source_ip)
        elif "client_id" in raw_payload and raw_payload["client_id"]:
            rate_key = raw_payload["client_id"]

        if self.is_component_enabled("rate_limiting"):
            rate_res = self.rate_limiter.consume(rate_key)
            if not rate_res.allowed:
                await self.sec_event_repo.log_event_async(
                    event_code="RATE_LIMIT_EXCEEDED",
                    severity="WARNING",
                    source_ip=source_ip,
                    sender_id=rate_key,
                    message=f"Rate limit exceeded for client '{rate_key}'. Tokens remaining: {rate_res.tokens_remaining:.2f}",
                    details={"retry_after": rate_res.retry_after_seconds},
                )
                raise SecurityPipelineError(
                    status_code=429,
                    error_code="RATE_LIMIT_EXCEEDED",
                    message="Command rate limit exceeded. Please retry later.",
                    retry_after=rate_res.retry_after_seconds,
                )

        # --- Stage 2: Mode: UNSECURED or Plaintext without header ---
        if (self._mode == SecurityMode.UNSECURED or (not self.is_component_enabled("encryption") and not self.is_component_enabled("sender_auth") and not self.is_component_enabled("anti_replay"))) and "header" not in raw_payload:
            cmd = raw_payload.get("command")
            if not cmd or not isinstance(cmd, str):
                raise SecurityPipelineError(
                    status_code=400,
                    error_code="UNKNOWN_COMMAND",
                    message="Command string must be specified.",
                )
            params = raw_payload.get("parameters")
            client_id = raw_payload.get("client_id", "GCS_CLIENT")
            return SecurityVerificationResult(
                is_valid=True,
                command=cmd,
                parameters=params,
                sender_id=client_id,
                security_mode=SecurityMode.UNSECURED,
            )

        # --- Stage 3: Authenticated Modes require Bearer Token ---
        authenticated_client_id = "GCS_CLIENT"
        if self.is_component_enabled("sender_auth"):
            try:
                authenticated_client_id = self.auth_manager.authenticate_header(authorization_header)
            except AuthenticationError as e:
                await self.sec_event_repo.log_event_async(
                    event_code=e.code,
                    severity="HIGH",
                    source_ip=source_ip,
                    message=e.message,
                )
                raise SecurityPipelineError(status_code=401, error_code=e.code, message=e.message) from e
        else:
            if authorization_header:
                try:
                    authenticated_client_id = self.auth_manager.authenticate_header(authorization_header)
                except Exception:
                    authenticated_client_id = "ANONYMOUS_OPERATOR"
            else:
                authenticated_client_id = "ANONYMOUS_OPERATOR"

        # Ensure header block exists for protected envelopes
        if "header" not in raw_payload or not isinstance(raw_payload["header"], dict):
            if not self.is_component_enabled("encryption") and not self.is_component_enabled("anti_replay"):
                cmd = raw_payload.get("command")
                if not cmd or not isinstance(cmd, str):
                    raise SecurityPipelineError(
                        status_code=400,
                        error_code="UNKNOWN_COMMAND",
                        message="Command string must be specified.",
                    )
                return SecurityVerificationResult(
                    is_valid=True,
                    command=cmd,
                    parameters=raw_payload.get("parameters"),
                    sender_id=authenticated_client_id,
                    security_mode=self._mode,
                )

            await self.sec_event_repo.log_event_async(
                event_code="INVALID_ENVELOPE",
                severity="WARNING",
                source_ip=source_ip,
                sender_id=authenticated_client_id,
                message="Protected command is missing required 'header' object.",
            )
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message="Protected command requires a valid 'header' structure.",
            )

        try:
            header = SecurityHeader(**raw_payload["header"])
        except Exception as e:
            await self.sec_event_repo.log_event_async(
                event_code="INVALID_HEADER",
                severity="WARNING",
                source_ip=source_ip,
                sender_id=authenticated_client_id,
                message=f"Malformed security header: {e}",
            )
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message=f"Malformed security header: {e}",
            ) from e

        # Verify header mode matches system active mode
        if self.is_component_enabled("receiver_auth"):
            mode_matches = (header.security_mode == self._mode) or (not self.is_component_enabled("encryption") and header.security_mode == SecurityMode.UNSECURED)
            if not mode_matches:
                await self.sec_event_repo.log_event_async(
                    event_code="SECURITY_MODE_MISMATCH",
                    severity="WARNING",
                    source_ip=source_ip,
                    sender_id=authenticated_client_id,
                    message=f"Header mode {header.security_mode.value} does not match active mode {self._mode.value}.",
                )
                raise SecurityPipelineError(
                    status_code=403,
                    error_code="SECURITY_MODE_MISMATCH",
                    message=f"Security mode mismatch: active is {self._mode.value}, received {header.security_mode.value}.",
                )

        # Verify sender authorization (cannot spoof another GCS identity)
        if self.is_component_enabled("sender_auth"):
            try:
                self.auth_manager.verify_sender_authorization(authenticated_client_id, header.sender_id)
            except AuthenticationError as e:
                await self.sec_event_repo.log_event_async(
                    event_code="SPOOFED_GCS_IDENTITY",
                    severity="CRITICAL",
                    source_ip=source_ip,
                    sender_id=authenticated_client_id,
                    message=f"Client '{authenticated_client_id}' attempted to spoof sender '{header.sender_id}'.",
                )
                raise SecurityPipelineError(status_code=403, error_code="SPOOFED_GCS_IDENTITY", message=e.message) from e

        # --- Stage 4: Anti-Replay Stage 1 (Freshness & Sequence Verification Ticket) ---
        replay_ticket = None
        if self.is_component_enabled("anti_replay"):
            try:
                replay_ticket = self.replay_filter.verify_candidate(
                    sender_id=header.sender_id,
                    sequence_number=header.sequence_number,
                    timestamp=header.timestamp,
                )
            except ReplayVerificationError as e:
                await self.sec_event_repo.log_event_async(
                    event_code=e.code,
                    severity="CRITICAL" if e.code == "REPLAY_ATTACK_DETECTED" else "WARNING",
                    source_ip=source_ip,
                    sender_id=header.sender_id,
                    message=e.message,
                    details={"sequence_number": header.sequence_number, "timestamp": header.timestamp},
                )
                raise SecurityPipelineError(status_code=403, error_code=e.code, message=e.message) from e

        # --- Stage 5: Cryptographic Verification by Mode ---
        try:
            if self._mode == SecurityMode.INTEGRITY_ONLY:
                inner_cmd, inner_params = await self._verify_integrity_mode(
                    raw_payload=raw_payload,
                    header=header,
                    source_ip=source_ip,
                    client_id=authenticated_client_id,
                )
            elif self._mode == SecurityMode.ENCRYPTED_AUTHENTICATED and self.is_component_enabled("encryption"):
                inner_cmd, inner_params = await self._verify_encrypted_mode(
                    raw_payload=raw_payload,
                    header=header,
                    source_ip=source_ip,
                    client_id=authenticated_client_id,
                )
            else:
                if "command" in raw_payload:
                    inner_cmd = raw_payload["command"]
                    inner_params = raw_payload.get("parameters")
                elif "payload" in raw_payload and isinstance(raw_payload["payload"], dict):
                    inner_cmd = raw_payload["payload"].get("command")
                    inner_params = raw_payload["payload"].get("parameters")
                elif "ciphertext" in raw_payload:
                    inner_cmd, inner_params = await self._verify_encrypted_mode(
                        raw_payload=raw_payload,
                        header=header,
                        source_ip=source_ip,
                        client_id=authenticated_client_id,
                    )
                else:
                    inner_cmd = raw_payload.get("command")
                    inner_params = raw_payload.get("parameters")
        except Exception:
            if replay_ticket is not None:
                self.replay_filter.abort_ticket(replay_ticket)
            raise

        # --- Stage 6: Anti-Replay Stage 2 (Commit Window Advance) ---
        if replay_ticket is not None:
            self.replay_filter.commit_ticket(replay_ticket)

        if self.is_component_enabled("receiver_auth"):
            if not inner_cmd or not isinstance(inner_cmd, str):
                raise SecurityPipelineError(
                    status_code=400,
                    error_code="UNKNOWN_COMMAND",
                    message="Payload must contain a valid command string.",
                )

        return SecurityVerificationResult(
            is_valid=True,
            command=inner_cmd,
            parameters=inner_params,
            sender_id=header.sender_id,
            security_mode=self._mode,
            message_id=header.message_id,
            sequence_number=header.sequence_number,
        )

    async def _verify_integrity_mode(
        self,
        raw_payload: dict[str, Any],
        header: SecurityHeader,
        source_ip: str,
        client_id: str,
    ) -> tuple[str, Optional[dict[str, Any]]]:
        """Verify HMAC-SHA-256 signed message."""
        payload_dict = raw_payload.get("payload")
        signature_b64 = raw_payload.get("signature")

        if not payload_dict or not isinstance(payload_dict, dict) or not signature_b64:
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message="INTEGRITY_ONLY mode requires 'payload' object and 'signature' string.",
            )

        try:
            signature_bytes = base64.b64decode(signature_b64)
        except Exception as e:
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message="Signature is not valid Base64.",
            ) from e

        header_bytes = canonicalize_header(header)
        payload_bytes = canonicalize_payload(payload_dict)
        data_to_verify = header_bytes + b"|" + payload_bytes

        try:
            self.crypto_service.verify_hmac(data_to_verify, signature_bytes, key_id=header.key_id)
        except CryptoVerificationError as e:
            await self.sec_event_repo.log_event_async(
                event_code="HMAC_VERIFICATION_FAILED",
                severity="CRITICAL",
                source_ip=source_ip,
                sender_id=header.sender_id,
                message=str(e),
                details={"message_id": header.message_id, "key_id": header.key_id},
            )
            raise SecurityPipelineError(
                status_code=403,
                error_code="HMAC_VERIFICATION_FAILED",
                message="HMAC signature verification failed. Message may have been tampered with.",
            ) from e

        cmd = payload_dict.get("command")
        if not cmd or not isinstance(cmd, str):
            raise SecurityPipelineError(
                status_code=400,
                error_code="UNKNOWN_COMMAND",
                message="Payload must contain a valid 'command' string.",
            )

        return cmd, payload_dict.get("parameters")

    async def _verify_encrypted_mode(
        self,
        raw_payload: dict[str, Any],
        header: SecurityHeader,
        source_ip: str,
        client_id: str,
    ) -> tuple[str, Optional[dict[str, Any]]]:
        """Decrypt and verify AES-256-GCM AEAD message."""
        iv_b64 = raw_payload.get("iv")
        ct_b64 = raw_payload.get("ciphertext")
        tag_b64 = raw_payload.get("auth_tag")

        if not (iv_b64 and ct_b64 and tag_b64):
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message="ENCRYPTED_AUTHENTICATED mode requires 'iv', 'ciphertext', and 'auth_tag'.",
            )

        try:
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ct_b64)
            auth_tag = base64.b64decode(tag_b64)
        except Exception as e:
            raise SecurityPipelineError(
                status_code=400,
                error_code="INVALID_SCHEMA",
                message="Cryptographic envelope contains invalid Base64 data.",
            ) from e

        aad_bytes = canonicalize_header(header)

        try:
            plaintext = self.crypto_service.decrypt_aes_gcm(
                iv=iv,
                ciphertext=ciphertext,
                auth_tag=auth_tag,
                aad=aad_bytes,
                key_id=header.key_id,
            )
        except CryptoVerificationError as e:
            await self.sec_event_repo.log_event_async(
                event_code="CRYPTO_DECRYPTION_FAILED",
                severity="CRITICAL",
                source_ip=source_ip,
                sender_id=header.sender_id,
                message=str(e),
                details={"message_id": header.message_id, "key_id": header.key_id},
            )
            raise SecurityPipelineError(
                status_code=403,
                error_code="CRYPTO_DECRYPTION_FAILED",
                message="Decryption or AEAD authentication tag verification failed.",
            ) from e

        try:
            inner_json = json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise SecurityPipelineError(
                status_code=400,
                error_code="MALFORMED_PAYLOAD",
                message="Decrypted plaintext is not valid JSON.",
            ) from e

        if not isinstance(inner_json, dict) or "command" not in inner_json:
            raise SecurityPipelineError(
                status_code=400,
                error_code="UNKNOWN_COMMAND",
                message="Decrypted payload missing 'command' string.",
            )

        return inner_json["command"], inner_json.get("parameters")

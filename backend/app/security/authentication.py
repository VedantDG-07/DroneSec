"""Authentication and access control management for Ground Control Station clients."""

from __future__ import annotations

import hmac
import os
from typing import Optional, Set


DEFAULT_GCS_TOKENS: dict[str, str] = {
    "gcs_secret_token_alpha": "GCS_STATION_1",
    "gcs_secret_token_bravo": "GCS_STATION_2",
    "gcs_secret_token_admin": "GCS_ADMIN",
}


class AuthenticationError(Exception):
    """Raised when authentication credentials are missing, invalid, or unauthorized."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthenticationManager:
    """Manages Bearer token authentication and sender identity verification.
    
    Guarantees:
    1. Constant-time token verification (hmac.compare_digest) to prevent timing side-channels.
    2. Enforces sender authorization (authenticated client must match claimed sender_id).
    3. Credentials are kept out of error messages and audit details.
    """

    def __init__(
        self,
        token_registry: Optional[dict[str, str]] = None,
        authorized_senders: Optional[Set[str] | list[str]] = None,
        valid_bearer_token: Optional[str] = None,
    ) -> None:
        # Map of bearer_token -> client_id
        if token_registry is not None:
            self._tokens = dict(token_registry)
        elif valid_bearer_token is not None:
            sender = (
                list(authorized_senders)[0] if authorized_senders else "GCS-PRIMARY"
            )
            self._tokens = {valid_bearer_token: sender}
        elif "SIM_GCS_TOKENS" in os.environ:
            # Format: token1:client1,token2:client2
            self._tokens = {}
            for pair in os.environ["SIM_GCS_TOKENS"].split(","):
                if ":" in pair:
                    t, c = pair.strip().split(":", 1)
                    self._tokens[t] = c
        else:
            self._tokens = dict(DEFAULT_GCS_TOKENS)

        self._authorized_senders = (
            set(authorized_senders)
            if authorized_senders is not None
            else set(self._tokens.values())
        )

    def authenticate_header(self, authorization_header: Optional[str]) -> str:
        """Validate Authorization header containing 'Bearer <token>'.
        
        Returns authenticated client_id if valid; raises AuthenticationError otherwise.
        """
        if not authorization_header:
            raise AuthenticationError(
                code="AUTH_TOKEN_MISSING",
                message="HTTP Authorization header is required.",
            )

        parts = authorization_header.strip().split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationError(
                code="AUTH_TOKEN_INVALID",
                message="Invalid Authorization header format. Expected 'Bearer <token>'.",
            )

        token = parts[1]
        matched_client_id: Optional[str] = None

        # Constant-time comparison across all registered tokens
        for valid_token, client_id in self._tokens.items():
            if hmac.compare_digest(token, valid_token):
                matched_client_id = client_id
                break

        if not matched_client_id:
            raise AuthenticationError(
                code="AUTH_TOKEN_INVALID",
                message="Provided Bearer token is invalid or unauthorized.",
            )

        return matched_client_id

    def verify_sender_authorization(self, authenticated_client_id: str, claimed_sender_id: str) -> None:
        """Verify that the authenticated client is authorized to transmit commands as claimed_sender_id."""
        # Admin can represent any station; otherwise authenticated client must match sender_id exactly
        if authenticated_client_id == "GCS_ADMIN":
            return

        if not hmac.compare_digest(authenticated_client_id, claimed_sender_id):
            raise AuthenticationError(
                code="AUTH_TOKEN_INVALID",
                message=f"Authenticated client '{authenticated_client_id}' is not authorized to act as '{claimed_sender_id}'.",
            )

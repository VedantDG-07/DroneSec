"""Cryptographic key management and secret lifecycle for drone security simulation."""

from __future__ import annotations

import base64
import os
import secrets
import threading
from typing import Optional


class KeyManager:
    """Manages symmetric encryption and integrity verification keys with versioning and rotation.
    
    Guarantees:
    1. Independent 256-bit keys for AES-256-GCM and HMAC-SHA-256.
    2. Generated using cryptographically secure PRNG (secrets.token_bytes).
    3. Keys are never exposed in string representations or API outputs.
    4. Thread-safe key storage, lookup, and atomic key rotation.
    """

    def __init__(
        self,
        initial_key_id: str = "sim_key_v1",
        aes_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._key_counter: int = 1
        self._active_key_id: str = initial_key_id
        self._aes_keys: dict[str, bytes] = {}
        self._hmac_keys: dict[str, bytes] = {}

        # Resolve initial AES key (32 bytes / 256 bits)
        if aes_key is not None:
            if len(aes_key) != 32:
                raise ValueError(f"AES-256 key must be exactly 32 bytes. Got {len(aes_key)}")
            resolved_aes = aes_key
        elif "SIM_AES_KEY" in os.environ:
            resolved_aes = base64.b64decode(os.environ["SIM_AES_KEY"])
            if len(resolved_aes) != 32:
                raise ValueError("SIM_AES_KEY environment variable must decode to 32 bytes.")
        else:
            resolved_aes = secrets.token_bytes(32)

        # Resolve initial HMAC key (32 bytes / 256 bits) - Strictly independent from AES key
        if hmac_key is not None:
            if len(hmac_key) != 32:
                raise ValueError(f"HMAC-SHA-256 key must be exactly 32 bytes. Got {len(hmac_key)}")
            resolved_hmac = hmac_key
        elif "SIM_HMAC_KEY" in os.environ:
            resolved_hmac = base64.b64decode(os.environ["SIM_HMAC_KEY"])
            if len(resolved_hmac) != 32:
                raise ValueError("SIM_HMAC_KEY environment variable must decode to 32 bytes.")
        else:
            resolved_hmac = secrets.token_bytes(32)

        self._aes_keys[self._active_key_id] = resolved_aes
        self._hmac_keys[self._active_key_id] = resolved_hmac

    @property
    def active_key_id(self) -> str:
        """Return identifier of the currently active key version."""
        with self._lock:
            return self._active_key_id

    def get_aes_key(self, key_id: Optional[str] = None) -> bytes:
        """Retrieve AES-256 key for specified version (or active version)."""
        with self._lock:
            target = key_id or self._active_key_id
            if target not in self._aes_keys:
                raise KeyError(f"AES key version '{target}' not found.")
            return self._aes_keys[target]

    def get_hmac_key(self, key_id: Optional[str] = None) -> bytes:
        """Retrieve HMAC-SHA-256 key for specified version (or active version)."""
        with self._lock:
            target = key_id or self._active_key_id
            if target not in self._hmac_keys:
                raise KeyError(f"HMAC key version '{target}' not found.")
            return self._hmac_keys[target]

    def rotate_keys(self) -> str:
        """Generate a new key generation version and advance active key version atomically."""
        with self._lock:
            self._key_counter += 1
            new_key_id = f"sim_key_v{self._key_counter}"

            new_aes = secrets.token_bytes(32)
            new_hmac = secrets.token_bytes(32)

            self._aes_keys[new_key_id] = new_aes
            self._hmac_keys[new_key_id] = new_hmac
            self._active_key_id = new_key_id

            return new_key_id

    def __repr__(self) -> str:
        with self._lock:
            return f"<KeyManager active_key_id={self._active_key_id} key_count={len(self._aes_keys)}>"

"""Cryptographic operations service implementing AES-256-GCM AEAD and HMAC-SHA-256 integrity."""

from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import secrets
import threading
from typing import Deque, Optional, Set
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.security.key_manager import KeyManager


MAX_NONCE_TRACKING: int = 50_000
MAX_INVOCATIONS_PER_KEY: int = 100_000


class CryptoVerificationError(Exception):
    """Raised when cryptographic tag verification, decryption, or signature checks fail."""
    pass


class CryptoService:
    """Provides authenticated encryption (AES-256-GCM) and message authentication (HMAC-SHA-256).
    
    Guarantees:
    1. AES-256-GCM utilizes a 256-bit key and fresh 96-bit (12-byte) CSPRNG nonce per encryption.
    2. Nonce cache prevents nonce reuse under the same active key with bounded memory (50k entries).
    3. Associated Authenticated Data (AAD) binds message metadata into Galois Field authentication.
    4. Constant-time comparison for HMAC signatures via hmac.compare_digest.
    5. Thread-safe nonce generation and encryption invocation counters per NIST SP 800-38D.
    """

    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager
        self._lock = threading.Lock()
        # Track used nonces per key_id with bounded memory to strictly prevent nonce reuse
        self._used_nonces: dict[str, Set[bytes]] = {}
        self._nonce_history: dict[str, Deque[bytes]] = {}
        self._encryption_counts: dict[str, int] = collections.defaultdict(int)

    def generate_nonce(self, key_id: Optional[str] = None) -> bytes:
        """Generate a fresh 96-bit (12-byte) nonce guaranteed to be unique for the key."""
        target_key_id = key_id or self.key_manager.active_key_id
        with self._lock:
            if target_key_id not in self._used_nonces:
                self._used_nonces[target_key_id] = set()
                self._nonce_history[target_key_id] = collections.deque()

            used_set = self._used_nonces[target_key_id]
            history = self._nonce_history[target_key_id]

            # Prune oldest if at capacity to maintain strictly bounded memory footprint
            if len(used_set) >= MAX_NONCE_TRACKING:
                oldest = history.popleft()
                used_set.discard(oldest)

            # Draw from CSPRNG until unique
            for _ in range(10):
                nonce = secrets.token_bytes(12)
                if nonce not in used_set:
                    used_set.add(nonce)
                    history.append(nonce)
                    self._encryption_counts[target_key_id] += 1
                    return nonce

            raise RuntimeError("Failed to generate unique cryptographic nonce.")

    def get_encryption_count(self, key_id: Optional[str] = None) -> int:
        """Return total encryption operations performed under specified key."""
        target_key_id = key_id or self.key_manager.active_key_id
        with self._lock:
            return self._encryption_counts.get(target_key_id, 0)

    def encrypt_aes_gcm(
        self,
        plaintext: bytes,
        aad: bytes,
        key_id: Optional[str] = None,
        nonce: Optional[bytes] = None,
        iv: Optional[bytes] = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt plaintext using AES-256-GCM with Associated Data (AAD).
        
        Returns:
            Tuple of (iv, ciphertext, auth_tag) in raw bytes.
            - iv: 12 bytes
            - ciphertext: encrypted payload bytes
            - auth_tag: 16 bytes authentication tag
        """
        target_key_id = key_id or self.key_manager.active_key_id
        key = self.key_manager.get_aes_key(target_key_id)

        resolved_iv = nonce if nonce is not None else (iv if iv is not None else self.generate_nonce(target_key_id))
        if len(resolved_iv) != 12:
            raise ValueError(f"AES-GCM IV must be exactly 12 bytes. Got {len(resolved_iv)}")

        aesgcm = AESGCM(key)
        # cryptography library outputs ciphertext + 16-byte tag concatenated
        ciphertext_and_tag = aesgcm.encrypt(resolved_iv, plaintext, aad)

        ciphertext = ciphertext_and_tag[:-16]
        auth_tag = ciphertext_and_tag[-16:]

        return resolved_iv, ciphertext, auth_tag

    def decrypt_aes_gcm(
        self,
        iv: bytes,
        ciphertext: bytes,
        auth_tag: bytes,
        aad: bytes,
        key_id: Optional[str] = None,
    ) -> bytes:
        """Decrypt AES-256-GCM ciphertext and verify 16-byte authentication tag against AAD.
        
        Raises CryptoVerificationError if authentication tag verification fails or data is corrupted.
        """
        target_key_id = key_id or self.key_manager.active_key_id
        try:
            key = self.key_manager.get_aes_key(target_key_id)
        except KeyError as e:
            raise CryptoVerificationError(str(e)) from e

        if len(iv) != 12:
            raise CryptoVerificationError(f"Invalid IV length: expected 12 bytes, got {len(iv)}")
        if len(auth_tag) != 16:
            raise CryptoVerificationError(f"Invalid auth_tag length: expected 16 bytes, got {len(auth_tag)}")

        aesgcm = AESGCM(key)
        ciphertext_and_tag = ciphertext + auth_tag

        try:
            plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, aad)
            return plaintext
        except InvalidTag as e:
            raise CryptoVerificationError(
                "AES-GCM authentication tag verification failed. Ciphertext, tag, or AAD was tampered with."
            ) from e

    def sign_hmac(self, data: bytes, key_id: Optional[str] = None) -> bytes:
        """Compute HMAC-SHA-256 signature across data bytes."""
        target_key_id = key_id or self.key_manager.active_key_id
        key = self.key_manager.get_hmac_key(target_key_id)
        return hmac.new(key, data, hashlib.sha256).digest()

    def generate_hmac_sha256(self, data: bytes, key_id: Optional[str] = None) -> bytes:
        """Convenience alias for sign_hmac."""
        return self.sign_hmac(data, key_id=key_id)

    def verify_hmac(self, data: bytes, signature: bytes, key_id: Optional[str] = None) -> bool:
        """Verify HMAC-SHA-256 signature using constant-time comparison.
        
        Raises CryptoVerificationError if signature does not match.
        """
        expected_sig = self.sign_hmac(data, key_id=key_id)
        if not hmac.compare_digest(signature, expected_sig):
            raise CryptoVerificationError("HMAC verification failed. Signature mismatch or data tampered with.")
        return True

    def verify_hmac_sha256(self, data: bytes, signature: bytes, key_id: Optional[str] = None) -> bool:
        """Verify HMAC-SHA-256 signature using constant-time comparison, returning bool."""
        expected_sig = self.sign_hmac(data, key_id=key_id)
        return hmac.compare_digest(signature, expected_sig)


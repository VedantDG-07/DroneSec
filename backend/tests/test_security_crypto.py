"""Unit tests for cryptographic engine and key manager (Phase 3)."""

from __future__ import annotations

import base64
import os
import pytest
from backend.app.security.crypto_service import CryptoService, CryptoVerificationError
from backend.app.security.key_manager import KeyManager


class TestKeyManager:
    """Verifies cryptographic key lifecycle, generation, separation, and versioning."""

    def test_random_key_generation(self) -> None:
        km = KeyManager()
        aes_key = km.get_aes_key()
        hmac_key = km.get_hmac_key()

        assert len(aes_key) == 32
        assert len(hmac_key) == 32
        # Strictly independent keys
        assert aes_key != hmac_key

    def test_key_rotation(self) -> None:
        km = KeyManager(initial_key_id="v1")
        v1_aes = km.get_aes_key("v1")
        v1_hmac = km.get_hmac_key("v1")

        new_key_id = km.rotate_keys()
        assert new_key_id != "v1"
        assert km.active_key_id == new_key_id

        v2_aes = km.get_aes_key(new_key_id)
        v2_hmac = km.get_hmac_key(new_key_id)

        assert v2_aes != v1_aes
        assert v2_hmac != v1_hmac
        # Older version still retrievable for decryption
        assert km.get_aes_key("v1") == v1_aes

    def test_invalid_key_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="AES-256 key must be exactly 32 bytes"):
            KeyManager(aes_key=b"too_short")

        with pytest.raises(ValueError, match="HMAC-SHA-256 key must be exactly 32 bytes"):
            KeyManager(hmac_key=b"also_too_short")

    def test_keys_never_exposed_in_repr(self) -> None:
        km = KeyManager()
        r = repr(km)
        assert "KeyManager" in r
        assert km.get_aes_key().hex() not in r
        assert km.get_hmac_key().hex() not in r


class TestCryptoServiceAESGCM:
    """Verifies AES-256-GCM AEAD encryption, decryption, authentication, and tamper resistance."""

    def test_aes_gcm_roundtrip(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        plaintext = b'{"command":"TAKEOFF","params":{"altitude":10.0}}'
        aad = b'{"sender_id":"GCS-PRIMARY","seq":1}'

        iv, ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, aad)

        assert len(iv) == 12  # 96-bit nonce
        assert len(tag) == 16  # 128-bit authentication tag
        assert ciphertext != plaintext

        decrypted = crypto.decrypt_aes_gcm(iv=iv, ciphertext=ciphertext, auth_tag=tag, aad=aad)
        assert decrypted == plaintext

    def test_fresh_nonce_generated_per_encryption(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        plaintext = b"identical_plaintext"
        aad = b"identical_aad"

        iv1, ct1, tag1 = crypto.encrypt_aes_gcm(plaintext, aad)
        iv2, ct2, tag2 = crypto.encrypt_aes_gcm(plaintext, aad)

        # IVs must never repeat
        assert iv1 != iv2
        # Different nonces produce different ciphertexts even for identical plaintexts
        assert ct1 != ct2

    def test_tampered_ciphertext_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        plaintext = b"sensitive command"
        aad = b"aad"
        iv, ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, aad)

        # Flip a bit in ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01

        with pytest.raises(CryptoVerificationError, match="tag verification failed"):
            crypto.decrypt_aes_gcm(iv=iv, ciphertext=bytes(tampered_ct), auth_tag=tag, aad=aad)

    def test_tampered_tag_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        plaintext = b"sensitive command"
        aad = b"aad"
        iv, ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, aad)

        tampered_tag = bytearray(tag)
        tampered_tag[-1] ^= 0xFF

        with pytest.raises(CryptoVerificationError, match="tag verification failed"):
            crypto.decrypt_aes_gcm(iv=iv, ciphertext=ciphertext, auth_tag=bytes(tampered_tag), aad=aad)

    def test_modified_aad_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        plaintext = b"payload"
        aad = b'{"seq":1}'
        modified_aad = b'{"seq":2}'
        iv, ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, aad)

        with pytest.raises(CryptoVerificationError, match="tag verification failed"):
            crypto.decrypt_aes_gcm(iv=iv, ciphertext=ciphertext, auth_tag=tag, aad=modified_aad)

    def test_invalid_iv_length_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        with pytest.raises(ValueError, match="IV must be exactly 12 bytes"):
            crypto.encrypt_aes_gcm(b"data", b"aad", iv=b"short_iv")

        with pytest.raises(CryptoVerificationError, match="Invalid IV length"):
            crypto.decrypt_aes_gcm(iv=b"bad_iv", ciphertext=b"ct", auth_tag=b"tag_16_bytes_long", aad=b"aad")

    def test_no_plaintext_leak_on_failure(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        try:
            crypto.decrypt_aes_gcm(b"garbage", b"123456789012", b"1234567890123456", b"aad")
        except CryptoVerificationError as exc:
            # Plaintext is not returned or leaked in exception
            assert not hasattr(exc, "plaintext")


class TestCryptoServiceHMAC:
    """Verifies HMAC-SHA-256 integrity generation and constant-time verification."""

    def test_hmac_generation_and_verification(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        data = b'{"command":"LAND","seq":42}'
        mac = crypto.generate_hmac_sha256(data)

        assert len(mac) == 32  # SHA-256 256 bits = 32 bytes
        # Must verify correctly
        assert crypto.verify_hmac_sha256(data, mac) is True

    def test_tampered_data_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        data = b'{"command":"LAND","seq":42}'
        mac = crypto.generate_hmac_sha256(data)

        tampered_data = b'{"command":"TAKEOFF","seq":42}'
        assert crypto.verify_hmac_sha256(tampered_data, mac) is False

    def test_tampered_mac_rejected(self) -> None:
        km = KeyManager()
        crypto = CryptoService(key_manager=km)

        data = b"message"
        mac = bytearray(crypto.generate_hmac_sha256(data))
        mac[0] ^= 0x01

        assert crypto.verify_hmac_sha256(data, bytes(mac)) is False

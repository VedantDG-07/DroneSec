"""Unit tests for the loopback-only Wireshark practical helper."""
import copy

import pytest

from backend.scripts.wireshark_lab import ensure_loopback, tamper_payload


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://[::1]:8000",
    ],
)
def test_loopback_urls_are_accepted(url: str) -> None:
    ensure_loopback(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000",
        "http://example.com:8000",
        "http://192.168.1.20:8000",
    ],
)
def test_non_loopback_or_non_http_urls_are_rejected(url: str) -> None:
    with pytest.raises(SystemExit):
        ensure_loopback(url)


def test_unsecured_tamper_changes_command() -> None:
    original = {"command": "MOVE_FORWARD", "client_id": "GCS_CLIENT"}
    changed = tamper_payload(original, "UNSECURED")

    assert original["command"] == "MOVE_FORWARD"
    assert changed["command"] == "MOVE_BACKWARD"


def test_hmac_tamper_changes_payload_but_not_signature() -> None:
    original = {
        "header": {"sender_id": "GCS-PRIMARY"},
        "payload": {"command": "MOVE_FORWARD"},
        "signature": "original-demo-signature",
    }
    changed = tamper_payload(original, "INTEGRITY_ONLY")

    assert original["payload"]["command"] == "MOVE_FORWARD"
    assert changed["payload"]["command"] == "MOVE_BACKWARD"
    assert changed["signature"] == original["signature"]


def test_aes_gcm_tamper_changes_ciphertext_not_auth_tag() -> None:
    original = {
        "header": {"sender_id": "GCS-PRIMARY"},
        "ciphertext": "AbCdEf==",
        "auth_tag": "unchanged-auth-tag",
    }
    changed = tamper_payload(original, "ENCRYPTED_AUTHENTICATED")

    assert changed["ciphertext"] != original["ciphertext"]
    assert changed["auth_tag"] == original["auth_tag"]
    assert original["ciphertext"] == "AbCdEf=="


def test_tamper_helper_does_not_mutate_nested_input() -> None:
    original = {
        "header": {"sender_id": "GCS-PRIMARY"},
        "payload": {"command": "MOVE_FORWARD"},
        "signature": "signature",
    }
    snapshot = copy.deepcopy(original)

    tamper_payload(original, "INTEGRITY_ONLY")

    assert original == snapshot

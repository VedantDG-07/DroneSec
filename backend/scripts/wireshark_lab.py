"""Run a controlled DroneSec command-traffic experiment for Wireshark.

Only loopback HTTP URLs are accepted. This script exercises the real FastAPI
command endpoint and the existing security pipeline; it does not contact any
external host or physical drone.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

import httpx

MODES = ("UNSECURED", "INTEGRITY_ONLY", "ENCRYPTED_AUTHENTICATED")
ACTIONS = ("send", "replay", "tamper")
DEMO_TOKEN = "gcs-sim-token-secret-2026"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Local DroneSec URL (loopback only; default: %(default)s)",
    )
    parser.add_argument("--mode", choices=MODES, default="UNSECURED")
    parser.add_argument("--action", choices=ACTIONS, default="send")
    parser.add_argument(
        "--token",
        default=os.getenv("SIM_GCS_BEARER_TOKEN", DEMO_TOKEN),
        help="Local demo bearer token (or set SIM_GCS_BEARER_TOKEN)",
    )
    return parser.parse_args()


def ensure_loopback(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(
            "Safety stop: --base-url must be an http:// loopback address "
            "(127.0.0.1, localhost, or ::1)."
        )


def show_response(label: str, response: httpx.Response) -> None:
    try:
        body = response.json()
    except ValueError:
        body = response.text[:300]
    print(f"\n{label}: HTTP {response.status_code}")
    print(json.dumps(body, indent=2, ensure_ascii=False))


def request_json(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    payload: dict | None = None,
    auth: bool = True,
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {client.headers['X-Demo-Token']}"} if auth else {}
    return client.request(method, path, json=payload, headers=headers)


def build_command_payload(
    client: httpx.Client,
    mode: str,
    sequence: int,
) -> dict:
    response = request_json(
        client,
        "POST",
        "/api/drone/command/pack",
        payload={
            "command": "MOVE_FORWARD",
            "parameters": {"distance_meters": 1.0},
            "sender_id": "GCS-PRIMARY",
            "sequence_number": sequence,
        },
    )
    show_response("Pack command", response)
    response.raise_for_status()
    return response.json()["data"]["payload"]


def tamper_payload(payload: dict, mode: str) -> dict:
    """Alter the command/ciphertext while retaining any existing authenticator."""
    changed = json.loads(json.dumps(payload))

    if mode == "UNSECURED":
        # There is no cryptographic envelope, so the command is directly editable.
        changed["command"] = "MOVE_BACKWARD"
    elif mode == "INTEGRITY_ONLY":
        # Keep the original HMAC signature while modifying its signed payload.
        changed["payload"]["command"] = "MOVE_BACKWARD"
    else:
        # Flip one printable Base64 character; keep the original GCM tag.
        ciphertext = changed["ciphertext"]
        replacement = "A" if not ciphertext or ciphertext[0] != "A" else "B"
        changed["ciphertext"] = replacement + ciphertext[1:]

    return changed


def main() -> int:
    args = parse_args()
    ensure_loopback(args.base_url)
    base_url = args.base_url.rstrip("/")
    headers = {"X-Demo-Token": args.token}

    try:
        with httpx.Client(base_url=base_url, headers=headers, timeout=5.0) as client:
            health = request_json(client, "GET", "/health", auth=False)
            show_response("Local DroneSec health", health)
            health.raise_for_status()

            mode_response = request_json(
                client,
                "POST",
                "/api/security/mode",
                payload={"mode": args.mode, "reason": "Wireshark practical lab"},
            )
            show_response("Set security mode", mode_response)
            mode_response.raise_for_status()

            # A fresh sequence per invocation; replay reuses the exact same envelope.
            sequence = int(time.time())
            payload = build_command_payload(client, args.mode, sequence)

            if args.action == "tamper":
                submitted = tamper_payload(payload, args.mode)
                print("\nTampering experiment: changed MOVE_FORWARD to MOVE_BACKWARD "
                      "in the request, without recomputing any authenticator.")
                response = request_json(
                    client, "POST", "/api/drone/command", payload=submitted
                )
                show_response("Tampered command", response)
                return 0

            first = request_json(client, "POST", "/api/drone/command", payload=payload)
            show_response("Command request", first)

            if args.action == "replay":
                print("\nReplay experiment: sending the exact same request envelope again.")
                replay = request_json(client, "POST", "/api/drone/command", payload=payload)
                show_response("Replayed command", replay)

            return 0

    except httpx.ConnectError:
        print(
            "Could not connect to DroneSec. Start it first with:\n"
            "uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload",
            file=sys.stderr,
        )
        return 2
    except httpx.HTTPError as exc:
        print(f"HTTP request failed: {exc}", file=sys.stderr)
        return 2
    except (KeyError, ValueError) as exc:
        print(f"Unexpected API response: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

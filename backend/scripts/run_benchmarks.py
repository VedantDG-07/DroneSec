"""Reproducible local benchmark harness for DroneSec simulation platform.

Measures:
1. Command Execution Latency (UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED).
2. Telemetry delivery timing & tick loop intervals.
3. Concurrent command handling & state version consistency.
4. Bounded cyberattack scenario execution.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.core.drone_engine import DroneEngine
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager
from backend.app.security.message_protocol import (
    SecurityMode,
    pack_encrypted_command,
    pack_hmac_command,
)
from backend.app.security.key_manager import KeyManager
from backend.app.security.crypto_service import CryptoService


def get_environment_info() -> dict[str, str]:
    return {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "sqlite_version": sqlite3.sqlite_version,
    }


def benchmark_command_latency(
    client: TestClient,
    crypto: CryptoService,
    key_manager: KeyManager,
    token: str,
    samples: int = 100,
) -> dict[str, Any]:
    results = {}
    modes = [
        (SecurityMode.UNSECURED, "UNSECURED"),
        (SecurityMode.INTEGRITY_ONLY, "INTEGRITY_ONLY"),
        (SecurityMode.ENCRYPTED_AUTHENTICATED, "ENCRYPTED_AUTHENTICATED"),
    ]

    for mode_enum, mode_name in modes:
        # Switch mode
        client.post(
            "/api/security/mode",
            headers={"Authorization": f"Bearer {token}"},
            json={"mode": mode_name, "reason": "Benchmarking"},
        )

        latencies_ms = []
        errors = 0
        seq = 1

        # Arm and takeoff first to allow movement commands
        if mode_enum == SecurityMode.UNSECURED:
            client.post("/api/drone/command", json={"command": "ARM"})
            client.post("/api/drone/command", json={"command": "TAKEOFF", "parameters": {"altitude": 10.0}})
        elif mode_enum == SecurityMode.INTEGRITY_ONLY:
            p = pack_hmac_command(crypto, "ARM", None, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
            seq += 1
            client.post("/api/drone/command", json=p, headers={"Authorization": f"Bearer {token}"})
            p = pack_hmac_command(crypto, "TAKEOFF", {"altitude": 10.0}, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
            seq += 1
            client.post("/api/drone/command", json=p, headers={"Authorization": f"Bearer {token}"})
        else:
            p = pack_encrypted_command(crypto, "ARM", None, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
            seq += 1
            client.post("/api/drone/command", json=p, headers={"Authorization": f"Bearer {token}"})
            p = pack_encrypted_command(crypto, "TAKEOFF", {"altitude": 10.0}, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
            seq += 1
            client.post("/api/drone/command", json=p, headers={"Authorization": f"Bearer {token}"})

        for i in range(samples):
            cmd = "MOVE_FORWARD" if i % 2 == 0 else "MOVE_BACKWARD"
            params = {"distance": 1.0}

            t0 = time.perf_counter()
            if mode_enum == SecurityMode.UNSECURED:
                res = client.post("/api/drone/command", json={"command": cmd, "parameters": params})
            elif mode_enum == SecurityMode.INTEGRITY_ONLY:
                payload = pack_hmac_command(crypto, cmd, params, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
                seq += 1
                res = client.post("/api/drone/command", json=payload, headers={"Authorization": f"Bearer {token}"})
            else:
                payload = pack_encrypted_command(crypto, cmd, params, sender_id="GCS-BENCH", sequence_number=seq, timestamp=time.time(), key_id=key_manager.active_key_id)
                seq += 1
                res = client.post("/api/drone/command", json=payload, headers={"Authorization": f"Bearer {token}"})
            t1 = time.perf_counter()

            if res.status_code == 200:
                latencies_ms.append((t1 - t0) * 1000.0)
            else:
                if errors == 0:
                    print(f"    DEBUG {mode_name} Error: HTTP {res.status_code} -> {res.text}")
                errors += 1

        sorted_lat = sorted(latencies_ms)
        p50 = statistics.median(sorted_lat) if sorted_lat else 0.0
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if sorted_lat else 0.0
        mean = statistics.mean(sorted_lat) if sorted_lat else 0.0

        results[mode_name] = {
            "samples": len(latencies_ms),
            "errors": errors,
            "min_ms": round(sorted_lat[0], 2) if sorted_lat else 0.0,
            "mean_ms": round(mean, 2),
            "median_p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "max_ms": round(sorted_lat[-1], 2) if sorted_lat else 0.0,
        }

    return results


def benchmark_attack_scenarios(client: TestClient, token: str) -> dict[str, Any]:
    attacks = [
        "COMMAND_REPLAY",
        "MESSAGE_TAMPERING",
        "BOUNDED_FLOODING",
        "SENDER_SPOOFING",
    ]
    results = {}

    # Switch to ENCRYPTED_AUTHENTICATED mode to benchmark defense evaluation
    client.post(
        "/api/security/mode",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "ENCRYPTED_AUTHENTICATED", "reason": "Attack Benchmark"},
    )

    for att in attacks:
        t0 = time.perf_counter()
        res = client.post(
            f"/api/attacks/{att}",
            headers={"Authorization": f"Bearer {token}"},
            json={"parameters": {}},
        )
        t1 = time.perf_counter()

        duration_ms = (t1 - t0) * 1000.0
        if res.status_code == 200:
            payload = res.json()
            data = payload.get("data", {})
            results[att] = {
                "status_code": res.status_code,
                "duration_ms": round(duration_ms, 2),
                "attack_result": data.get("attack_result"),
                "defense_triggered": data.get("defense_triggered"),
                "state_compromised": data.get("state_compromised"),
            }
        else:
            print(f"    DEBUG Attack {att} Error: HTTP {res.status_code} -> {res.text}")
            results[att] = {
                "status_code": res.status_code,
                "duration_ms": round(duration_ms, 2),
                "error": res.json() if res.headers.get("content-type") == "application/json" else res.text,
            }

    return results


def benchmark_concurrency(client: TestClient, samples: int = 30) -> dict[str, Any]:
    # Switch to UNSECURED mode for raw concurrency benchmark
    client.post(
        "/api/security/mode",
        json={"mode": "UNSECURED", "reason": "Concurrency Benchmark"},
    )
    # Ensure drone is armed and flying
    client.post("/api/drone/command", json={"command": "ARM"})
    client.post("/api/drone/command", json={"command": "TAKEOFF", "parameters": {"altitude": 10.0}})

    initial_state = client.get("/api/drone/state").json()["data"]
    start_v = initial_state["state_version"]

    errors = 0
    t0 = time.perf_counter()

    def send_cmd(i: int):
        nonlocal errors
        cmd = "MOVE_FORWARD" if i % 2 == 0 else "MOVE_BACKWARD"
        res = client.post("/api/drone/command", json={"command": cmd, "parameters": {"distance": 0.5}})
        if res.status_code != 200:
            errors += 1

    threads = [threading.Thread(target=send_cmd, args=(i,)) for i in range(samples)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_time_ms = (time.perf_counter() - t0) * 1000.0
    final_state = client.get("/api/drone/state").json()["data"]
    final_v = final_state["state_version"]
    version_diff = final_v - start_v

    return {
        "concurrent_requests": samples,
        "successful_updates": version_diff,
        "errors": errors,
        "total_time_ms": round(total_time_ms, 2),
        "throughput_cmds_per_sec": round(samples / (total_time_ms / 1000.0), 2) if total_time_ms > 0 else 0.0,
        "version_invariance_maintained": (version_diff == (samples - errors)),
    }


def benchmark_telemetry(client: TestClient, count: int = 50) -> dict[str, Any]:
    # Query rolling telemetry buffer
    res = client.get(f"/api/drone/telemetry?limit={count}")
    if res.status_code == 200:
        samples = res.json().get("data", [])
        if len(samples) >= 2:
            intervals = [
                samples[i]["timestamp"] - samples[i+1]["timestamp"]
                for i in range(len(samples)-1)
            ]
            intervals_ms = [abs(dt) * 1000.0 for dt in intervals if dt != 0]
            if intervals_ms:
                return {
                    "count": len(samples),
                    "mean_interval_ms": round(statistics.mean(intervals_ms), 2),
                    "median_interval_ms": round(statistics.median(intervals_ms), 2),
                    "p95_interval_ms": round(sorted(intervals_ms)[int(len(intervals_ms) * 0.95)], 2),
                }
    return {"count": 0, "mean_interval_ms": 0.0, "median_interval_ms": 0.0, "p95_interval_ms": 0.0}


def main():
    print("=" * 70)
    print(" DRONESEC SECURITY & RELIABILITY BENCHMARK SUITE")
    print("=" * 70)

    env_info = get_environment_info()
    for k, v in env_info.items():
        print(f"  {k:18}: {v}")
    print("-" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "benchmark.db")
        token = "bench-secret-token-2026"
        cfg = AppConfig(
            db_path=db_path,
            gcs_bearer_token=token,
            authorized_sender="GCS-BENCH",
            rate_limit_capacity=1000.0,
            rate_limit_refill_rate=500.0,
            telemetry_interval_seconds=0.05,
            simulation_tick_rate_hz=20.0,
        )
        db_mgr = DatabaseManager(db_path)
        app = create_app(app_config=cfg, db_manager=db_mgr)

        # Use app's actual security service to ensure identical key agreement
        sec_service = app.state.security_service
        km = sec_service.key_manager
        crypto = sec_service.crypto_service

        with TestClient(app) as client:
            print("\n1. Measuring Command Latency Across Security Modes (N=100 per mode)...")
            cmd_results = benchmark_command_latency(client, crypto, km, token, samples=100)
            print(f"  {'Mode':<26} | {'Samples':<8} | {'p50 (ms)':<9} | {'p95 (ms)':<9} | {'Errors'}")
            print("  " + "-" * 62)
            for mode, stats in cmd_results.items():
                print(f"  {mode:<26} | {stats['samples']:<8} | {stats['median_p50_ms']:<9} | {stats['p95_ms']:<9} | {stats['errors']}")

            print("\n2. Measuring Concurrent Command Handling (N=30 concurrent threads)...")
            conc_results = benchmark_concurrency(client, samples=30)
            print(f"  Requests Dispatched   : {conc_results['concurrent_requests']}")
            print(f"  Successful State Sync : {conc_results['successful_updates']}")
            print(f"  Errors Encountered    : {conc_results['errors']}")
            print(f"  Total Wall Time (ms)  : {conc_results['total_time_ms']}")
            print(f"  Throughput (cmds/sec) : {conc_results['throughput_cmds_per_sec']}")
            print(f"  State Invariance Pass : {conc_results['version_invariance_maintained']}")

            print("\n3. Measuring Telemetry Tick Loop Intervals (20 Hz target / 50ms)...")
            time.sleep(1.0)  # Allow telemetry loop to accumulate samples
            telem_results = benchmark_telemetry(client, count=30)
            print(f"  Samples Analyzed      : {telem_results['count']}")
            print(f"  Mean Interval (ms)    : {telem_results['mean_interval_ms']}")
            print(f"  Median Interval (ms)  : {telem_results['median_interval_ms']}")
            print(f"  p95 Interval (ms)     : {telem_results['p95_interval_ms']}")

            print("\n4. Measuring Bounded Attack Scenario Execution...")
            attack_results = benchmark_attack_scenarios(client, token)
            print(f"  {'Scenario':<24} | {'Duration (ms)':<14} | {'Result':<20} | {'Defense'}")
            print("  " + "-" * 74)
            for att, r in attack_results.items():
                print(f"  {att:<24} | {r.get('duration_ms', 0):<14} | {str(r.get('attack_result')):<20} | {r.get('defense_triggered')}")

    print("\n" + "=" * 70)
    print(" BENCHMARK COMPLETE - ALL METRICS COLLECTED FROM LOCAL ENVIRONMENT")
    print("=" * 70)


if __name__ == "__main__":
    main()

# DroneSec: Phase 6 Security Evaluation & Benchmarking Report

**Run Identifier:** `eval_1792180539_3a89e9`  
**Execution Timestamp:** 2026-10-16 19:55:39 UTC  
**Run Status:** `COMPLETED`  
**Integration Verification Gate:** `PASSED`  
**Total Experiments Evaluated:** 21 of 21  

---

## 1. Executive Summary

Phase 6 provides rigorous, empirical security benchmarking across the three supported operational modes:
- **`UNSECURED`:** Plaintext JSON without authentication or signatures (baseline vulnerability demonstration).
- **`INTEGRITY_ONLY`:** Authenticated envelope with HMAC-SHA-256 and Bearer tokens (tampering and spoofing defenses).
- **`ENCRYPTED_AUTHENTICATED`:** AES-256-GCM AEAD encryption with sliding-window anti-replay (full confidentiality, integrity, authenticity).

All experiments were conducted against the local software-in-the-loop (SITL) simulated drone engine. Authoritative state invariants and strict atomicity were continuously verified.

---

## 2. Evaluation Methodology & Safety Isolation

- **Local Execution Only:** Zero requests were routed across external networks or public interfaces.
- **Synthetic Test Credentials:** Synthetic Bearer tokens (`gcs-sim-token-secret-2026`) and dedicated test key material were used.
- **Deterministic Isolation:** Between test scenarios, the authoritative simulation engine was reset to controlled baselines.
- **FSM vs Security Separation:** Attacks evaluating coordinate movement were initiated with an airborne hovering drone to guarantee rejections resulted from cryptographic defenses rather than baseline flight-state disarming.
- **No Key Logging:** Sensitive keys and credentials are never logged or exported.

---

## 3. Metric Definitions

| Metric | Formula | Description |
|---|---|---|
| **Unauthorized State-Mutation Rate** | $\frac{\text{Mutations Caused by Attacks}}{\text{Total Attack Attempts}}$ | Proportion of adversarial attempts that mutated authoritative state. (Target: 0% in secured modes). |
| **Attack Rejection Rate** | $\frac{\text{Attacks Rejected by Security}}{\text{Total Attack Attempts}}$ | Proportion of adversarial payloads terminated by cryptographic / authentication pipeline. |
| **Security Detection Rate** | $\frac{\text{Scenarios with Logged Defense}}{\text{Total Attack Scenarios}}$ | Coverage of explicit security audit incident logging. |
| **Replay Rejection Rate** | $\frac{\text{Replayed Packets Rejected}}{\text{Total Replayed Packets Submitted}}$ | Effectiveness of anti-replay sliding window (64-frame) and timestamp freshness ($|\Delta t| \le 5.0$s). |
| **Legitimate-Command Success Rate** | $\frac{\text{Valid Commands Executed}}{\text{Valid Commands Attempted}}$ | Operational availability for legitimate GCS operator commands. |
| **Command Latency (p50 / p95)** | Percentiles over measured $\Delta t$ (ms) | End-to-end processing latency including cryptographic verification. |

---

## 4. Benchmark Results Comparison Matrix

| Operating Mode | Attack Attempts | Mutation Rate | Attack Rejection | Detection Rate | Replay Rejection | Legit Success | Median Latency | p95 Latency | Rate Limits |
|---|---|---|---|---|---|---|---|---|---|
| **`ENCRYPTED_AUTHENTICATED`** | 49 | 0.0% | 83.7% | 100.0% | 50.0% | 100.0% | 10.09 ms | 14.17 ms | 7 |
| **`INTEGRITY_ONLY`** | 49 | 0.0% | 83.7% | 100.0% | 100.0% | 100.0% | 9.80 ms | 13.95 ms | 8 |
| **`UNSECURED`** | 49 | 83.7% | 8.2% | 100.0% | 0.0% | 100.0% | 9.45 ms | 11.48 ms | 8 |

### Mode Evaluation Notes

- **`ENCRYPTED_AUTHENTICATED`**: Production-grade authenticated encryption using AES-256-GCM (AEAD) with HKDF key derivation, 64-frame anti-replay sliding window, and Bearer authentication. Guarantees confidentiality, integrity, authenticity, and replay prevention.
- **`INTEGRITY_ONLY`**: Provides message integrity and sender authentication via HMAC-SHA-256 and Bearer tokens. Guarantees tampering detection and identity verification, but DOES NOT provide confidentiality (telemetry and command coordinates remain visible in transit).
- **`UNSECURED`**: Baseline comparison mode. Transmits raw unencrypted payloads without authentication, cryptographic signatures, or replay filters. Demonstrates clear vulnerability to injection, tampering, replay, and spoofing. NOT RECOMMENDED for production or operational deployment.

---

## 5. Experiment Breakdown

| Mode | Scenario | Attempts | Accepted | Rej (Sec) | Rej (Eng) | Defense Code | Mutated? | Result | Latency (p50) |
|---|---|---|---|---|---|---|---|---|---|
| `UNSECURED` | `UNAUTHORIZED_COMMAND` | 3 | 1 | 0 | 2 | `NONE` | **YES** | `PASS` | 8.79 ms |
| `UNSECURED` | `MESSAGE_TAMPERING` | 3 | 3 | 0 | 0 | `NONE` | **YES** | `PASS` | 9.05 ms |
| `UNSECURED` | `COMMAND_REPLAY` | 2 | 2 | 0 | 0 | `NONE` | **YES** | `PASS` | 9.23 ms |
| `UNSECURED` | `SENDER_SPOOFING` | 3 | 1 | 0 | 2 | `NONE` | **YES** | `PASS` | 9.34 ms |
| `UNSECURED` | `MALFORMED_FUZZING` | 8 | 0 | 4 | 4 | `INVALID_SCHEMA` | NO | `PASS` | 9.11 ms |
| `UNSECURED` | `BOUNDED_FLOODING` | 30 | 1 | 0 | 21 | `RATE_LIMIT_EXCEEDED` | **YES** | `PASS` | 10.02 ms |
| `UNSECURED` | `LEGITIMATE_FLIGHT_CYCLE` | 4 | 4 | 0 | 0 | `NONE` | **YES** | `PASS` | 10.06 ms |
| `INTEGRITY_ONLY` | `UNAUTHORIZED_COMMAND` | 3 | 0 | 3 | 0 | `AUTH_TOKEN_MISSING` | NO | `PASS` | 9.58 ms |
| `INTEGRITY_ONLY` | `MESSAGE_TAMPERING` | 3 | 0 | 3 | 0 | `HMAC_VERIFICATION_FAILED` | NO | `PASS` | 14.55 ms |
| `INTEGRITY_ONLY` | `COMMAND_REPLAY` | 2 | 0 | 2 | 0 | `SECURITY_MODE_MISMATCH` | NO | `PASS` | 13.63 ms |
| `INTEGRITY_ONLY` | `SENDER_SPOOFING` | 3 | 0 | 3 | 0 | `SECURITY_MODE_MISMATCH` | NO | `PASS` | 12.91 ms |
| `INTEGRITY_ONLY` | `MALFORMED_FUZZING` | 8 | 0 | 8 | 0 | `AUTH_TOKEN_MISSING` | NO | `PASS` | 11.46 ms |
| `INTEGRITY_ONLY` | `BOUNDED_FLOODING` | 30 | 0 | 22 | 0 | `RATE_LIMIT_EXCEEDED` | NO | `PASS` | 9.53 ms |
| `INTEGRITY_ONLY` | `LEGITIMATE_FLIGHT_CYCLE` | 4 | 4 | 0 | 0 | `NONE` | **YES** | `PASS` | 10.02 ms |
| `ENCRYPTED_AUTHENTICATED` | `UNAUTHORIZED_COMMAND` | 3 | 0 | 3 | 0 | `AUTH_TOKEN_MISSING` | NO | `PASS` | 9.93 ms |
| `ENCRYPTED_AUTHENTICATED` | `MESSAGE_TAMPERING` | 3 | 0 | 3 | 0 | `CRYPTO_DECRYPTION_FAILED` | NO | `PASS` | 9.92 ms |
| `ENCRYPTED_AUTHENTICATED` | `COMMAND_REPLAY` | 2 | 1 | 1 | 0 | `REPLAY_ATTACK_DETECTED` | NO | `PASS` | 10.60 ms |
| `ENCRYPTED_AUTHENTICATED` | `SENDER_SPOOFING` | 3 | 0 | 3 | 0 | `SPOOFED_GCS_IDENTITY` | NO | `PASS` | 9.32 ms |
| `ENCRYPTED_AUTHENTICATED` | `MALFORMED_FUZZING` | 8 | 0 | 8 | 0 | `AUTH_TOKEN_MISSING` | NO | `PASS` | 9.58 ms |
| `ENCRYPTED_AUTHENTICATED` | `BOUNDED_FLOODING` | 30 | 0 | 23 | 0 | `RATE_LIMIT_EXCEEDED` | NO | `PASS` | 11.66 ms |
| `ENCRYPTED_AUTHENTICATED` | `LEGITIMATE_FLIGHT_CYCLE` | 4 | 4 | 0 | 0 | `NONE` | **YES** | `PASS` | 9.65 ms |

---

## 6. System Limitations & Reproducibility

### Limitations
1. **Software-in-the-Loop Simulation:** Flight dynamics and kinematics operate deterministically at 20 Hz without sensor drift, wind shear, or physical aerodynamic perturbations.
2. **Single-Node Localhost Testing:** Network packet transmission simulates radio link latency in software; RF packet loss, jamming, and physical signal degradation are not modeled.
3. **In-Memory Cryptography:** Keys reside in backend process memory (`KeyManager`) without hardware security module (HSM) or secure enclave backing.

### Local Reproducibility Instructions
To reproduce this evaluation locally:
1. Start the DroneSec backend server: `python -m uvicorn backend.app.main:app --port 8000`
2. Execute the verification gate: `curl -X POST http://127.0.0.1:8000/api/evaluation/verify`
3. Run the full security benchmark: `curl -X POST http://127.0.0.1:8000/api/evaluation/run`
4. Fetch recorded metrics: `curl http://127.0.0.1:8000/api/evaluation/latest`
5. Export dataset as CSV/JSON: `curl http://127.0.0.1:8000/api/evaluation/export/csv -o benchmark.csv`

---
*Report automatically generated by DroneSec Phase 6 Evaluation Engine.*
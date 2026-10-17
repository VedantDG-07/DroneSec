# Empirical Experiment & Evaluation Summary

**Evaluation Run ID:** `eval_1792180539_3a89e9`  
**Execution Timestamp:** 2026-10-16 19:55:39 UTC  
**Environment:** Python 3.14.3, Windows 10 (AMD64), SQLite 3.50.4, FastAPI 0.115  
**Data Sources:**
- [`docs/results/experiment-summary.json`](file:///c:/Users/User/Documents/drone/docs/results/experiment-summary.json)
- [`docs/results/experiment-summary.csv`](file:///c:/Users/User/Documents/drone/docs/results/experiment-summary.csv)
- [`docs/results/benchmarks.json`](file:///c:/Users/User/Documents/drone/docs/results/benchmarks.json)

---

## 1. Metric Definitions & Denominators

| Metric Name | Formula / Denominator | Purpose |
|---|---|---|
| **Unauthorized State-Mutation Rate** | $\frac{\text{Attacks resulting in state version increase or coordinate displacement}}{\text{Total attack attempts submitted } (N=49)}$ | Measures failure of security controls to prevent unauthorized actuation. **Target: 0.0%**. |
| **Attack Rejection Rate** | $\frac{\text{Attacks rejected by security pipeline with } 401/403/422/429}{\text{Total attack attempts submitted } (N=49)}$ | Measures rate at which attack packets are explicitly blocked by security guards. |
| **Security Detection Rate** | $\frac{\text{Attack scenarios producing explicit security audit event}}{\text{Total attack scenarios executed } (N=6)}$ | Measures visibility of hostile activity in persistent audit logs. |
| **Replay Rejection Rate** | $\frac{\text{Replayed packets rejected by anti-replay sliding window or timestamp filter}}{\text{Total replayed packets submitted } (N=2)}$ | Measures resistance against frame capture and injection. |
| **Legitimate-Command Success Rate** | $\frac{\text{Legitimate operator flight commands executed}}{\text{Legitimate flight commands submitted } (N=4)}$ | Measures link availability and false rejection rate for authorized operators. |
| **End-to-End Command Latency ($p_{50} / p_{95}$)** | Measured duration (ms) from HTTP dispatch to response receipt | Measures latency impact of cryptographic processing under 100-sample loads. |

---

## 2. Comparative Evaluation Matrix

| Metric | `UNSECURED` | `INTEGRITY_ONLY` | `ENCRYPTED_AUTHENTICATED` |
|---|---|---|---|
| **Total Attack Attempts** | 49 | 49 | 49 |
| **State Mutations Caused** | **41** | **0** | **0** |
| **Unauthorized State-Mutation Rate** | **83.67%** | **0.00%** | **0.00%** |
| **Security Pipeline Rejections** | 4 (8.16%) | 41 (83.67%) | 41 (83.67%) |
| **Engine State Machine Rejections** | 4 (8.16%) | 0 (0.00%) | 0 (0.00%) |
| **Security Detection Rate** | 100.0% | 100.0% | 100.0% |
| **Replay Rejection Rate** | 0.0% (0/2) | 100.0% (2/2) | 50.0% (1/2)* |
| **Legitimate Command Success** | 100.0% (4/4) | 100.0% (4/4) | 100.0% (4/4) |
| **Median Latency ($p_{50}$)** | 9.45 ms (eval) / 12.17 ms (bench) | 9.80 ms (eval) / 12.37 ms (bench) | 10.09 ms (eval) / 12.66 ms (bench) |
| **95th Percentile Latency ($p_{95}$)** | 11.48 ms (eval) / 15.55 ms (bench) | 13.95 ms (eval) / 14.14 ms (bench) | 14.17 ms (eval) / 16.29 ms (bench) |
| **Rate Limiter Interceptions** | 8 | 8 | 7 |

*\*Note on Replay Rejection in `ENCRYPTED_AUTHENTICATED`: The two-packet replay sequence consists of Packet 1 (legitimate baseline command with fresh sequence number $s=1$, expected to execute) and Packet 2 (exact duplicate frame resubmitted, rejected with `REPLAY_ATTACK_DETECTED`). Thus, 1 of 2 packets was rejected as designed.*

---

## 3. Visual Comparisons

### State Mutation Rate Comparison
```
UNSECURED:               [████████████████████████████████████████] 83.67% (41/49 Compromised)
INTEGRITY_ONLY:          []                                          0.00% (0/49 Compromised)
ENCRYPTED_AUTHENTICATED: []                                          0.00% (0/49 Compromised)
```

### Security Pipeline Rejection Rate Comparison
```
UNSECURED:               [████]                                      8.16% (Schema baseline only)
INTEGRITY_ONLY:          [████████████████████████████████████████] 83.67% (All hostile payloads)
ENCRYPTED_AUTHENTICATED: [████████████████████████████████████████] 83.67% (All hostile payloads)
```

### Command Latency Distribution ($N=100$ Benchmark)
```
UNSECURED:               [p50: 12.17ms] ---- [p95: 15.55ms]
INTEGRITY_ONLY:          [p50: 12.37ms] ---- [p95: 14.14ms]
ENCRYPTED_AUTHENTICATED: [p50: 12.66ms] ------ [p95: 16.29ms]
```

---

## 4. Full 21-Experiment Breakdown

| Mode | Scenario Type | Attempts | Accepted | Rej (Sec) | Rej (Eng) | Defense Code | State Mutated? | Result | Median Latency |
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

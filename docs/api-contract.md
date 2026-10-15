# API Contract & Communication Specification
## Drone Communication Security Simulation Platform (Phase 0)

---

### Document Information
- **Project:** Drone Communication Security Simulation Platform
- **Phase:** Phase 0 — Requirements and Architecture Blueprint
- **Version:** 1.0.0
- **Status:** APPROVED FOR ARCHITECTURE
- **Classification:** Formal Interface Specification (REST & WebSockets)

---

## 1. Overview & Protocol Standards

The platform exposes two primary communication channels:
1. **REST API (HTTP/1.1):** Used for configuration, discrete flight commands, security mode changes, attack scenario injection, and querying historical logs and analytics.
2. **WebSocket Hub (RFC 6455):** Used for low-latency, real-time downstream telemetry broadcasting ($10\text{ Hz}$) and instant push notifications of security events.

### Standard Response Envelopes
All REST endpoints adhere to a standardized JSON response envelope.

#### Standard Success Envelope
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": 1729000000.123
}
```

#### Standard Error Envelope
```json
{
  "status": "error",
  "error": {
    "code": "SECURITY_SIGNATURE_INVALID",
    "message": "AES-GCM authentication tag verification failed. Payload may have been tampered with.",
    "details": {
      "sender_id": "GCS_ALPHA",
      "expected_mode": "ENCRYPTED_AUTHENTICATED"
    }
  },
  "timestamp": 1729000000.123
}
```

---

## 2. REST API Specification

### 2.1 System & Health

#### `GET /health`
Returns the operational health of the simulation backend, active background loop, and database.
- **Method:** `GET`
- **Auth:** None (Public)
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "system_status": "OPERATIONAL",
    "uptime_seconds": 1245.8,
    "simulation_loop": {
      "running": true,
      "tick_rate_hz": 20.0,
      "last_tick_timestamp": 1729000000.100
    },
    "database": {
      "status": "CONNECTED",
      "wal_mode": true
    },
    "memory_mb": 42.5
  },
  "timestamp": 1729000000.123
}
```

---

### 2.2 Drone Control & State

#### `GET /api/drone/state`
Returns the authoritative, real-time flight and kinematic state vector of the virtual drone.
- **Method:** `GET`
- **Auth:** Optional / Bearer Token
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "state_version": 4512,
    "timestamp": 1729000000.100,
    "flight_state": "HOVERING",
    "armed": true,
    "position": {
      "x": 12.0,
      "y": 5.0,
      "z": -4.0
    },
    "geographic": {
      "latitude": 37.774864,
      "longitude": -122.419263,
      "altitude_msl": 20.0
    },
    "motion": {
      "heading": 45.0,
      "speed": 0.0
    },
    "battery": {
      "level_percent": 94.2,
      "voltage_volts": 11.8,
      "state_of_health": "GOOD"
    },
    "last_command_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
  },
  "timestamp": 1729000000.123
}
```

---

#### `POST /api/drone/command`
Submits a flight command to the authoritative drone core. The request body structure depends on the active security mode:
- **In `UNSECURED` mode:** Accepts `PlainCommandRequest`.
- **In `INTEGRITY_ONLY` mode:** Accepts `HmacSignedCommandRequest`.
- **In `ENCRYPTED_AUTHENTICATED` mode:** Accepts `EncryptedCommandRequest`.

##### Plain Command Request Schema (`UNSECURED`)
```json
{
  "command": "MOVE_FORWARD",
  "parameters": {
    "distance_meters": 2.0
  },
  "client_id": "GCS_STATION_1"
}
```

##### Authenticated / Encrypted Command Request Schema (`ENCRYPTED_AUTHENTICATED`)
```json
{
  "header": {
    "message_id": "1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
    "sender_id": "GCS_STATION_1",
    "sequence_number": 104,
    "timestamp": 1729000000.110,
    "security_mode": "ENCRYPTED_AUTHENTICATED",
    "key_id": "sim_key_v1"
  },
  "iv": "dGVzdF9ub25jZV8xMg==",
  "ciphertext": "aGVsbG9fd29ybGRfY3J5cHRv...",
  "auth_tag": "OGE3ZjEyYmNkZWZh...",
  "signature": null
}
```

- **Responses:**
  - `200 OK`: Command accepted, validated, and executed.
  - `400 Bad Request`: Schema validation error, invalid command parameter, or physical limit exceeded.
  - `401 Unauthorized`: Missing or invalid GCS bearer token.
  - `403 Forbidden`: Cryptographic verification failure, bad tag, replay detected, or invalid HMAC.
  - `429 Too Many Requests`: Command rate limit exceeded (Token bucket exhausted).

##### Success Response `200 OK`:
```json
{
  "status": "success",
  "data": {
    "command_id": "1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
    "command": "MOVE_FORWARD",
    "execution_status": "EXECUTED",
    "state_version_after": 4513,
    "drone_position": {
      "x": 12.0,
      "y": 5.0,
      "z": -2.0
    },
    "processing_latency_ms": 1.45
  },
  "timestamp": 1729000000.125
}
```

---

#### `GET /api/drone/telemetry`
Returns a rolling buffer of the last $N$ telemetry samples (default: 50).
- **Query Parameters:** `limit` (int, default: 50, max: 500)
- **Response `200 OK`:** Array of telemetry records.

---

### 2.3 Security Engine Configuration & Status

#### `GET /api/security/status`
Returns the active cryptographic configuration, active security profile, anti-replay window status, and rate-limiting metrics.
- **Method:** `GET`
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "current_mode": "ENCRYPTED_AUTHENTICATED",
    "active_key_id": "sim_key_v1",
    "algorithms": {
      "encryption": "AES-256-GCM",
      "integrity": "HMAC-SHA-256",
      "kdf": "HKDF-SHA256"
    },
    "replay_protection": {
      "enabled": true,
      "window_size": 64,
      "highest_sequence_number": 104,
      "timestamp_tolerance_seconds": 5.0
    },
    "rate_limiting": {
      "enabled": true,
      "rate_limit_per_second": 10.0,
      "burst_capacity": 20
    }
  },
  "timestamp": 1729000000.123
}
```

---

#### `POST /api/security/mode`
Switches the active security operational mode of the simulator.
- **Method:** `POST`
- **Request Body:**
```json
{
  "mode": "ENCRYPTED_AUTHENTICATED",
  "reason": "Evaluation run switch"
}
```
*Permitted modes:* `UNSECURED`, `INTEGRITY_ONLY`, `ENCRYPTED_AUTHENTICATED`.
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "previous_mode": "UNSECURED",
    "new_mode": "ENCRYPTED_AUTHENTICATED",
    "transition_timestamp": 1729000000.200
  },
  "timestamp": 1729000000.201
}
```

---

### 2.4 Cyberattack Simulator

#### `POST /api/attacks/{attack_type}`
Triggers an automated, controlled attack injection scenario against the local security pipeline.
- **Method:** `POST`
- **Path Parameters:**
  - `attack_type`: Enum string (`unauthorized_command`, `message_tampering`, `replay_attack`, `spoofed_identity`, `malformed_payload`, `command_flood`).
- **Request Body:**
```json
{
  "parameters": {
    "target_command": "DISARM",
    "tamper_coordinate_delta": 500.0,
    "flood_count": 100
  }
}
```
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "attack_run_id": "a9c1d2e3-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    "attack_type": "REPLAY_ATTACK",
    "security_mode_active": "ENCRYPTED_AUTHENTICATED",
    "payload_injected": {
      "replayed_sequence_number": 104,
      "command": "MOVE_FORWARD"
    },
    "attack_result": "BLOCKED_BY_DEFENSE",
    "defense_triggered": "REPLAY_ATTACK_DETECTED",
    "state_compromised": false,
    "initial_state_version": 4513,
    "final_state_version": 4513,
    "coordinates_drift": {
      "delta_x": 0.0,
      "delta_y": 0.0,
      "delta_z": 0.0
    },
    "execution_duration_ms": 3.82
  },
  "timestamp": 1729000000.350
}
```

---

#### `GET /api/attacks/history`
Returns a paginated log of all previously executed attack runs.
- **Method:** `GET`
- **Query Parameters:** `limit` (default: 50), `offset` (default: 0).

---

### 2.5 Security Audit Logs & Analytics

#### `GET /api/logs`
Queries persistently stored communication and security incident audit logs.
- **Query Parameters:**
  - `category`: Filter by `COMMAND`, `SECURITY_EVENT`, or `ATTACK`.
  - `severity`: Filter by `INFO`, `WARNING`, `CRITICAL`.
  - `limit`: Number of records (default: 100).
- **Response `200 OK`:** Array of structured log entries.

---

#### `GET /api/analytics/summary`
Returns aggregate statistical calculations comparing secured and unsecured operations.
- **Method:** `GET`
- **Response `200 OK`:**
```json
{
  "status": "success",
  "data": {
    "total_commands_evaluated": 1500,
    "total_attacks_attempted": 300,
    "by_mode": {
      "UNSECURED": {
        "commands_processed": 500,
        "attacks_attempted": 100,
        "attacks_blocked": 15,
        "attacks_succeeded": 85,
        "attack_rejection_rate_percent": 15.0,
        "successful_attack_rate_percent": 85.0,
        "mean_latency_ms": 0.42,
        "p99_latency_ms": 1.15
      },
      "ENCRYPTED_AUTHENTICATED": {
        "commands_processed": 1000,
        "attacks_attempted": 200,
        "attacks_blocked": 200,
        "attacks_succeeded": 0,
        "attack_rejection_rate_percent": 100.0,
        "successful_attack_rate_percent": 0.0,
        "legitimate_command_success_rate_percent": 99.8,
        "false_rejection_rate_percent": 0.2,
        "mean_latency_ms": 1.85,
        "p99_latency_ms": 4.10
      }
    },
    "cryptographic_overhead_ms": 1.43
  },
  "timestamp": 1729000000.500
}
```

---

## 3. WebSocket Hub Specification (`/ws/telemetry`)

### 3.1 Handshake & Protocol Flow
- **URL:** `ws://localhost:8000/ws/telemetry`
- **Query Auth:** `ws://localhost:8000/ws/telemetry?token=gcs_session_token_xyz`
- **Frame Encoding:** Text frames containing UTF-8 JSON payloads.
- **Heartbeat:** Server sends periodic ping every $15\text{s}$; client responds with pong frame.

### 3.2 Downstream Broadcast Message Types

#### 1. Telemetry Frame (`TELEMETRY_UPDATE`)
Broadcast periodically at $10\text{ Hz}$ to all subscribed GCS clients:
```json
{
  "type": "TELEMETRY_UPDATE",
  "seq": 8920,
  "timestamp": 1729000000.100,
  "payload": {
    "state_version": 4513,
    "flight_state": "HOVERING",
    "x": 12.0,
    "y": 5.0,
    "z": -2.0,
    "latitude": 37.774882,
    "longitude": -122.419263,
    "altitude_msl": 20.0,
    "heading": 45.0,
    "speed": 0.0,
    "battery_percent": 93.8
  }
}
```

#### 2. Security Alert Frame (`SECURITY_ALERT`)
Pushed immediately whenever a security violation or attack is detected:
```json
{
  "type": "SECURITY_ALERT",
  "timestamp": 1729000000.105,
  "severity": "CRITICAL",
  "event_code": "REPLAY_ATTACK_DETECTED",
  "message": "Duplicate sequence number 104 received within sliding window. Command rejected.",
  "source_ip": "127.0.0.1",
  "sender_id": "MALICIOUS_ACTOR"
}
```

#### 3. Attack Event Frame (`ATTACK_EVENT`)
Pushed when an automated attack test completes:
```json
{
  "type": "ATTACK_EVENT",
  "timestamp": 1729000000.355,
  "attack_type": "MESSAGE_TAMPERING",
  "result": "BLOCKED_BY_DEFENSE",
  "state_compromised": false
}
```

### 3.3 Upstream Client Frames

#### 1. Ping Frame (`PING`)
```json
{
  "type": "PING",
  "timestamp": 1729000000.120
}
```
*Server replies with:*
```json
{
  "type": "PONG",
  "timestamp": 1729000000.121
}
```

### 3.4 Disconnection & Error Codes
| WS Close Code | Reason | Description |
|---|---|---|
| `1000` | Normal Closure | Clean shutdown or client initiated navigation. |
| `1008` | Policy Violation | Authentication token invalid or expired. |
| `1011` | Server Error | Unhandled server exception in simulation tick. |
| `4001` | Rate Limit Exceeded | Client exceeded upstream WebSocket frame rate. |

---

## 4. Error Code Catalog

| Error Code | HTTP Status | Description |
|---|---|---|
| `INVALID_SCHEMA` | `422 Unprocessable Entity` | Pydantic validation failed on missing or mistyped fields. |
| `UNKNOWN_COMMAND` | `400 Bad Request` | Command string does not match any valid enum value. |
| `INVALID_STATE_TRANSITION` | `400 Bad Request` | Command cannot be executed from the current flight state. |
| `BOUNDARY_LIMIT_EXCEEDED` | `400 Bad Request` | Target position falls outside local coordinate geofence. |
| `BATTERY_CRITICAL` | `400 Bad Request` | Command rejected due to insufficient battery reserve. |
| `AUTH_TOKEN_MISSING` | `401 Unauthorized` | HTTP Authorization header missing. |
| `AUTH_TOKEN_INVALID` | `401 Unauthorized` | Bearer token failed signature or expiration check. |
| `CRYPTO_DECRYPTION_FAILED` | `403 Forbidden` | AES-GCM decryption failed (ciphertext or tag corrupted). |
| `HMAC_VERIFICATION_FAILED` | `403 Forbidden` | HMAC signature mismatch (tampering detected). |
| `REPLAY_ATTACK_DETECTED` | `403 Forbidden` | Sequence number was previously seen or falls behind sliding window. |
| `TIMESTAMP_OUT_OF_BOUNDS` | `403 Forbidden` | Message timestamp is stale or skewed beyond $\pm 5.0\text{s}$. |
| `RATE_LIMIT_EXCEEDED` | `429 Too Many Requests` | Request exceeds allowed token bucket rate. |

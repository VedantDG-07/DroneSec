# DroneSec System Architecture Specification

---

## 1. Architectural Philosophy & Invariants

DroneSec is designed as an authoritative, software-in-the-loop (SITL) simulation and security benchmarking platform for Unmanned Aerial Vehicle (UAV) Command and Control (C2). The architecture adheres to five formal invariants:

1. **Authoritative Backend State Single Source of Truth:**
   The backend [`DroneEngine`](file:///c:/Users/User/Documents/drone/backend/app/core/drone_engine.py) maintains the single authoritative simulation state (Cartesian coordinates $(x, y, z)$, velocity vector, battery percentage, flight state, and monotonically increasing `state_version`). The Three.js Ground Control Station (GCS) is strictly an observer and command emitter; it cannot mutate simulation parameters directly.

2. **Decoupled Intercepting Security Pipeline:**
   All incoming commands pass through a six-stage security pipeline ([`SecurityService`](file:///c:/Users/User/Documents/drone/backend/app/security/security_service.py)) before reaching the drone core. The pipeline is fully independent of web presentation logic and fails closed on any cryptographic or protocol error.

3. **Mathematical State Invariance Under Attack:**
   If a command violates security or kinematic rules, authoritative state remains mathematically unchanged:
   $$\Delta \mathbf{p} = \|\mathbf{p}_{\text{final}} - \mathbf{p}_{\text{initial}}\| = 0 \quad \land \quad \text{state\_version}_{\text{final}} = \text{state\_version}_{\text{initial}}$$

4. **Zero Reader-Writer Contention via SQLite WAL Mode:**
   All persistent audit records (commands, security alerts, cyberattack runs, and statistical evaluation batches) are stored in SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), enabling simultaneous high-frequency readers and writers without database locking.

5. **Local Loopback Isolation:**
   All network communication is strictly confined to local loopback (`127.0.0.1` / `localhost`). Zero external or cloud infrastructure is required or accessed.

---

## 2. High-Level System Architecture

```mermaid
flowchart TD
    subgraph Frontend["Presentation Layer (Browser / Three.js)"]
        UI_HUD["Tactical HUD & Primary Flight Display (PFD)"]
        UI_3D["Three.js 3D Simulation Viewport (Island / Helipad / Quadcopter)"]
        UI_Controls["Flight Control Dispatcher (FSM Constraints)"]
        UI_Security["Security Status Panel & Mode Switcher"]
        UI_Attack["Cyberattack Console (ATK-01 to ATK-06)"]
        UI_Eval["Automated Evaluation Runner UI"]
        WS_Client["WebSocket Telemetry Receiver"]
    end

    subgraph TransportGateway["Transport & Gateway Layer (FastAPI / Starlette)"]
        HTTP_Middleware["HTTP Request Size Limiter (<= 64 KiB)"]
        CORS_Guard["CORS Least-Privilege Origin Filter"]
        REST_Routes["REST API Route Handlers (/api/drone, /api/security, /api/attacks)"]
        WS_Hub["WebSocket Hub (Frame Cap <= 4096 B, Heartbeat Monitor)"]
    end

    subgraph SecurityPipeline["Security & Defense Pipeline (SecurityService)"]
        Stage1["Stage 1: Token Bucket Rate Limiter (Capacity=20, Refill=10/s)"]
        Stage2["Stage 2: Mode Guard (UNSECURED vs Secured Modes)"]
        Stage3["Stage 3: Bearer Authentication & Operator Authorization"]
        Stage4["Stage 4: Anti-Replay Candidate Check (Freshness & Bitmask Ticket)"]
        Stage5["Stage 5: Cryptographic Decryption & Verification (AES-256-GCM / HMAC)"]
        Stage6["Stage 6: Two-Phase Commit Window Advance"]
        KeyMgr["KeyManager (Thread-Safe Key Storage & Rotation)"]
    end

    subgraph SimulationCore["Authoritative Simulation Domain"]
        Engine["DroneEngine (Authoritative State & Kinematics)"]
        FSM["Flight State Machine (Formal States & Safety Transitions)"]
        Battery["BatteryModel (Voltage Curve, Low & Critical Thresholds)"]
        Geo["CoordinateService (Local Flat-Earth <-> WGS-84 Geodesic)"]
        TelemetryLoop["TelemetryService (Periodic 20 Hz Simulation Loop)"]
    end

    subgraph Persistence["Persistence & Audit Storage (SQLite WAL)"]
        DB["DatabaseManager (WAL Mode, synchronous=NORMAL)"]
        CmdRepo["CommandLogRepository"]
        SecRepo["SecurityEventRepository"]
        AtkRepo["AttackRunRepository"]
        EvalRepo["EvaluationRepository"]
    end

    Frontend -->|"HTTP POST /api/drone/command"| TransportGateway
    Frontend -->|"WebSocket ws://127.0.0.1:8000/ws/telemetry"| TransportGateway
    TransportGateway --> SecurityPipeline
    SecurityPipeline -->|"Authorized Plaintext Command"| SimulationCore
    SimulationCore -->|"State Snapshot"| TelemetryLoop
    TelemetryLoop -->|"Outbound Telemetry Broadcast (10-20 Hz)"| WS_Hub
    WS_Hub -->|"TELEMETRY_UPDATE Frames"| WS_Client
    SecurityPipeline -.->|"Audit Events"| SecRepo
    SimulationCore -.->|"Command Execution History"| CmdRepo
    Persistence <--> DB
```

---

## 3. End-to-End Command Execution Lifecycle

The diagram below traces an incoming command from submission to authoritative execution or fail-closed rejection:

```mermaid
sequenceDiagram
    autonumber
    actor GCS as Ground Control Station
    participant GW as FastAPI Gateway
    participant Sec as SecurityService
    participant Auth as AuthManager
    participant RF as AntiReplayFilter
    participant Crypto as CryptoService
    participant Engine as DroneEngine
    participant DB as SQLite WAL Persistence

    GCS->>GW: POST /api/drone/command (Body <= 64 KiB)
    GW->>Sec: verify_command_request(raw_payload, auth_header)
    
    rect rgb(240, 248, 255)
        note over Sec,Crypto: Security Defense Pipeline
        Sec->>Sec: Stage 1: TokenBucketRateLimiter.consume(sender_id)
        alt Rate Limit Exceeded
            Sec-->>GW: Raise SecurityPipelineError(429, RATE_LIMIT_EXCEEDED)
            GW->>DB: sec_repo.log_event_async(RATE_LIMIT_EXCEEDED)
            GW-->>GCS: HTTP 429 Too Many Requests
        end

        alt Security Mode == UNSECURED
            Sec-->>GW: Return Plaintext Command Payload
        else Secured Modes (INTEGRITY_ONLY or ENCRYPTED_AUTHENTICATED)
            Sec->>Auth: authenticate_header(auth_header)
            alt Invalid or Missing Token
                Auth-->>Sec: Raise AuthenticationError(401)
                Sec-->>GW: Raise SecurityPipelineError(401, AUTH_TOKEN_INVALID)
                GW->>DB: sec_repo.log_event_async(AUTH_TOKEN_INVALID)
                GW-->>GCS: HTTP 401 Unauthorized
            end

            Sec->>RF: verify_candidate(sender_id, sequence_number, timestamp)
            alt Timestamp Expired or Duplicate Sequence
                RF-->>Sec: Raise ReplayVerificationError(403)
                Sec-->>GW: Raise SecurityPipelineError(403, REPLAY_ATTACK_DETECTED)
                GW->>DB: sec_repo.log_event_async(REPLAY_ATTACK_DETECTED)
                GW-->>GCS: HTTP 403 Forbidden
            end

            alt Mode == INTEGRITY_ONLY
                Sec->>Crypto: verify_hmac(canonical(header) | canonical(payload), sig)
            else Mode == ENCRYPTED_AUTHENTICATED
                Sec->>Crypto: decrypt_aes_gcm(iv, ciphertext, auth_tag, aad=canonical(header))
            end

            alt Cryptographic Verification Failed
                Crypto-->>Sec: Raise CryptoVerificationError(403)
                Sec->>RF: abort_ticket(replay_ticket)
                Sec-->>GW: Raise SecurityPipelineError(403, CRYPTO_DECRYPTION_FAILED)
                GW->>DB: sec_repo.log_event_async(CRYPTO_DECRYPTION_FAILED)
                GW-->>GCS: HTTP 403 Forbidden
            end

            Sec->>RF: commit_ticket(replay_ticket) [Advances Sliding Window Atomically]
        end
    end

    GW->>Engine: execute_command(command, parameters)
    Engine->>Engine: Validate Flight State Machine Transition & Geofence
    alt Invalid Flight Transition or Geofence Violation
        Engine-->>GW: CommandResult(success=False, error_code="FSM_TRANSITION_INVALID")
        GW->>DB: cmd_repo.log_command(status="REJECTED")
        GW-->>GCS: HTTP 400 Bad Request
    else Valid Flight Command
        Engine->>Engine: Apply Kinematic Update & Monotonically Increment state_version
        Engine-->>GW: CommandResult(success=True, state_version_after=V+1)
        GW->>DB: cmd_repo.log_command(status="EXECUTED")
        GW-->>GCS: HTTP 200 OK (CommandExecutionData)
    end
```

---

## 4. Component Directory & File Mapping

| Module / Component | Source File | Responsibilities |
|---|---|---|
| **FastAPI Core & Lifecycle** | [`backend/app/main.py`](file:///c:/Users/User/Documents/drone/backend/app/main.py) | Application lifespan, router mounting, 64 KiB request limit middleware, static file serving. |
| **Configuration Engine** | [`backend/app/config.py`](file:///c:/Users/User/Documents/drone/backend/app/config.py) | Environment loading, production safety guards (`__post_init__`), CORS origin whitelisting. |
| **REST & WebSocket Routes** | [`backend/app/api/routes.py`](file:///c:/Users/User/Documents/drone/backend/app/api/routes.py) | Route dispatch, schema validation, operator authorization dependency. |
| **Authoritative Drone Engine** | [`backend/app/core/drone_engine.py`](file:///c:/Users/User/Documents/drone/backend/app/core/drone_engine.py) | Thread-safe kinematic integration, geofence boundary enforcement, state versioning. |
| **Flight State Machine (FSM)** | [`backend/app/core/flight_fsm.py`](file:///c:/Users/User/Documents/drone/backend/app/core/flight_fsm.py) | Formal flight state enumeration (`DISARMED` to `EMERGENCY_LANDING`) and transition safety. |
| **Geodesic Coordinates** | [`backend/app/core/coordinate_service.py`](file:///c:/Users/User/Documents/drone/backend/app/core/coordinate_service.py) | WGS-84 geodesic reference conversion to Cartesian meters. |
| **Cryptographic Service** | [`backend/app/security/crypto_service.py`](file:///c:/Users/User/Documents/drone/backend/app/security/crypto_service.py) | AES-256-GCM AEAD encryption/decryption, HMAC-SHA-256, bounded nonce deque. |
| **Key Management** | [`backend/app/security/key_manager.py`](file:///c:/Users/User/Documents/drone/backend/app/security/key_manager.py) | Thread-safe symmetric key storage, random generation, and zero-downtime rotation. |
| **Anti-Replay Filter** | [`backend/app/security/replay_protection.py`](file:///c:/Users/User/Documents/drone/backend/app/security/replay_protection.py) | 64-bit sliding window, 5-second timestamp freshness, two-phase commit tickets. |
| **Token-Bucket Rate Limiter** | [`backend/app/security/rate_limiter.py`](file:///c:/Users/User/Documents/drone/backend/app/security/rate_limiter.py) | Per-sender and per-IP burst limiting with continuous token replenishment. |
| **Security Service Orchestrator** | [`backend/app/security/security_service.py`](file:///c:/Users/User/Documents/drone/backend/app/security/security_service.py) | Coordinates pipeline verification stages 1–6 and audit event generation. |
| **Cyberattack Orchestrator** | [`backend/app/services/attack_service.py`](file:///c:/Users/User/Documents/drone/backend/app/services/attack_service.py) | Manages attack runs ATK-01 to ATK-06, mutual exclusion locking, and cancellation. |
| **Scenario Runner** | [`backend/app/attacks/scenario_runner.py`](file:///c:/Users/User/Documents/drone/backend/app/attacks/scenario_runner.py) | Executes attack payloads against internal client, verifies state invariants. |
| **Payload Factory** | [`backend/app/attacks/payload_factory.py`](file:///c:/Users/User/Documents/drone/backend/app/attacks/payload_factory.py) | Constructs bit-flipped, replayed, forged, and flooded test payloads. |
| **Evaluation Framework** | [`backend/app/evaluation/runner.py`](file:///c:/Users/User/Documents/drone/backend/app/evaluation/runner.py) | Automated 21-experiment evaluation suite across all 3 modes. |
| **Telemetry Service** | [`backend/app/services/telemetry_service.py`](file:///c:/Users/User/Documents/drone/backend/app/services/telemetry_service.py) | Fixed-interval ($20\text{ Hz}$) simulation tick loop and broadcast coordinator. |
| **WebSocket Hub** | [`backend/app/websocket/hub.py`](file:///c:/Users/User/Documents/drone/backend/app/websocket/hub.py) | Client connection registry, ping/pong heartbeats, 4096-byte frame dropping. |
| **SQLite WAL Persistence** | [`backend/app/persistence/database.py`](file:///c:/Users/User/Documents/drone/backend/app/persistence/database.py) | Connection management, WAL mode initialization, schema migrations. |
| **Repositories** | [`backend/app/persistence/repositories.py`](file:///c:/Users/User/Documents/drone/backend/app/persistence/repositories.py) | Asynchronous thread-safe repositories for command logs, security events, attack runs. |

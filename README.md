# DroneSec: UAV Communication Security & Cyber Defense Simulation Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-green.svg)](https://cryptography.io)
[![Tests](https://img.shields.io/badge/tests-234%20passed-brightgreen.svg)]()

**DroneSec** is an enterprise-grade, software-in-the-loop (SITL) simulation and security benchmarking platform for Unmanned Aerial Vehicle (UAV) to Ground Control Station (GCS) telemetry and command communications. 

The platform models deterministic drone flight dynamics, authoritative finite state machines, multi-tier cryptographic defenses, and reproducible cyberattack vectors. It provides aerospace engineers, cybersecurity researchers, and defense analysts with a safe, local laboratory environment to evaluate communication link vulnerabilities, test cryptographic defenses, and mathematically verify state invariants under adversarial conditions.

---

## Key System Capabilities

### 1. Authoritative Flight Simulation Core
- **Deterministic Kinematics Engine:** Fixed-step numerical simulation ($20\text{ Hz}$) computing authoritative local $(x, y, z)$ position, velocity vectors, heading, ground speed, and battery consumption curves.
- **Strict Flight State Machine (FSM):** Guaranteed transitions across formal flight states (`DISARMED`, `ARMED`, `TAKING_OFF`, `HOVERING`, `MOVING`, `LANDING`, `EMERGENCY_LANDING`). Mid-air disarming and invalid transitions are strictly rejected.
- **Geodesic Coordinate Service:** Flat-Earth projection conversions between local Cartesian coordinates (metres) and geographic coordinates (WGS-84 Latitude, Longitude, Altitude MSL) with sub-centimetre precision.
- **Safety Bounds & Geofence:** Boundary limit enforcement across horizontal ($[-100, 100]\text{ m}$) and vertical ($[0, 50]\text{ m}$) corridors.

### 2. Cryptographic Security Engine
DroneSec implements dynamic, zero-downtime security operating modes to demonstrate clear contrasts between vulnerable legacy links and modern authenticated encryption:

- **`UNSECURED`:** Plaintext JSON payloads simulating legacy unencrypted telemetry/command protocols. Receptive to injection, tampering, and replay attacks.
- **`INTEGRITY_ONLY`:** Authenticated message envelopes utilizing **HMAC-SHA-256** signatures computed with constant-time verification against timing attacks.
- **`ENCRYPTED_AUTHENTICATED`:** Comprehensive confidentiality and authenticity protection using **AES-256-GCM** (Galois/Counter Mode Authenticated Encryption with Associated Data).
- **Key Derivation (KDF):** Standard **PBKDF2-HMAC-SHA256** with 100,000 iterations and dedicated cryptographic salts.
- **Anti-Replay Sliding Window:** Sequence-number tracking over a 64-frame bitmask combined with strict timestamp freshness filtering ($|t_{\text{server}} - t_{\text{packet}}| \le 5.0\text{ s}$).
- **Token-Bucket Rate Limiter:** Dual-parameter token bucket with burst capacity ($10$ tokens) and steady-state refill ($5\text{ tokens/s}$) protecting endpoints against denial-of-service saturation.

### 3. Controlled Cyberattack Simulation Engine
Local-only, reproducible attack scenarios executing against the live command processing pipeline to validate security boundaries:

| Attack Scenario | Description | Unsecured Behavior | Defense Triggered |
|---|---|---|---|
| **ATK-01: Unauthorized Command Injection** | Command dispatched without valid credentials | Command executes unconditionally | `AUTH_TOKEN_MISSING` / `AUTH_TOKEN_INVALID` (`401`) |
| **ATK-02: Message Tampering** | Bit-flipped ciphertext or manipulated payload coordinates | Injected payload moves drone to tampered coordinate | `CRYPTO_DECRYPTION_FAILED` / `HMAC_VERIFICATION_FAILED` (`403`) |
| **ATK-03: Command Replay Attack** | Captured legitimate frame resubmitted at later timestamp | Command re-executes unintended displacement | `REPLAY_ATTACK_DETECTED` (`403`) |
| **ATK-04: Sender Spoofing** | Rogue transmitter claiming authoritative GCS identity | Counterfeit operator identity accepted | `SPOOFED_GCS_IDENTITY` (`403`) |
| **ATK-05: Malformed Payload & Fuzzing** | Out-of-bounds coordinates, corrupt types, invalid enums | Rejected safely by Pydantic schema baseline | Cryptographic or Schema Sanitizer (`400`/`422`) |
| **ATK-06: Bounded Flooding / DoS** | High-frequency burst of commands exceeding link capacity | Processing queue saturation | `RATE_LIMIT_EXCEEDED` (`429`) |

### 4. Mathematical State Invariant Verification
For every attack run $A \in \{\text{ATK-01} \dots \text{ATK-06}\}$ under active defense, DroneSec automatically evaluates and enforces the state integrity invariant:

$$\mathcal{I}(S_0, S_1) = \begin{cases} 
\text{True (Pass)}, & \text{if } S_1.\text{state\_version} = S_0.\text{state\_version} \;\land\; \|S_1.\mathbf{p} - S_0.\mathbf{p}\| = 0 \\
\text{False (Compromised)}, & \text{otherwise}
\end{cases}$$

State version numbers are guaranteed to be strictly monotonic: $S_{t+1}.\text{state\_version} \ge S_t.\text{state\_version}$.

### 5. High-Throughput Real-Time Telemetry & Audit Persistence
- **WebSocket Telemetry Stream:** Low-latency ($10\text{–}20\text{ Hz}$) state broadcasting with bidirectional `PING`/`PONG` keepalive monitoring.
- **SQLite WAL Persistence:** Write-Ahead Logging (WAL) storage recording command logs, security events, and complete cyberattack audit trails with zero reader/writer contention.

### 6. Interactive 3D Simulation World & Ground Control Station (GCS)
- **Tactical Dark HUD Interface:** Glassmorphism UI cards, real-time Primary Flight Display (PFD) gauges, live battery drain meter, and compass cardinal orientation.
- **Three.js WebGL Simulation World:** Low-poly procedural island terrain, landing helipad, control tower with flashing beacon, hangars, communication radar, and spatial geofence envelope.
- **Deterministic Procedural Quadcopter:** 4 dynamically rotating propeller rotors, orientation gimbal, navigation strobes, belly state beacon, and real-time shadow projection.
- **Dynamic Flight Trail:** Continuous breadcrumb trajectory tracking past flight paths.
- **Multiple Tactical Camera Modes:** Free Orbit, Drone Chase Cam, Top-Down Orthographic Tactical View, and Airfield Control Tower View.
- **Integrated Attack Console & Audit Log:** Interactive execution of all 6 cyberattack scenarios with visual feedback of exploit versus mitigation outcomes and real-time event logs.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                           Ground Control Station (GCS)                            |
|                 UI / REST Client / Real-Time WebSocket Telemetry                  |
+-----------------------------------------------------------------------------------+
                                   |                       ^
                 POST /api/drone/command                   |  ws://.../ws/telemetry
                 POST /api/attacks/{type}                  |  (10-20 Hz Telemetry)
                                   v                       |
+-----------------------------------------------------------------------------------+
|                               DroneSec Backend API                                |
|  +-----------------------------------------------------------------------------+  |
|  |                          Security Pipeline Guard                            |  |
|  |  [ Token Bucket Rate Limiter ] -> [ Anti-Replay Sliding Window & Freshness ]  |  |
|  |  -> [ Bearer Token Auth ] -> [ AES-256-GCM AEAD / HMAC-SHA256 Decryption ]   |  |
|  +-----------------------------------------------------------------------------+  |
|                                   | (Authorized Plaintext Command)                |
|                                   v                                               |
|  +-----------------------------------------------------------------------------+  |
|  |                      Authoritative Simulation Engine                        |  |
|  |  [ Flight State Machine (FSM) ] <--> [ Kinematics, Battery, Geofence Bounds ]  |  |
|  |  [ WGS-84 Coordinate Service ]  <--> [ Controlled Cyberattack Orchestrator ] |  |
|  +-----------------------------------------------------------------------------+  |
|                                   |                                               |
|                                   v                                               |
|  +-----------------------------------------------------------------------------+  |
|  |                     SQLite Storage Engine (WAL Mode)                        |  |
|  |     `command_logs`   |   `security_events`   |   `attack_runs` (Audit)      |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## API Reference

All REST endpoints adhere to a standardized JSON response envelope:

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": 1729000000.0
}
```

### Drone & Telemetry Endpoints
- `GET /health`: Platform liveness, uptime, memory, engine tick rate, and DB connectivity.
- `GET /api/drone/state`: Authoritative state snapshot (position, GPS coordinates, speed, battery, flight state, state version).
- `POST /api/drone/command`: Submit discrete flight command (`ARM`, `TAKEOFF`, `MOVE_FORWARD`, `MOVE_BACKWARD`, `MOVE_LEFT`, `MOVE_RIGHT`, `MOVE_UP`, `MOVE_DOWN`, `LAND`, `STOP`).
- `GET /api/drone/telemetry`: Rolling buffer of recent telemetry records (`limit`: 1–500).
- `WS /ws/telemetry`: Real-time downstream telemetry broadcasting and heartbeat keepalive.

### Security Management Endpoints
- `GET /api/security/status`: Inspect active security mode, replay window metrics, and rate limiter status.
- `POST /api/security/mode`: Dynamically change active mode (`UNSECURED`, `INTEGRITY_ONLY`, `ENCRYPTED_AUTHENTICATED`).

### Cyberattack Simulation Endpoints
- `POST /api/attacks/{attack_type}`: Execute a controlled cyberattack scenario:
  - `unauthorized_command` (ATK-01)
  - `message_tampering` (ATK-02)
  - `replay_attack` (ATK-03)
  - `spoofed_identity` (ATK-04)
  - `malformed_payload` (ATK-05)
  - `command_flood` (ATK-06)
- `GET /api/attacks/history`: Paginated audit history of past attack executions and invariant verification outcomes.
- `GET /api/logs`: Query command execution audit logs and security incident alerts.

---

## Project Structure

```
Drone security/
├── docs/                               # Formal System Specifications & Blueprints
│   ├── requirements.md                 # System requirements and functional scope
│   ├── architecture.md                 # Component architectures and threat boundaries
│   ├── api-contract.md                 # Complete REST and WebSocket protocol specifications
│   ├── coordinate-system.md            # Geodesic and Cartesian conversion formulas
│   ├── security-design.md              # Cryptographic architecture and key management
│   ├── attack-test-plan.md             # Attack scenarios and invariant evaluation formulas
│   ├── testing-strategy.md             # Quality assurance standards and test pyramid
│   └── development-roadmap.md          # Implementation roadmap and milestones
│
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application lifespan & routing
│   │   ├── config.py                   # Centralized configuration & environment parsing
│   │   ├── core/                       # Authoritative Simulation Core
│   │   │   ├── coordinate_service.py   # WGS-84 <-> Local Cartesian conversion
│   │   │   ├── flight_fsm.py           # Finite state machine & valid transitions
│   │   │   └── drone_engine.py         # Kinematics, battery burn, geofence clamping
│   │   ├── security/                   # Cryptographic & Defense Pipeline
│   │   │   ├── crypto.py               # AES-256-GCM, HMAC-SHA256, PBKDF2 KDF
│   │   │   ├── anti_replay.py          # 64-frame bitmask sliding window & freshness
│   │   │   └── rate_limiter.py         # Token-bucket rate limiting
│   │   ├── attacks/                    # Controlled Cyberattack Simulator
│   │   │   ├── attack_types.py         # Scenario enums, schemas, and classification
│   │   │   ├── payload_factory.py      # Malicious bit-flipped & fuzzed packet factory
│   │   │   └── scenario_runner.py      # Local attack orchestration & invariant checker
│   │   ├── api/                        # Transport Layer & Routes
│   │   │   ├── schemas.py              # Pydantic models & request/response envelopes
│   │   │   └── routes.py               # REST API & WebSocket handlers
│   │   ├── services/                   # Business Orchestration Services
│   │   │   ├── command_service.py      # Serialized command execution & security dispatch
│   │   │   ├── telemetry_service.py    # Background tick loop & broadcast orchestrator
│   │   │   ├── security_service.py     # Multi-mode security coordination & key store
│   │   │   └── attack_service.py       # Attack scenario execution & direct client
│   │   ├── websocket/                  # Real-Time Telemetry Hub
│   │   │   └── hub.py                  # Client registry, broadcast dispatcher, PING/PONG
│   │   └── persistence/                # Storage & Audit Layer
│   │       ├── database.py             # SQLite WAL connection & schema migration
│   │       └── repositories.py         # Command, Security, and Attack audit repositories
│   │
│   └── tests/                          # Automated Verification Suite (173 tests)
│       ├── test_coordinates.py         # Geodesic math, precision, and edge cases
│       ├── test_flight_fsm.py          # Flight state machine state transitions
│       ├── test_drone_engine.py        # Drone kinematics, battery, and geofencing
│       ├── test_persistence.py         # SQLite WAL mode, indexing, and queries
│       ├── test_api.py                 # REST routes, envelope adherence, error codes
│       ├── test_websocket.py           # WebSocket protocol, telemetry frames, heartbeat
│       ├── test_security_crypto.py     # AES-256-GCM AEAD, HMAC verification, PBKDF2
│       ├── test_anti_replay.py         # Sliding window bitmask & timestamp freshness
│       ├── test_rate_limiter.py        # Token bucket burst, refill, and concurrency
│       ├── test_security_service.py    # Security mode transitions & pipeline execution
│       ├── test_attack_scenarios.py    # ATK-01 to ATK-06 vulnerability & defense tests
│       ├── test_state_invariants.py    # Mathematical state invariants & audit persistence
│       └── test_frontend.py            # Static GCS serving, asset delivery & route precedence
│
├── frontend/                           # Ground Control Station Web Application
│   ├── index.html                      # Tactical GCS interface markup
│   ├── css/
│   │   └── gcs.css                     # Tactical dark theme, HUD styling & glassmorphism
│   └── js/
│       ├── app.js                      # Main GCS application coordinator
│       ├── simulation.js               # Three.js 3D world, procedural terrain & drone model
│       ├── telemetry.js                # WebSocket telemetry client & heartbeat manager
│       ├── flight_controls.js          # REST command dispatcher & FSM button constraints
│       ├── security_panel.js           # Security status & dynamic mode switcher
│       ├── attack_console.js           # Cyberattack console & invariant report cards
│       ├── event_log.js                # Live audit log table & JSON exporter
│       └── vendor/
│           ├── three.module.js         # Offline Three.js 3D WebGL graphics library
│           └── OrbitControls.js        # Three.js camera interaction controls
│
├── data/                               # Persistent SQLite database storage
├── requirements.txt                    # Project dependencies
└── README.md                           # Documentation
```

---

## Installation & Setup

### Prerequisites
- Python 3.11, 3.12, 3.13, or 3.14
- Virtual environment tool (`venv` or `uv`)

### 1. Clone the Repository
```bash
git clone https://github.com/VedantDG-07/DroneSec.git
cd DroneSec
```

### 2. Set Up Virtual Environment & Dependencies
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Configure environment variables
# Copy template and customize secret keys and origins as needed
cp .env.example .env
```

---

## Configuration & Environments

DroneSec supports local development and hardened production modes configured via environment variables or a `.env` file (see [`.env.example`](file:///c:/Users/User/Documents/drone/.env.example)):

- `SIM_APP_ENV`: Operating environment (`development` or `production`). When set to `production`, safe configuration is strictly enforced (rejects default demo tokens, rejects wildcard CORS, and requires explicit cryptographic keys).
- `SIM_GCS_BEARER_TOKEN`: Authorization bearer token for privileged GCS operations.
- `SIM_CORS_ORIGINS`: Comma-separated list of allowed CORS origins (default: loopback addresses `127.0.0.1:8000,localhost:8000`).
- `SIM_MAX_REQUEST_BODY_BYTES`: Maximum allowed HTTP request body size (default: 65,536 bytes / 64 KiB).
- `SIM_AES_256_KEY` & `SIM_HMAC_SHA256_KEY`: Cryptographic 256-bit hexadecimal keys for authenticated AEAD and HMAC pipelines.

---

## Running the Application

Start the DroneSec simulation backend and Ground Control Station with Uvicorn:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Once launched:
- **Ground Control Station (GCS) Dashboard:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check Endpoint:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Authoritative Drone State:** [http://127.0.0.1:8000/api/drone/state](http://127.0.0.1:8000/api/drone/state)
- **Real-Time Telemetry Stream:** `ws://127.0.0.1:8000/ws/telemetry`

---

## Wireshark Practical (Local Traffic Lab)

A small loopback-only client exercises DroneSec's existing command API and security pipeline so you can observe the real HTTP/TCP traffic in Wireshark. It covers plaintext visibility, replay comparison, and tampering under the existing security modes without creating a separate crypto implementation.

See **[docs/wireshark-practical.md](docs/wireshark-practical.md)** for the full walkthrough.

With the server running at `127.0.0.1:8000`, select the Npcap loopback interface in Wireshark and use:

```text
tcp.port == 8000
```

Example commands from the repository root:

```powershell
python -m backend.scripts.wireshark_lab --mode UNSECURED --action send
python -m backend.scripts.wireshark_lab --mode UNSECURED --action replay
python -m backend.scripts.wireshark_lab --mode ENCRYPTED_AUTHENTICATED --action replay
python -m backend.scripts.wireshark_lab --mode ENCRYPTED_AUTHENTICATED --action tamper
```

The runner refuses non-loopback URLs. Wireshark captures traffic; DroneSec's security pipeline performs authentication, integrity verification, and replay rejection. This practical uses HTTP and should not be described as full transport-layer TLS encryption.

---

## Running the Automated Test Suite

DroneSec includes a test suite with **234 automated tests** covering unit physics, cryptographic invariants, concurrency, WebSocket streaming, cyberattack scenarios, and Phase 7 security hardening:

### Run All Tests
```bash
pytest -v
```

### Run Specific Modules
```bash
# Phase 7 Security Hardening, Concurrency & Reliability
pytest backend/tests/test_phase7_hardening_reliability.py -v

# Cyberattack simulation scenarios (ATK-01 to ATK-06)
pytest backend/tests/test_attack_scenarios.py -v

# Mathematical state invariant verification
pytest backend/tests/test_state_invariants.py -v

# Cryptographic engine & AEAD primitives
pytest backend/tests/test_security_crypto.py backend/tests/test_anti_replay.py backend/tests/test_rate_limiter.py -v

# Flight physics & state machine
pytest backend/tests/test_flight_fsm.py backend/tests/test_drone_engine.py backend/tests/test_coordinates.py -v

# REST API & WebSocket streaming
pytest backend/tests/test_api.py backend/tests/test_websocket.py backend/tests/test_persistence.py -v
```

---

## Local Benchmarking

Run the reproducible local benchmarking harness to measure command latency across security modes, telemetry loop interval regularity, concurrent command throughput, and bounded cyberattack execution:

```bash
python -m backend.scripts.run_benchmarks
```

---

## Security & Ethical Disclosure

> **Safety Notice:** DroneSec is strictly a software-in-the-loop simulation environment running on isolated local loopback interfaces (`127.0.0.1`). It does **not** perform actual RF signal emissions, software-defined radio (SDR) jamming, hardware manipulation, or unauthorized network intrusion against external devices. It is designed exclusively for cybersecurity education, cryptographic research, and defensive software engineering.

---



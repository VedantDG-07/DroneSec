# DroneSec Known Limitations, Technical Assumptions & Future Work

---

## 1. System Assumptions & Scope Boundaries

DroneSec is designed strictly as an educational and research software-in-the-loop (SITL) simulation platform. The following explicit scope boundaries apply:

- **Isolated Localhost Execution:** The application executes exclusively on local loopback (`127.0.0.1`).
- **No Physical RF Hardware:** The platform does not transmit RF electromagnetic radiation, interface with software-defined radios (HackRF, RTL-SDR, USRP), or manipulate physical aerial vehicles.
- **Defensive Research Objective:** All attack modules are white-box security tests designed to evaluate software-layer cryptographic and protocol defenses.

---

## 2. Technical Limitations & Threat to Validity

| Area | Production Drone Requirement | DroneSec SITL Implementation | Operational Impact & Mitigation |
|---|---|---|---|
| **RF Physical Layer** | Direct-sequence spread spectrum (DSSS), frequency hopping (FHSS), RF jamming, multipath interference, RSSI attenuation. | Logical transport layer over HTTP/JSON and WebSockets. | RF-level jamming is represented as application-layer token-bucket rate limiting (`BOUNDED_FLOODING`); physical link layer security is out of scope. |
| **Cryptographic Storage** | Hardware Security Module (HSM), TPM 2.0, or secure enclave for private key isolation. | In-memory [`KeyManager`](file:///c:/Users/User/Documents/drone/backend/app/security/key_manager.py) protected by process boundaries and thread locks. | Host memory compromise could expose symmetric keys; acceptable for local SITL research. Production systems require PKCS#11 HSM integration. |
| **Nonce History Memory Bounding** | Unbounded anti-replay and nonce caches across multi-day continuous flight missions. | Bounded to 50,000 nonces via FIFO deque in [`CryptoService`](file:///c:/Users/User/Documents/drone/backend/app/security/crypto_service.py). | Prevents memory growth during long simulation runs. To maintain NIST SP 800-38D compliance under continuous missions, keys must be rotated before $2^{32}$ packets. |
| **Persistence Concurrency** | Distributed time-series database (e.g., InfluxDB, TimescaleDB, Cassandra) handling 10,000+ writes/second. | SQLite 3 in WAL mode (`PRAGMA journal_mode=WAL;`). | Enables concurrent readers and serialized writers with zero reader lock contention. Exceeding ~1,000 concurrent writes/second causes write lock queuing. |
| **Flight Dynamics & Aerodynamics** | 6-DOF non-linear flight dynamics, motor inertia, rotor wash, ground effect, gyro/accelerometer sensor noise, wind gusts. | 3-DOF kinematic position integration at fixed $20\text{ Hz}$ step with velocity clamping and linear battery discharge. | Adequate for verifying flight state machine safety and geofence boundary enforcement; not suitable for aerodynamic control tuning. |
| **Network Latency & Jitter** | Real-world telemetry links exhibit variable round-trip time (RTT: 20–150 ms) and random packet drop rates (1–5%). | Sub-millisecond local loopback IPC latency ($p_{50} \approx 10\text{–}12\text{ ms}$ including crypto). | Benchmarks measure pure software cryptographic processing overhead; real-world deployments must account for wireless link latency. |

---

## 3. Unsupported Commands & Legacy Caveats

- **Unsupported Commands:** Complex autonomous mission scripting, Bezier curved waypoint splines, camera gimbal pan/tilt controls, and payload drops are not implemented.
- **Vertical Movement:** `MOVE_UP` and `MOVE_DOWN` are supported as vertical displacement commands mapped to altitude changes within the geofence ($[0, 50]\text{ m}$).
- **Parameter Aliases:** Both `distance` and `distance_meters` parameter keys are accepted by the command parser for backward compatibility.

---

## 4. Future Research & Development Roadmap

1. **Hardware-in-the-Loop (HITL) Integration:** Adding support for MAVLink v2.0 packet framing over serial/UART interfaces to connect with physical flight controllers (PX4 / ArduPilot).
2. **Post-Quantum Cryptography (PQC):** Evaluating NIST PQC standards (e.g., ML-KEM / ML-DSA) for UAV key exchange and command signing under resource-constrained embedded microcontrollers.
3. **Sensor Noise Injection:** Incorporating simulated Gaussian GPS position noise and compass magnetic declination to test navigation resilience under spoofed GPS environments.

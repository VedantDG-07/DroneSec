# DroneSec Local Demonstration Guide

This guide walks through a complete end-to-end local demonstration of the DroneSec Drone Communication Security Simulation Platform, from initial startup to interactive flight controls, security mode toggling, cyberattack injection, and audit log analysis.

---

## 1. Prerequisites & Environment Setup

### System Requirements
- Python 3.11, 3.12, 3.13, or 3.14.
- Modern WebGL-compatible browser (Chrome, Edge, Firefox, or Safari).
- Local loopback network access (`127.0.0.1`).

### Step 1.1: Clone and Activate Virtual Environment
```bash
# Clone repository
git clone https://github.com/VedantDG-07/DroneSec.git
cd DroneSec

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 1.2: Environment Configuration
Copy the documented environment configuration:
```bash
cp .env.example .env
```
*(By default, development settings are configured for local zero-configuration simulation).*

---

## 2. Launching the Backend & Ground Control Station

### Step 2.1: Start the Backend Server
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 2.2: Open the Ground Control Station (GCS)
Navigate to:
- **Ground Control Station Interface:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **System Health Endpoint:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 3. Telemetry Verification & 3D Viewport Interaction

1. **Verify WebSocket Connection:**
   - Look at the top-right header in the GCS dashboard.
   - The indicator should read `CONNECTED` with a green pulse and a live heartbeat counter ($10\text{–}20\text{ Hz}$).
2. **Interact with the 3D Simulation Viewport:**
   - **Rotate:** Left-click and drag to orbit around the quadcopter and island helipad.
   - **Pan:** Right-click and drag.
   - **Zoom:** Mouse scroll wheel.
   - **Camera Modes:** Click camera buttons in the viewport toolbar (`Orbit View`, `Drone Follow Cam`, `Top-Down Tactical View`, `Control Tower Cam`).

---

## 4. Demonstrating Supported Flight Commands

The flight controls strictly enforce the authoritative Flight State Machine (FSM):

```
[DISARMED] ---> [ARMED] ---> [TAKING_OFF] ---> [HOVERING] <---> [MOVING]
                                                    |
                                                    v
                                                 [LANDING] ---> [DISARMED]
```

### Step 4.1: Arm and Take Off
1. Click **`ARM`** in the Flight Controls panel. The drone state changes to `ARMED`, and propeller rotors begin spinning.
2. Click **`TAKEOFF`**. The drone ascends to default altitude ($10.0\text{ m}$) and transitions into `HOVERING`.

### Step 4.2: Directional & Vertical Navigation
1. Click **`FORWARD`** ($+5\text{ m}$ forward pitch).
2. Click **`RIGHT`** ($+5\text{ m}$ roll right).
3. Click **`UP`** ($+2\text{ m}$ vertical climb).
4. Click **`DOWN`** ($-2\text{ m}$ vertical descent).
5. Observe the continuous 3D breadcrumb trajectory trail tracking past positions, and the real-time compass heading and battery drain meter in the Primary Flight Display (PFD).

### Step 4.3: Landing
1. Click **`LAND`**. The drone descends to ground level ($z = 0\text{ m}$) and automatically returns to `DISARMED`.

---

## 5. Security Operating Mode Switching

In the **Security Controls Panel**, toggle between operating modes:

1. **`UNSECURED` Mode:**
   - Simulates legacy unencrypted UAV communications.
   - Telemetry and commands travel as plain JSON without signatures or encryption.
2. **`INTEGRITY_ONLY` Mode:**
   - Message envelopes are signed using **HMAC-SHA-256** and require valid Bearer authentication.
   - Prevents unauthorized command injection and parameter tampering.
3. **`ENCRYPTED_AUTHENTICATED` Mode:**
   - Full **AES-256-GCM** authenticated encryption with Associated Data (AEAD) and 64-frame anti-replay sliding window.
   - Guarantees confidentiality, authenticity, and replay prevention.

---

## 6. Running Controlled Cyberattack Scenarios

In the **Cyberattack Console**, select and execute attacks to observe live defensive reactions:

### Scenario 1: Command Replay Attack (`ATK-03`)
1. Set Security Mode to `UNSECURED`. Run **`Command Replay`**.
   - *Outcome:* Replayed command is accepted; drone moves unexpectedly.
2. Switch Security Mode to `ENCRYPTED_AUTHENTICATED`. Run **`Command Replay`**.
   - *Outcome:* Intercepted! The defense triggers `REPLAY_ATTACK_DETECTED` (HTTP 403). The state invariant card shows $\Delta \mathbf{p} = 0.000\text{ m}$ and `state_version` unchanged.

### Scenario 2: Message Tampering Attack (`ATK-02`)
1. Set Security Mode to `ENCRYPTED_AUTHENTICATED`. Run **`Message Tampering`** (coordinates manipulated by $+500\text{ m}$).
   - *Outcome:* The GCM authentication tag fails verification. The defense triggers `CRYPTO_DECRYPTION_FAILED` (HTTP 403). The tampered command is rejected before touching drone memory.

### Scenario 3: Bounded Flooding / DoS (`ATK-06`)
1. Run **`Bounded Flooding`** (burst of 30 rapid commands).
   - *Outcome:* First burst consumes available tokens; subsequent rapid frames are terminated with `RATE_LIMIT_EXCEEDED` (HTTP 429), protecting simulation CPU resources.

---

## 7. Inspecting Persistent Audit Logs & Exporting Data

1. Scroll to the **Live Event & Audit Log** table in the lower half of the GCS.
2. Observe color-coded severity badges (`INFO`, `WARNING`, `CRITICAL`).
3. Filter by category (`ALL`, `COMMANDS`, `SECURITY`, `ATTACKS`).
4. Click **`Export CSV`** or **`Export JSON`** to download full forensic logs.
5. Alternatively, query the REST API directly:
   ```bash
   curl "http://127.0.0.1:8000/api/logs?limit=20"
   ```

---

## 8. Clean Shutdown & Data Reset

1. Press `Ctrl + C` in the terminal running Uvicorn to cleanly terminate the server and background simulation loop.
2. To reset the persistent SQLite simulation database for a fresh demonstration run:
   ```bash
   # Remove temporary SQLite database files
   rm data/simulation.db data/simulation.db-wal data/simulation.db-shm
   ```
   *(The database schema will automatically re-initialize on next startup).*

# Wireshark Practical: DroneSec Local Command Security

This lab uses DroneSec's **existing FastAPI command endpoint and security modules**. It does not create a second crypto implementation or send anything to a physical drone. All utility requests are restricted to the local loopback host.

## What this demonstrates

- HTTP/TCP command traffic visible in Wireshark when security mode is `UNSECURED`.
- Replay of an identical command envelope and the difference between `UNSECURED` and secured modes.
- Command/ciphertext tampering with no attempt to recompute the HMAC/GCM authenticator.
- Existing AES-256-GCM, HMAC-SHA-256, bearer-token authentication, and anti-replay pipeline in `backend/app/security/`.

Wireshark **observes packets**; DroneSec's application security pipeline accepts or rejects the command. This demo uses HTTP on loopback, not TLS. In secured modes the HTTP body still has visible metadata and a JSON envelope, while the command payload is protected by HMAC or AES-GCM. Do not describe this as full transport encryption.

## 1. Install dependencies and run DroneSec

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000/ and use the dashboard to arm and take off the virtual drone. Wait until it is hovering before using movement commands; the flight state machine correctly rejects commands that are invalid for the current state.

The runner uses the default local development credential from configuration unless overridden. Never reuse demonstration credentials in a deployed environment. If you changed `SIM_GCS_BEARER_TOKEN`, pass that token to the runner using `--token` or the environment variable.

## 2. Capture traffic in Wireshark

1. Start Wireshark and select **Adapter for loopback traffic capture** (Npcap Loopback Adapter).
2. Start capturing, then apply this display filter:

   ```text
   tcp.port == 8000
   ```

3. The practical sends requests to `127.0.0.1:8000`. Select a TCP packet and choose **Follow → TCP Stream** to inspect the HTTP request/response.
4. In `UNSECURED` mode, the command JSON is readable. In secured modes, the command is packed by the app's own `/api/drone/command/pack` endpoint and the body contains the security envelope.
5. Stop the capture and save it as `docs/results/wireshark-unsecured.pcapng` or another suitable evidence name. Keep captures small; review before committing since they contain request metadata and demonstration credentials can appear in HTTP headers.

## 3. Run the local traffic experiments

Run these commands from a **second terminal** at the repository root while the server and Wireshark capture remain running.

### Plaintext command

```powershell
python -m backend.scripts.wireshark_lab --mode UNSECURED --action send
```

Observe a JSON command in Wireshark's TCP stream.

### Replay comparison

```powershell
python -m backend.scripts.wireshark_lab --mode UNSECURED --action replay
python -m backend.scripts.wireshark_lab --mode ENCRYPTED_AUTHENTICATED --action replay
```

The script sends a command, then re-submits the **same exact envelope**. The unsecured pipeline does not apply anti-replay protection. In authenticated mode, the replay should be rejected by the sequence/timestamp anti-replay check. The script resets the replay filter when switching modes, so each invocation demonstrates the scenario from a clean mode transition.

### Tampering comparison

```powershell
python -m backend.scripts.wireshark_lab --mode UNSECURED --action tamper
python -m backend.scripts.wireshark_lab --mode INTEGRITY_ONLY --action tamper
python -m backend.scripts.wireshark_lab --mode ENCRYPTED_AUTHENTICATED --action tamper
```

The utility modifies the command for unsecured traffic, changes the payload without recomputing HMAC in `INTEGRITY_ONLY`, or flips a Base64 ciphertext character in `ENCRYPTED_AUTHENTICATED`. The unsecured request can reach command execution if the current flight state permits it; secured requests should be rejected by authentication/integrity verification. Check the HTTP status and response error code rather than assuming all command requests execute.

If the dashboard is not in a state that permits `MOVE_FORWARD` or `MOVE_BACKWARD`, the flight state machine may reject a plaintext command even though the security layer accepted it. That is a separate safety control, not cryptographic protection.

### Alternate credential

```powershell
python -m backend.scripts.wireshark_lab --mode ENCRYPTED_AUTHENTICATED --action replay --token YOUR_LOCAL_DEMO_TOKEN
```

The token is sent only to the loopback server. Do not paste real production credentials into screenshots, packet captures, or source control.

## 4. What to record in the report

| Test | Expected observation |
|---|---|
| `UNSECURED` send | Command payload is readable in the HTTP stream |
| `UNSECURED` replay | Same envelope is submitted a second time; no anti-replay rejection from the unsecured pipeline |
| `ENCRYPTED_AUTHENTICATED` replay | Replay check rejects duplicate/stale sequence or timestamp |
| `UNSECURED` tampering | Changed command is not cryptographically detected; flight-state validation may still reject it |
| `INTEGRITY_ONLY` tampering | HMAC verification rejects modified payload |
| `ENCRYPTED_AUTHENTICATED` tampering | AES-GCM authentication rejects modified ciphertext/tag |

Save screenshots of the filter and packet list, the unsecured TCP stream, an encrypted-mode envelope, and the replay/tampering error responses. Include which security mode was active in each result.

## Design note

Keep the existing application modules. Cryptography, message framing, authentication, replay protection, the simulated attack engine, and the dashboard already have separate responsibilities in this repository. This practical script is just a loopback client; it deliberately does not duplicate `CryptoService` or `SecurityService`.

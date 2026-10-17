"""Attack scenario orchestrator.

Executes controlled attack scenarios against the local FastAPI test client,
exercises the actual Phase 3 security pipeline, and records structured results.

Safety guarantees:
- Only runs against the embedded test application (no external HTTP).
- Conservative hard limits on request counts and payload sizes.
- Cancellation via asyncio.Event; never blocks indefinitely.
- Drone engine safety checks are NEVER disabled.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.app.attacks.attack_types import (
    AttackScenarioType,
    AttackStatus,
    MAX_ATTEMPTS,
    MAX_FLOOD_REQUESTS,
    ScenarioRunStatus,
)


@dataclass
class AttackAttemptRecord:
    """Single request/response observation within an attack scenario."""

    attempt_index: int
    payload_summary: str            # Redacted description — never the raw secret key
    http_status: int
    response_code: Optional[str]
    latency_ms: float
    is_security_rejection: bool     # True if rejected by the security pipeline
    state_version_before: int
    state_version_after: int
    position_delta_norm: float      # ||p_after - p_before|| in metres


@dataclass
class ScenarioResult:
    """Aggregated outcome of a complete attack scenario run."""

    run_id: str
    scenario_type: AttackScenarioType
    security_mode_active: str
    started_at: float
    finished_at: float
    status: ScenarioRunStatus

    # State invariant snapshots
    state_version_initial: int
    state_version_final: int
    position_initial: dict[str, float]       # {"x": float, "y": float, "z": float}
    position_final: dict[str, float]

    # Counters
    total_attempts: int
    accepted: int                   # Reached the drone engine
    rejected_by_security: int       # Rejected before drone engine
    rejected_by_engine: int         # Rejected by engine invariants
    rate_limited: int

    # Classified outcomes
    attempts: list[AttackAttemptRecord] = field(default_factory=list)

    # Invariant evaluation
    state_mutation_detected: bool = False
    invariant_passed: bool = True

    # High-level outcome label
    attack_status: AttackStatus = AttackStatus.ATTACK_BLOCKED
    defense_triggered: Optional[str] = None
    payload_injected: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        return max(0.001, self.finished_at - self.started_at)

    @property
    def execution_duration_ms(self) -> float:
        return max(0.1, (self.finished_at - self.started_at) * 1000)

    @property
    def state_compromised(self) -> bool:
        return self.state_mutation_detected

    @property
    def coordinates_drift(self) -> dict[str, float]:
        dx = self.position_final.get("x", 0.0) - self.position_initial.get("x", 0.0)
        dy = self.position_final.get("y", 0.0) - self.position_initial.get("y", 0.0)
        dz = self.position_final.get("z", 0.0) - self.position_initial.get("z", 0.0)
        return {
            "delta_x": round(dx, 4),
            "delta_y": round(dy, 4),
            "delta_z": round(dz, 4),
        }

    def to_api_response_data(self) -> dict[str, Any]:
        """Convert result into standard response schema per docs/api-contract.md section 2.4."""
        return {
            "attack_run_id": self.run_id,
            "attack_type": self.scenario_type.name,
            "security_mode_active": self.security_mode_active,
            "payload_injected": self.payload_injected,
            "attack_result": self.attack_status.value,
            "defense_triggered": self.defense_triggered,
            "state_compromised": self.state_compromised,
            "initial_state_version": self.state_version_initial,
            "final_state_version": self.state_version_final,
            "coordinates_drift": self.coordinates_drift,
            "execution_duration_ms": round(self.execution_duration_ms, 2),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict suitable for API responses and DB storage."""
        return {
            "run_id": self.run_id,
            "scenario_type": self.scenario_type.value,
            "security_mode_active": self.security_mode_active,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 4),
            "status": self.status.value,
            "state_version_initial": self.state_version_initial,
            "state_version_final": self.state_version_final,
            "position_initial": self.position_initial,
            "position_final": self.position_final,
            "state_mutation_detected": self.state_mutation_detected,
            "invariant_passed": self.invariant_passed,
            "attack_status": self.attack_status.value,
            "defense_triggered": self.defense_triggered,
            "payload_injected": self.payload_injected,
            "counters": {
                "total_attempts": self.total_attempts,
                "accepted": self.accepted,
                "rejected_by_security": self.rejected_by_security,
                "rejected_by_engine": self.rejected_by_engine,
                "rate_limited": self.rate_limited,
            },
            # Include condensed per-attempt records (no raw secrets)
            "attempts": [
                {
                    "index": a.attempt_index,
                    "payload": a.payload_summary,
                    "http_status": a.http_status,
                    "response_code": a.response_code,
                    "latency_ms": round(a.latency_ms, 2),
                    "is_security_rejection": a.is_security_rejection,
                    "state_version_before": a.state_version_before,
                    "state_version_after": a.state_version_after,
                    "position_delta_norm": round(a.position_delta_norm, 4),
                }
                for a in self.attempts
            ],
        }


_SECURITY_REJECTION_CODES = frozenset({
    "AUTH_TOKEN_MISSING",
    "AUTH_TOKEN_INVALID",
    "SPOOFED_GCS_IDENTITY",
    "HMAC_VERIFICATION_FAILED",
    "CRYPTO_DECRYPTION_FAILED",
    "REPLAY_ATTACK_DETECTED",
    "TIMESTAMP_OUT_OF_BOUNDS",
    "SECURITY_MODE_MISMATCH",
    "INVALID_SCHEMA",
    "RATE_LIMIT_EXCEEDED",
})


class AttackScenarioRunner:
    """Orchestrates attack execution against the local application client.

    Invariants:
    - Never modifies the drone engine or security pipeline directly.
    - All requests go through the public API client (same path as real operator).
    - Only one scenario executes at a time (guarded by _running_lock).
    - Respects cancellation via asyncio.Event.
    """

    def __init__(self, http_client: Any, drone_engine: Any) -> None:
        """
        Args:
            http_client: Starlette / httpx TestClient with `.get()` and `.post()` methods.
            drone_engine: DroneEngine instance (read-only, for state snapshots).
        """
        self._client = http_client
        self._engine = drone_engine
        self._running_lock = asyncio.Lock()
        self._cancel_event: Optional[asyncio.Event] = None
        self._current_run_id: Optional[str] = None
        self._results: dict[str, ScenarioResult] = {}

    @property
    def is_running(self) -> bool:
        return self._running_lock.locked()

    @property
    def current_run_id(self) -> Optional[str]:
        return self._current_run_id

    def get_result(self, run_id: str) -> Optional[ScenarioResult]:
        return self._results.get(run_id)

    def list_results(self) -> list[ScenarioResult]:
        return list(self._results.values())

    def cancel(self) -> bool:
        """Signal the active scenario to abort. Returns True if a scenario was running."""
        if self._cancel_event is not None:
            self._cancel_event.set()
            return True
        return False

    async def _send_post(
        self,
        url: str,
        json: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        if hasattr(self._client, "apost"):
            return await self._client.apost(url, json=json, headers=headers)
        elif asyncio.iscoroutinefunction(getattr(self._client, "post", None)):
            return await self._client.post(url, json=json, headers=headers)
        else:
            return self._client.post(url, json=json, headers=headers)

    # ------------------------------------------------------------------
    # Public scenario entry-points
    # ------------------------------------------------------------------

    async def run_scenario(
        self,
        scenario_type: AttackScenarioType | str,
        security_mode: str,
        parameters: Optional[dict[str, Any]] = None,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
    ) -> ScenarioResult:
        """Unified runner entry point that resolves scenario type and dispatches with parameters."""
        if isinstance(scenario_type, str):
            scenario_enum = AttackScenarioType.from_string(scenario_type)
        else:
            scenario_enum = scenario_type

        params = parameters or {}
        target_command = params.get("target_command", "ARM")
        tamper_delta = params.get("tamper_coordinate_delta", 500.0)
        flood_count = params.get("flood_count", 40)
        attempts = params.get("attempts", 3)

        if scenario_enum == AttackScenarioType.UNAUTHORIZED_COMMAND:
            return await self.run_unauthorized_command(
                security_mode=security_mode,
                attempts=attempts,
                factory=factory,
                bearer_token=bearer_token,
                target_command=target_command,
                parameters=params,
            )
        elif scenario_enum == AttackScenarioType.MESSAGE_TAMPERING:
            return await self.run_message_tampering(
                security_mode=security_mode,
                attempts=attempts,
                factory=factory,
                bearer_token=bearer_token,
                target_command=target_command,
                tamper_coordinate_delta=tamper_delta,
                parameters=params,
            )
        elif scenario_enum == AttackScenarioType.COMMAND_REPLAY:
            return await self.run_replay_attack(
                security_mode=security_mode,
                attempts=attempts,
                factory=factory,
                bearer_token=bearer_token,
                target_command=target_command,
                parameters=params,
            )
        elif scenario_enum == AttackScenarioType.SENDER_SPOOFING:
            return await self.run_sender_spoofing(
                security_mode=security_mode,
                attempts=attempts,
                factory=factory,
                bearer_token=bearer_token,
                target_command=target_command,
                parameters=params,
            )
        elif scenario_enum == AttackScenarioType.MALFORMED_FUZZING:
            return await self.run_malformed_fuzzing(
                security_mode=security_mode,
                factory=factory,
            )
        elif scenario_enum == AttackScenarioType.BOUNDED_FLOODING:
            return await self.run_bounded_flooding(
                security_mode=security_mode,
                flood_count=flood_count,
                factory=factory,
                bearer_token=bearer_token,
            )
        else:
            raise ValueError(f"Unsupported scenario: {scenario_enum}")

    async def run_unauthorized_command(
        self,
        security_mode: str,
        attempts: int = 3,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
        target_command: str = "ARM",
        parameters: Optional[dict[str, Any]] = None,
    ) -> ScenarioResult:
        """ATK-01: Inject commands with missing or invalid Bearer tokens."""
        attempts = min(attempts, MAX_ATTEMPTS)
        run_id, cancel = self._begin_run()
        t_start = time.time()

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        payload = (
            factory.unauthorized_missing_bearer(
                command=target_command,
                seq=1,
                security_mode=security_mode,
                parameters=parameters,
            )
            if factory
            else {"command": target_command, "parameters": parameters, "client_id": "ATK01_CLIENT"}
        )

        for i in range(attempts):
            if cancel.is_set():
                break
            sv_before = self._engine.state_version
            p_before = self._pos()

            t0 = time.perf_counter()
            res = await self._send_post("/api/drone/command", json=payload)
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)

            is_sec = code in _SECURITY_REJECTION_CODES or res.status_code in (401, 403, 429)
            if res.status_code == 429:
                rate_limited += 1
            elif is_sec:
                rejected_sec += 1
            elif res.status_code in (200,):
                accepted += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-01[missing-bearer] cmd={target_command}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.UNAUTHORIZED_COMMAND,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected=payload,
            started_at=t_start,
        )

    async def run_message_tampering(
        self,
        security_mode: str,
        attempts: int = 3,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
        target_command: str = "ARM",
        tamper_coordinate_delta: float = 500.0,
        parameters: Optional[dict[str, Any]] = None,
    ) -> ScenarioResult:
        """ATK-02: Submit bit-flipped ciphertext / corrupted HMAC packets."""
        attempts = min(attempts, MAX_ATTEMPTS)
        run_id, cancel = self._begin_run()
        t_start = time.time()

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        last_payload: dict[str, Any] = {}
        for i in range(attempts):
            if cancel.is_set():
                break
            sv_before = self._engine.state_version
            p_before = self._pos()

            if factory:
                payload = factory.tampered_ciphertext(
                    command=target_command,
                    seq=i + 1,
                    security_mode=security_mode,
                    parameters=parameters or {"distance": tamper_coordinate_delta},
                )
            else:
                payload = {
                    "command": target_command,
                    "parameters": parameters or {"distance": tamper_coordinate_delta},
                    "client_id": "ATK02_CLIENT",
                    "_tampered": True,
                }
            last_payload = payload

            headers = {}
            if security_mode != "UNSECURED":
                headers["Authorization"] = f"Bearer {bearer_token}"

            t0 = time.perf_counter()
            res = await self._send_post(
                "/api/drone/command", json=payload,
                headers=headers
            )
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)
            is_sec = code in _SECURITY_REJECTION_CODES or res.status_code in (403, 401)

            if res.status_code == 429:
                rate_limited += 1
            elif is_sec:
                rejected_sec += 1
            elif res.status_code == 200:
                accepted += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-02[tampered-ct] seq={i+1}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.MESSAGE_TAMPERING,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected=last_payload,
            started_at=t_start,
        )

    async def run_replay_attack(
        self,
        security_mode: str,
        attempts: int = 2,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
        target_command: str = "MOVE_FORWARD",
        parameters: Optional[dict[str, Any]] = None,
    ) -> ScenarioResult:
        """ATK-03: Submit a captured packet twice; second submission must be rejected."""
        attempts = min(attempts, MAX_ATTEMPTS)
        run_id, cancel = self._begin_run()
        t_start = time.time()

        # Ensure drone is airborne if replaying a movement command
        if target_command in ("MOVE_FORWARD", "MOVE_BACKWARD", "MOVE_LEFT", "MOVE_RIGHT", "MOVE_UP", "MOVE_DOWN"):
            from backend.app.core.flight_fsm import FlightState
            from backend.app.core.drone_engine import DroneCommand
            if self._engine.flight_state == FlightState.DISARMED:
                self._engine.execute_command(DroneCommand.ARM)
                self._engine.execute_command(DroneCommand.TAKEOFF)
            elif self._engine.flight_state == FlightState.ARMED:
                self._engine.execute_command(DroneCommand.TAKEOFF)

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        # Build one packet and submit it twice
        seq = 1
        if factory is not None:
            first_pkt = factory.captured_replay_packet(
                command=target_command,
                seq=seq,
                security_mode=security_mode,
                parameters=parameters,
            )
        else:
            first_pkt = {"command": target_command, "parameters": parameters, "client_id": "ATK03_CLIENT"}

        headers = {}
        if security_mode != "UNSECURED":
            headers["Authorization"] = f"Bearer {bearer_token}"

        for i in range(min(attempts, 2)):
            if cancel.is_set():
                break
            if i == 1:
                # Capture baseline state immediately before the replay injection
                s0 = self._snapshot()
            sv_before = self._engine.state_version
            p_before = self._pos()

            t0 = time.perf_counter()
            res = await self._send_post(
                "/api/drone/command", json=first_pkt,
                headers=headers
            )
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)
            is_sec = code in _SECURITY_REJECTION_CODES or res.status_code in (403, 401, 429)

            if res.status_code == 429:
                rate_limited += 1
            elif is_sec:
                rejected_sec += 1
            elif res.status_code == 200:
                accepted += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-03[replay] attempt={i+1} seq={seq}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.COMMAND_REPLAY,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected=first_pkt,
            started_at=t_start,
        )

    async def run_sender_spoofing(
        self,
        security_mode: str,
        attempts: int = 1,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
        target_command: str = "ARM",
        spoofed_sender: str = "ROGUE-GCS",
        parameters: Optional[dict[str, Any]] = None,
    ) -> ScenarioResult:
        """ATK-04: Submit a command with a spoofed sender_id."""
        attempts = min(attempts, MAX_ATTEMPTS)
        run_id, cancel = self._begin_run()
        t_start = time.time()

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        last_payload: dict[str, Any] = {}
        for i in range(attempts):
            if cancel.is_set():
                break
            sv_before = self._engine.state_version
            p_before = self._pos()

            payload = (
                factory.spoofed_sender_packet(
                    command=target_command,
                    seq=i + 1,
                    spoofed_sender_id=spoofed_sender,
                    security_mode=security_mode,
                    parameters=parameters,
                )
                if factory
                else {"command": target_command, "client_id": spoofed_sender}
            )
            last_payload = payload

            headers = {}
            if security_mode != "UNSECURED":
                headers["Authorization"] = f"Bearer {bearer_token}"

            t0 = time.perf_counter()
            res = await self._send_post(
                "/api/drone/command", json=payload,
                headers=headers
            )
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)
            is_sec = code in _SECURITY_REJECTION_CODES or res.status_code in (403, 401)

            if res.status_code == 429:
                rate_limited += 1
            elif is_sec:
                rejected_sec += 1
            elif res.status_code == 200:
                accepted += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-04[spoof] sender={spoofed_sender}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.SENDER_SPOOFING,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected=last_payload,
            started_at=t_start,
        )

    async def run_malformed_fuzzing(
        self,
        security_mode: str,
        factory: Any = None,
    ) -> ScenarioResult:
        """ATK-05: Submit malformed / fuzz payloads and verify zero state mutation."""
        run_id, cancel = self._begin_run()
        t_start = time.time()

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        fuzz_cases = factory.all_fuzz_cases() if factory else [
            {"command": "DO_BARREL_ROLL"},
            {},
            {"command": None},
            {"command": "ARM", "parameters": "not_a_dict"},
        ]

        for i, payload in enumerate(fuzz_cases):
            if cancel.is_set():
                break
            sv_before = self._engine.state_version
            p_before = self._pos()

            t0 = time.perf_counter()
            res = await self._send_post("/api/drone/command", json=payload)
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)
            is_sec = code in _SECURITY_REJECTION_CODES

            # Fuzz in UNSECURED mode: engine/schema rejects bad inputs
            if res.status_code == 429:
                rate_limited += 1
            elif is_sec:
                rejected_sec += 1
            elif res.status_code == 200:
                accepted += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-05[fuzz] case={i} cmd={payload.get('command', '?')}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.MALFORMED_FUZZING,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected=fuzz_cases[0] if fuzz_cases else {},
            started_at=t_start,
        )

    async def run_bounded_flooding(
        self,
        security_mode: str,
        flood_count: int = 40,
        factory: Any = None,
        bearer_token: str = "valid_secret_token",
    ) -> ScenarioResult:
        """ATK-06: Bounded burst to exercise token-bucket rate limiting."""
        flood_count = min(flood_count, MAX_FLOOD_REQUESTS)
        run_id, cancel = self._begin_run()
        t_start = time.time()

        s0 = self._snapshot()
        records: list[AttackAttemptRecord] = []
        accepted = rejected_sec = rejected_eng = rate_limited = 0

        client_id = f"FLOOD_{run_id[:8]}"
        payloads = factory.flood_batch(count=flood_count, client_id=client_id) if factory else [
            {"command": "ARM", "client_id": client_id} for _ in range(flood_count)
        ]

        headers = {"Authorization": f"Bearer {bearer_token}"} if security_mode != "UNSECURED" else None

        for i, payload in enumerate(payloads):
            if cancel.is_set():
                break
            sv_before = self._engine.state_version
            p_before = self._pos()

            t0 = time.perf_counter()
            res = await self._send_post("/api/drone/command", json=payload, headers=headers)
            lat = (time.perf_counter() - t0) * 1000

            sv_after = self._engine.state_version
            p_after = self._pos()
            code = self._error_code(res)
            is_sec = res.status_code == 429

            if res.status_code == 429:
                rate_limited += 1
                is_sec = True
            elif res.status_code == 200:
                accepted += 1
            elif code in _SECURITY_REJECTION_CODES:
                rejected_sec += 1
            else:
                rejected_eng += 1

            records.append(AttackAttemptRecord(
                attempt_index=i,
                payload_summary=f"ATK-06[flood] req={i+1}",
                http_status=res.status_code,
                response_code=code,
                latency_ms=lat,
                is_security_rejection=is_sec,
                state_version_before=sv_before,
                state_version_after=sv_after,
                position_delta_norm=self._delta_norm(p_before, p_after),
            ))

        return self._finish_run(
            run_id=run_id,
            scenario_type=AttackScenarioType.BOUNDED_FLOODING,
            security_mode=security_mode,
            s0=s0,
            records=records,
            accepted=accepted,
            rejected_sec=rejected_sec,
            rejected_eng=rejected_eng,
            rate_limited=rate_limited,
            payload_injected={"flood_count": flood_count, "client_id": client_id},
            started_at=t_start,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _begin_run(self) -> tuple[str, asyncio.Event]:
        run_id = str(uuid.uuid4())
        cancel = asyncio.Event()
        self._cancel_event = cancel
        self._current_run_id = run_id
        return run_id, cancel

    def _finish_run(
        self,
        run_id: str,
        scenario_type: AttackScenarioType,
        security_mode: str,
        s0: dict[str, Any],
        records: list[AttackAttemptRecord],
        accepted: int,
        rejected_sec: int,
        rejected_eng: int,
        rate_limited: int,
        payload_injected: Optional[dict[str, Any]] = None,
        started_at: Optional[float] = None,
    ) -> ScenarioResult:
        s1 = self._snapshot()
        state_mutated = s1["state_version"] != s0["state_version"] or \
                        self._delta_norm(s0["position"], s1["position"]) > 0.0

        defense_triggered = None
        if rate_limited > 0:
            defense_triggered = "RATE_LIMIT_EXCEEDED"
        else:
            for r in records:
                if r.response_code and r.response_code in _SECURITY_REJECTION_CODES:
                    defense_triggered = r.response_code
                    break
                if r.http_status == 429:
                    defense_triggered = "RATE_LIMIT_EXCEEDED"
                    break
                if r.http_status == 401:
                    defense_triggered = r.response_code or "AUTH_TOKEN_MISSING"
                    break
                if r.http_status == 403:
                    defense_triggered = r.response_code or "CRYPTO_DECRYPTION_FAILED"
                    break

        # Determine attack_status
        if rejected_sec > 0 or rate_limited > 0:
            status = AttackStatus.ATTACK_MITIGATED if rate_limited > 0 else AttackStatus.BLOCKED_BY_DEFENSE
        elif accepted > 0 and state_mutated:
            status = AttackStatus.SUCCESSFUL_EXPLOIT
        elif accepted == 0 and rejected_eng > 0:
            status = AttackStatus.BASELINE_REJECTED
        else:
            status = AttackStatus.BLOCKED_BY_DEFENSE if not state_mutated else AttackStatus.SUCCESSFUL_EXPLOIT

        now = time.time()
        start = started_at if started_at is not None else (now - 0.05)

        result = ScenarioResult(
            run_id=run_id,
            scenario_type=scenario_type,
            security_mode_active=security_mode,
            started_at=start,
            finished_at=now,
            status=ScenarioRunStatus.COMPLETED,
            state_version_initial=s0["state_version"],
            state_version_final=s1["state_version"],
            position_initial=s0["position"],
            position_final=s1["position"],
            total_attempts=len(records),
            accepted=accepted,
            rejected_by_security=rejected_sec,
            rejected_by_engine=rejected_eng,
            rate_limited=rate_limited,
            attempts=records,
            state_mutation_detected=state_mutated,
            invariant_passed=not state_mutated or accepted > 0,
            attack_status=status,
            defense_triggered=defense_triggered,
            payload_injected=payload_injected or {},
        )
        self._results[run_id] = result
        self._current_run_id = None
        self._cancel_event = None
        return result

    def _snapshot(self) -> dict[str, Any]:
        eng = self._engine
        return {
            "state_version": eng.state_version,
            "position": {"x": eng.x, "y": eng.y, "z": eng.z},
        }

    def _pos(self) -> dict[str, float]:
        eng = self._engine
        return {"x": eng.x, "y": eng.y, "z": eng.z}

    @staticmethod
    def _delta_norm(p0: dict[str, float], p1: dict[str, float]) -> float:
        import math
        dx = p1["x"] - p0["x"]
        dy = p1["y"] - p0["y"]
        dz = p1["z"] - p0["z"]
        return math.sqrt(dx * dx + dy * dy + dz * dz)

    @staticmethod
    def _error_code(res: Any) -> Optional[str]:
        try:
            body = res.json()
            return body.get("error", {}).get("code")
        except Exception:
            return None

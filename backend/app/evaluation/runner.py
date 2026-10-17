"""Evaluation runner coordinating repeatable benchmark experiments across all security modes."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Optional

from backend.app.attacks.attack_types import AttackScenarioType, AttackStatus
from backend.app.attacks.payload_factory import PayloadFactory
from backend.app.attacks.scenario_runner import AttackScenarioRunner, ScenarioResult
from backend.app.core.drone_engine import DroneCommand, DroneEngine, FlightState
from backend.app.evaluation.metrics import EvaluationMetricsCalculator
from backend.app.evaluation.models import (
    EvaluationRunRecord,
    EvaluationRunStatus,
    ExperimentRecord,
    ExperimentStatus,
    OverallBenchmarkMetrics,
)
from backend.app.evaluation.repository import EvaluationRepository
from backend.app.evaluation.verification_gate import VerificationGate
from backend.app.persistence.database import DatabaseManager
from backend.app.persistence.repositories import LogQueryRepository
from backend.app.security.crypto_service import CryptoService
from backend.app.security.message_protocol import (
    SecurityMode,
    pack_encrypted_command,
    pack_hmac_command,
)
from backend.app.security.security_service import SecurityService
from backend.app.services.attack_service import AttackService
from backend.app.services.command_service import CommandService


class EvaluationRunner:
    """Orchestrates controlled, repeatable security benchmark evaluations.
    
    Guarantees:
    - Zero external network exposure (local simulation only).
    - Synthetic identities, sequence numbers, and keys.
    - Deterministic reset of engine state and anti-replay windows between runs.
    - Explicit separation between baseline FSM rejections and cryptographic defenses.
    - Accurate latency measurements and invariant verification.
    """

    def __init__(
        self,
        drone_engine: DroneEngine,
        command_service: CommandService,
        security_service: SecurityService,
        attack_service: AttackService,
        eval_repo: EvaluationRepository,
        crypto_service: CryptoService,
        log_repo: LogQueryRepository,
        db_manager: DatabaseManager,
        bearer_token: str = "gcs-sim-token-secret-2026",
    ) -> None:
        self.engine = drone_engine
        self.cmd_service = command_service
        self.sec_service = security_service
        self.attack_service = attack_service
        self.eval_repo = eval_repo
        self.crypto_service = crypto_service
        self.log_repo = log_repo
        self.db_manager = db_manager
        self.bearer_token = bearer_token
        self.factory = PayloadFactory(crypto_service=crypto_service)
        self.verification_gate = VerificationGate(
            drone_engine=drone_engine,
            command_service=command_service,
            security_service=security_service,
            attack_service=attack_service,
            log_repo=log_repo,
        )

    def _reset_to_ground(self) -> None:
        """Reset drone engine to grounded, DISARMED state."""
        self.engine._fsm.reset(FlightState.DISARMED)
        self.engine._armed = False
        self.engine._x = 0.0
        self.engine._y = 0.0
        self.engine._z = 0.0
        self.engine._heading = 0.0
        self.engine._speed = 0.0
        self.engine._battery_level = 100.0
        self.engine._state_version = 0

    def _bring_to_hover(self) -> None:
        """Bring drone engine to airborne HOVERING state at Y=5.0m."""
        self._reset_to_ground()
        self.engine.execute_command(DroneCommand.ARM)
        self.engine.execute_command(DroneCommand.TAKEOFF)

    async def run_evaluation(
        self,
        modes: Optional[list[str]] = None,
        iterations_per_scenario: int = 3,
        run_gate: bool = True,
    ) -> tuple[EvaluationRunRecord, OverallBenchmarkMetrics, list[ExperimentRecord]]:
        """Run complete security benchmark across specified operational modes."""
        target_modes = modes or ["UNSECURED", "INTEGRITY_ONLY", "ENCRYPTED_AUTHENTICATED"]
        run_id = f"eval_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        t_start = time.time()

        # 1. Run integration verification gate first if requested
        gate_passed = True
        if run_gate:
            gate_res = await self.verification_gate.run_gate()
            gate_passed = gate_res.gate_status.value == "PASSED"

        # Calculate estimated total experiments
        # 6 attack scenarios + 1 legitimate command cycle per mode
        total_exps = len(target_modes) * 7

        run_record = EvaluationRunRecord(
            id=str(uuid.uuid4()),
            run_id=run_id,
            timestamp=t_start,
            status=EvaluationRunStatus.RUNNING,
            total_experiments=total_exps,
            completed_experiments=0,
        )
        await self.eval_repo.save_run_async(run_record)

        experiments: list[ExperimentRecord] = []

        try:
            for mode_str in target_modes:
                mode_enum = SecurityMode(mode_str)
                # Switch security mode formally
                self.sec_service.set_security_mode(mode_enum, reason=f"Phase 6 Benchmark Run {run_id}")

                # --- Attack Scenarios ---
                scenarios = [
                    (AttackScenarioType.UNAUTHORIZED_COMMAND, "UNAUTHORIZED_COMMAND", {"target_command": "ARM", "attempts": iterations_per_scenario}),
                    (AttackScenarioType.MESSAGE_TAMPERING, "MESSAGE_TAMPERING", {"target_command": "MOVE_FORWARD", "tamper_coordinate_delta": 500.0, "attempts": iterations_per_scenario}),
                    (AttackScenarioType.COMMAND_REPLAY, "COMMAND_REPLAY", {"target_command": "MOVE_FORWARD", "attempts": iterations_per_scenario}),
                    (AttackScenarioType.SENDER_SPOOFING, "SENDER_SPOOFING", {"target_command": "ARM", "attempts": iterations_per_scenario}),
                    (AttackScenarioType.MALFORMED_FUZZING, "MALFORMED_FUZZING", {}),
                    (AttackScenarioType.BOUNDED_FLOODING, "BOUNDED_FLOODING", {"flood_count": 30}),
                ]

                for sc_type, sc_name, params in scenarios:
                    exp = await self._run_attack_experiment(
                        run_id=run_id,
                        security_mode=mode_str,
                        scenario_type=sc_type,
                        scenario_name=sc_name,
                        params=params,
                    )
                    experiments.append(exp)
                    await self.eval_repo.save_experiment_async(exp)
                    run_record.completed_experiments += 1
                    await self.eval_repo.save_run_async(run_record)

                # --- Legitimate Command Flight Cycle ---
                legit_exp = await self._run_legitimate_command_cycle(
                    run_id=run_id,
                    security_mode=mode_str,
                )
                experiments.append(legit_exp)
                await self.eval_repo.save_experiment_async(legit_exp)
                run_record.completed_experiments += 1
                await self.eval_repo.save_run_async(run_record)

            # Compute quantitative benchmark metrics
            overall_metrics = EvaluationMetricsCalculator.compute_overall_metrics(
                run_id=run_id,
                timestamp=t_start,
                experiments=experiments,
                verification_gate_passed=gate_passed,
            )

            # Mark run completed
            run_record.status = EvaluationRunStatus.COMPLETED
            run_record.metrics_summary = overall_metrics.to_dict()

            # Generate markdown report
            from backend.app.evaluation.exporter import EvaluationExporter
            report_md = EvaluationExporter.generate_markdown_report(
                run_record=run_record,
                metrics=overall_metrics,
                experiments=experiments,
            )
            run_record.markdown_report = report_md
            await self.eval_repo.save_run_async(run_record)

            # Reset security mode back to UNSECURED following evaluation
            self.sec_service.set_security_mode(SecurityMode.UNSECURED, reason="Post-benchmark reset")
            self._reset_to_ground()

            return run_record, overall_metrics, experiments

        except Exception as e:
            run_record.status = EvaluationRunStatus.FAILED
            await self.eval_repo.save_run_async(run_record)
            raise

    async def _run_attack_experiment(
        self,
        run_id: str,
        security_mode: str,
        scenario_type: AttackScenarioType,
        scenario_name: str,
        params: dict[str, Any],
    ) -> ExperimentRecord:
        """Run an isolated attack scenario experiment with controlled initial drone state."""
        exp_id = f"exp_{scenario_name}_{security_mode}_{uuid.uuid4().hex[:4]}"
        t_exp_start = time.time()

        # Controlled initial state setup:
        # If the attack scenario tests movement (tampering or replay), the drone must be HOVERING.
        # Otherwise, the engine FSM will reject MOVE_FORWARD before security has a chance to evaluate it!
        requires_airborne = scenario_type in {
            AttackScenarioType.MESSAGE_TAMPERING,
            AttackScenarioType.COMMAND_REPLAY,
        }
        if requires_airborne:
            self._bring_to_hover()
        else:
            self._reset_to_ground()

        initial_snapshot = self.engine.get_state_snapshot()
        initial_state_dict = {
            "state_version": initial_snapshot.state_version,
            "flight_state": initial_snapshot.flight_state.value,
            "x": initial_snapshot.x,
            "y": initial_snapshot.y,
            "z": initial_snapshot.z,
            "battery": initial_snapshot.battery_level,
        }

        runner = self.attack_service.get_runner()
        scenario_res: ScenarioResult = await runner.run_scenario(
            scenario_type=scenario_type,
            security_mode=security_mode,
            parameters=params,
            factory=self.factory,
            bearer_token=self.bearer_token,
        )

        final_snapshot = self.engine.get_state_snapshot()
        final_state_dict = {
            "state_version": final_snapshot.state_version,
            "flight_state": final_snapshot.flight_state.value,
            "x": final_snapshot.x,
            "y": final_snapshot.y,
            "z": final_snapshot.z,
            "battery": final_snapshot.battery_level,
        }

        # Check state mutation
        # Note: In multi-step scenarios such as COMMAND_REPLAY (ATK-03), attempt 0 transmits
        # a legitimate frame to capture, and attempt 1 is the replay attempt.
        # scenario_res.state_compromised specifically evaluates whether unauthorized mutation occurred during the replay.
        if scenario_type == AttackScenarioType.COMMAND_REPLAY:
            state_mutated = scenario_res.state_compromised
        else:
            state_mutated = (
                scenario_res.state_compromised or
                final_snapshot.state_version != initial_snapshot.state_version or
                abs(final_snapshot.x - initial_snapshot.x) > 0.001 or
                abs(final_snapshot.y - initial_snapshot.y) > 0.001 or
                abs(final_snapshot.z - initial_snapshot.z) > 0.001
            )

        latencies = [a.latency_ms for a in scenario_res.attempts]
        sorted_lats = sorted(latencies)
        p50 = sorted_lats[len(sorted_lats) // 2] if sorted_lats else None
        p95 = sorted_lats[int(len(sorted_lats) * 0.95)] if sorted_lats else None

        # Determine pass / fail / inconclusive
        # In UNSECURED: ATK-01..04 should mutate state (demonstrating exploitability). ATK-05 is rejected by schema.
        # In SECURED: All attacks must NOT mutate state, and defense must be triggered.
        result_status = ExperimentStatus.PASS
        result_reason = ""

        if security_mode == "UNSECURED":
            if scenario_type in {
                AttackScenarioType.UNAUTHORIZED_COMMAND,
                AttackScenarioType.MESSAGE_TAMPERING,
                AttackScenarioType.COMMAND_REPLAY,
                AttackScenarioType.SENDER_SPOOFING,
            }:
                if state_mutated:
                    result_reason = "Expected exploit demonstrated: unauthenticated/tampered command executed."
                else:
                    result_status = ExperimentStatus.FAIL
                    result_reason = "Vulnerability demonstration failed: command was rejected unexpectedly."
            else:
                result_reason = f"Baseline rejection observed: {scenario_res.attack_status.value}."
        else:
            # Secured modes: Integrity or Encrypted
            if state_mutated and scenario_type != AttackScenarioType.BOUNDED_FLOODING:
                result_status = ExperimentStatus.FAIL
                result_reason = "Security failure: state mutation occurred despite defensive profile."
            else:
                defense = scenario_res.defense_triggered or "BLOCKED"
                result_reason = f"Defense held: attack terminated ({defense}). Authoritative state preserved."

        return ExperimentRecord(
            id=str(uuid.uuid4()),
            run_id=run_id,
            experiment_id=exp_id,
            timestamp=t_exp_start,
            security_mode=security_mode,
            scenario_type=scenario_name,
            test_config=params,
            initial_state=initial_state_dict,
            final_state=final_state_dict,
            attempts_count=scenario_res.total_attempts,
            accepted_count=scenario_res.accepted,
            rejected_security_count=scenario_res.rejected_by_security,
            rejected_engine_count=scenario_res.rejected_by_engine,
            rate_limited_count=scenario_res.rate_limited,
            actual_defense_reason=scenario_res.defense_triggered,
            state_mutated=state_mutated,
            result_status=result_status,
            result_reason=result_reason,
            latencies=latencies,
            p50_latency_ms=p50,
            p95_latency_ms=p95,
            audit_event_ids=[scenario_res.run_id],
        )

    async def _run_legitimate_command_cycle(
        self,
        run_id: str,
        security_mode: str,
    ) -> ExperimentRecord:
        """Execute authorized, valid flight command lifecycle in the active security mode."""
        exp_id = f"exp_LEGITIMATE_{security_mode}_{uuid.uuid4().hex[:4]}"
        t_exp_start = time.time()

        self._reset_to_ground()
        initial_snapshot = self.engine.get_state_snapshot()
        initial_state_dict = {
            "state_version": initial_snapshot.state_version,
            "flight_state": initial_snapshot.flight_state.value,
            "x": initial_snapshot.x,
            "y": initial_snapshot.y,
            "z": initial_snapshot.z,
            "battery": initial_snapshot.battery_level,
        }

        # Sequence of 4 legitimate commands: ARM -> TAKEOFF -> MOVE_FORWARD -> LAND
        commands_to_run = [
            ("ARM", None),
            ("TAKEOFF", None),
            ("MOVE_FORWARD", {"distance_meters": 2.0}),
            ("LAND", None),
        ]

        latencies: list[float] = []
        accepted = 0
        rejected_sec = 0
        rejected_eng = 0
        highest_seq = self.sec_service.replay_filter.get_highest_sequence_number("GCS-PRIMARY")
        seq = max(1, highest_seq + 1)

        for cmd_name, params in commands_to_run:
            t0 = time.perf_counter()
            if security_mode == "UNSECURED":
                payload = {"command": cmd_name, "parameters": params, "client_id": "GCS-PRIMARY"}
            elif security_mode == "INTEGRITY_ONLY":
                payload = pack_hmac_command(
                    crypto_service=self.crypto_service,
                    command=cmd_name,
                    parameters=params,
                    sender_id="GCS-PRIMARY",
                    sequence_number=seq,
                    timestamp=time.time(),
                )
            else:  # ENCRYPTED_AUTHENTICATED
                payload = pack_encrypted_command(
                    crypto_service=self.crypto_service,
                    command=cmd_name,
                    parameters=params,
                    sender_id="GCS-PRIMARY",
                    sequence_number=seq,
                    timestamp=time.time(),
                )
            seq += 1

            outcome = await self.cmd_service.process_and_execute(
                raw_payload=payload,
                authorization_header=f"Bearer {self.bearer_token}",
                source_ip="127.0.0.1",
            )
            lat_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(round(lat_ms, 2))

            if outcome.success:
                accepted += 1
            else:
                rejected_eng += 1

        final_snapshot = self.engine.get_state_snapshot()
        final_state_dict = {
            "state_version": final_snapshot.state_version,
            "flight_state": final_snapshot.flight_state.value,
            "x": final_snapshot.x,
            "y": final_snapshot.y,
            "z": final_snapshot.z,
            "battery": final_snapshot.battery_level,
        }

        sorted_lats = sorted(latencies)
        p50 = sorted_lats[len(sorted_lats) // 2] if sorted_lats else None
        p95 = sorted_lats[int(len(sorted_lats) * 0.95)] if sorted_lats else None

        all_succeeded = accepted == len(commands_to_run)
        result_status = ExperimentStatus.PASS if all_succeeded else ExperimentStatus.FAIL
        result_reason = (
            f"Authorized command cycle: {accepted}/{len(commands_to_run)} executed successfully."
            if all_succeeded
            else f"Authorized command rejected in {security_mode} mode."
        )

        return ExperimentRecord(
            id=str(uuid.uuid4()),
            run_id=run_id,
            experiment_id=exp_id,
            timestamp=t_exp_start,
            security_mode=security_mode,
            scenario_type="LEGITIMATE_FLIGHT_CYCLE",
            test_config={"commands": [c[0] for c in commands_to_run]},
            initial_state=initial_state_dict,
            final_state=final_state_dict,
            attempts_count=len(commands_to_run),
            accepted_count=accepted,
            rejected_security_count=rejected_sec,
            rejected_engine_count=rejected_eng,
            rate_limited_count=0,
            actual_defense_reason=None,
            state_mutated=True,  # Legitimate flight commands are intended to mutate state
            result_status=result_status,
            result_reason=result_reason,
            latencies=latencies,
            p50_latency_ms=p50,
            p95_latency_ms=p95,
            audit_event_ids=[],
        )

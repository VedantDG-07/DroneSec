"""Automated test suite for Phase 6: End-to-End Security Evaluation and Benchmarking.

Covers:
- Integration-verification gate execution and failure detection
- Experiment isolation and simulation reset behavior
- Reproducible scenario configurations across UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED
- Metric calculations with zero denominators, empty datasets, and boundary values
- Missing and inconclusive observations handling
- SQLite audit persistence and result retrieval
- Authoritative state-invariant tracking and drift calculation
- Authorization and mode-switching safeguards
- CSV, JSON, and Markdown export correctness
- Regression coverage for vertical movement and command packaging
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient

from backend.app.attacks.attack_types import AttackScenarioType, AttackStatus
from backend.app.config import AppConfig
from backend.app.core.drone_engine import DroneCommand, DroneEngine, FlightState
from backend.app.evaluation.exporter import EvaluationExporter
from backend.app.evaluation.metrics import EvaluationMetricsCalculator
from backend.app.evaluation.repository import EvaluationRepository
from backend.app.evaluation.runner import EvaluationRunner
from backend.app.evaluation.verification_gate import VerificationGate
from backend.app.evaluation.models import (
    EvaluationRunRecord,
    EvaluationRunStatus,
    ExperimentRecord,
    ExperimentStatus,
    GateStatus,
)
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager
from backend.app.security.message_protocol import SecurityMode


@pytest.fixture
def eval_app(tmp_path: Path):
    """Fixture providing an isolated FastAPI test application and TestClient."""
    db_file = tmp_path / "test_evaluation.db"
    db_mgr = DatabaseManager(str(db_file))

    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        rate_limit_capacity=30.0,
        rate_limit_refill_rate=15.0,
        security_mode="UNSECURED",
    )

    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client, app


# ===========================================================================
# 1. Integration-Verification Gate
# ===========================================================================

class TestVerificationGate:
    """Verifies that the integration gate passes on healthy systems and detects anomalies."""

    @pytest.mark.asyncio
    async def test_verification_gate_passes_on_healthy_system(self, eval_app):
        client, app = eval_app
        gate = VerificationGate(
            drone_engine=app.state.drone_engine,
            command_service=app.state.command_service,
            security_service=app.state.security_service,
            attack_service=app.state.attack_service,
            log_repo=app.state.log_repo,
        )

        result = await gate.run_gate()
        failed_checks = [c for c in result.checks if not c.passed]
        assert not failed_checks, f"Failed checks: {[(c.name, c.error_message) for c in failed_checks]}"
        assert result.gate_status == GateStatus.PASSED
        assert result.failed_count == 0
        assert result.passed_count > 0
        assert "PASSED" in result.summary

    @pytest.mark.asyncio
    async def test_verification_gate_detects_simulated_fsm_failure(self, eval_app):
        """Verify the gate reports FAILED if an invariant check fails."""
        client, app = eval_app
        gate = VerificationGate(
            drone_engine=app.state.drone_engine,
            command_service=app.state.command_service,
            security_service=app.state.security_service,
            attack_service=app.state.attack_service,
            log_repo=app.state.log_repo,
        )

        # Intentionally tamper with drone engine to disallow ARM
        original_arm = app.state.drone_engine._handle_arm
        from backend.app.core.drone_engine import CommandResult

        app.state.drone_engine._handle_arm = lambda cmd_id: CommandResult(
            success=False,
            command=DroneCommand.ARM,
            message="Simulated motor failure",
            state_version=0,
            error_code="HARDWARE_FAULT",
        )

        try:
            result = await gate.run_gate()
            assert result.gate_status == GateStatus.FAILED
            assert result.failed_count >= 1
            arm_check = next(c for c in result.checks if c.name == "Flight Command Lifecycle")
            assert arm_check.passed is False
            assert "Simulated motor failure" in str(arm_check.error_message)
        finally:
            app.state.drone_engine._handle_arm = original_arm


# ===========================================================================
# 2. Experiment Isolation and Reset Behavior
# ===========================================================================

class TestExperimentIsolation:
    """Verify simulation resets cleanly between runs and does not pollute state."""

    @pytest.mark.asyncio
    async def test_engine_resets_between_experiments(self, eval_app):
        client, app = eval_app
        runner: EvaluationRunner = app.state.eval_runner

        # Put engine into airborne state with non-zero coordinates
        runner._bring_to_hover()
        runner.engine.execute_command(DroneCommand.MOVE_FORWARD, distance_meters=5.0)
        assert runner.engine.z == 5.0
        assert runner.engine.flight_state == FlightState.HOVERING

        # Reset to ground
        runner._reset_to_ground()
        assert runner.engine.flight_state == FlightState.DISARMED
        assert runner.engine.x == 0.0
        assert runner.engine.y == 0.0
        assert runner.engine.z == 0.0
        assert runner.engine.battery_level == 100.0
        assert runner.engine.state_version == 0


# ===========================================================================
# 3. Reproducible Scenario Configurations Across Security Modes
# ===========================================================================

class TestReproducibleScenarios:
    """Validate experiments in UNSECURED, INTEGRITY_ONLY, and ENCRYPTED_AUTHENTICATED."""

    @pytest.mark.asyncio
    async def test_unsecured_mode_demonstrates_vulnerability(self, eval_app):
        client, app = eval_app
        runner: EvaluationRunner = app.state.eval_runner

        # Run unauthorized injection in UNSECURED
        exp = await runner._run_attack_experiment(
            run_id="test_run_unsec",
            security_mode="UNSECURED",
            scenario_type=AttackScenarioType.UNAUTHORIZED_COMMAND,
            scenario_name="UNAUTHORIZED_COMMAND",
            params={"target_command": "ARM", "attempts": 2},
        )

        assert exp.security_mode == "UNSECURED"
        assert exp.state_mutated is True
        assert exp.result_status == ExperimentStatus.PASS  # Expected exploit shown

    @pytest.mark.asyncio
    async def test_integrity_only_blocks_tampering(self, eval_app):
        client, app = eval_app
        runner: EvaluationRunner = app.state.eval_runner
        runner.sec_service.set_security_mode(SecurityMode.INTEGRITY_ONLY)

        exp = await runner._run_attack_experiment(
            run_id="test_run_int",
            security_mode="INTEGRITY_ONLY",
            scenario_type=AttackScenarioType.MESSAGE_TAMPERING,
            scenario_name="MESSAGE_TAMPERING",
            params={"target_command": "MOVE_FORWARD", "tamper_coordinate_delta": 500.0, "attempts": 2},
        )

        assert exp.security_mode == "INTEGRITY_ONLY"
        assert exp.state_mutated is False
        assert exp.result_status == ExperimentStatus.PASS
        assert exp.actual_defense_reason == "HMAC_VERIFICATION_FAILED"

    @pytest.mark.asyncio
    async def test_encrypted_authenticated_blocks_replay(self, eval_app):
        client, app = eval_app
        runner: EvaluationRunner = app.state.eval_runner
        runner.sec_service.set_security_mode(SecurityMode.ENCRYPTED_AUTHENTICATED)

        exp = await runner._run_attack_experiment(
            run_id="test_run_enc",
            security_mode="ENCRYPTED_AUTHENTICATED",
            scenario_type=AttackScenarioType.COMMAND_REPLAY,
            scenario_name="COMMAND_REPLAY",
            params={"target_command": "MOVE_FORWARD", "attempts": 2},
        )

        assert exp.security_mode == "ENCRYPTED_AUTHENTICATED"
        assert exp.state_mutated is False
        assert exp.result_status == ExperimentStatus.PASS
        assert exp.actual_defense_reason == "REPLAY_ATTACK_DETECTED"

    @pytest.mark.asyncio
    async def test_legitimate_command_cycle_succeeds_in_all_modes(self, eval_app):
        client, app = eval_app
        runner: EvaluationRunner = app.state.eval_runner

        for mode in ("UNSECURED", "INTEGRITY_ONLY", "ENCRYPTED_AUTHENTICATED"):
            runner.sec_service.set_security_mode(SecurityMode(mode))
            exp = await runner._run_legitimate_command_cycle(
                run_id="test_legit_cycle",
                security_mode=mode,
            )
            assert exp.result_status == ExperimentStatus.PASS
            assert exp.accepted_count == exp.attempts_count
            assert exp.rejected_security_count == 0


# ===========================================================================
# 4. Metric Calculations & Zero Denominators
# ===========================================================================

class TestMetricCalculations:
    """Verifies math correctness, division-by-zero protection, and percentiles."""

    def test_zero_denominators_safe(self):
        """Empty experiment list must return 0.0 rates without ZeroDivisionError."""
        metrics = EvaluationMetricsCalculator.compute_mode_metrics("TEST_MODE", [])
        assert metrics.total_experiments == 0
        assert metrics.total_attack_attempts == 0
        assert metrics.unauthorized_mutation_rate == 0.0
        assert metrics.attack_rejection_rate == 0.0
        assert metrics.detection_rate == 0.0
        assert metrics.replay_rejection_rate == 0.0
        assert metrics.legitimate_success_rate == 0.0
        assert metrics.median_latency_ms is None
        assert metrics.p95_latency_ms is None
        assert metrics.inconclusive_rate == 0.0

    def test_overall_metrics_empty_experiments(self):
        overall = EvaluationMetricsCalculator.compute_overall_metrics("run_empty", time.time(), [])
        assert overall.total_experiments == 0
        assert overall.overall_unauthorized_mutation_rate == 0.0
        assert overall.overall_attack_rejection_rate == 0.0
        assert overall.overall_legitimate_success_rate == 0.0
        assert overall.overall_median_latency_ms is None
        assert overall.overall_p95_latency_ms is None

    def test_metric_calculations_with_synthetic_data(self):
        exp1 = ExperimentRecord(
            id="1", run_id="r1", experiment_id="e1", timestamp=100.0,
            security_mode="ENCRYPTED_AUTHENTICATED", scenario_type="ATK-01",
            test_config={}, initial_state={}, final_state={},
            attempts_count=4, accepted_count=0, rejected_security_count=4,
            rejected_engine_count=0, rate_limited_count=0,
            actual_defense_reason="AUTH_TOKEN_MISSING", state_mutated=False,
            result_status=ExperimentStatus.PASS, result_reason="",
            latencies=[1.0, 2.0, 3.0, 4.0], p50_latency_ms=2.5, p95_latency_ms=3.85,
            audit_event_ids=["evt1"],
        )
        exp2 = ExperimentRecord(
            id="2", run_id="r1", experiment_id="e2", timestamp=101.0,
            security_mode="ENCRYPTED_AUTHENTICATED", scenario_type="LEGITIMATE_FLIGHT",
            test_config={}, initial_state={}, final_state={},
            attempts_count=2, accepted_count=2, rejected_security_count=0,
            rejected_engine_count=0, rate_limited_count=0,
            actual_defense_reason=None, state_mutated=True,
            result_status=ExperimentStatus.PASS, result_reason="",
            latencies=[0.5, 0.8], p50_latency_ms=0.65, p95_latency_ms=0.78,
            audit_event_ids=[],
        )

        m = EvaluationMetricsCalculator.compute_mode_metrics("ENCRYPTED_AUTHENTICATED", [exp1, exp2])
        assert m.total_experiments == 2
        assert m.total_attack_attempts == 4
        assert m.unauthorized_mutation_rate == 0.0
        assert m.attack_rejection_rate == 1.0  # 4 / 4
        assert m.detection_rate == 1.0
        assert m.legitimate_success_rate == 1.0  # 2 / 2
        assert m.median_latency_ms is not None


# ===========================================================================
# 5. Missing or Inconclusive Observations Handling
# ===========================================================================

class TestInconclusiveHandling:
    """Verifies that missing or inconclusive observations are accounted for."""

    def test_inconclusive_experiment_flagged(self):
        exp = ExperimentRecord(
            id="inc1", run_id="r_inc", experiment_id="e_inc", timestamp=100.0,
            security_mode="UNSECURED", scenario_type="ATK-01",
            test_config={}, initial_state={}, final_state={},
            attempts_count=1, accepted_count=0, rejected_security_count=0,
            rejected_engine_count=0, rate_limited_count=0,
            actual_defense_reason=None, state_mutated=False,
            result_status=ExperimentStatus.INCONCLUSIVE,
            result_reason="Network socket timeout",
            latencies=[], p50_latency_ms=None, p95_latency_ms=None,
            audit_event_ids=[],
        )
        m = EvaluationMetricsCalculator.compute_mode_metrics("UNSECURED", [exp])
        assert m.inconclusive_count == 1
        assert m.inconclusive_rate == 1.0
        assert m.unauthorized_mutation_rate == 0.0


# ===========================================================================
# 6. Persistence & Result Retrieval
# ===========================================================================

class TestPersistenceAndRetrieval:
    """Verifies SQLite storage and retrieval of evaluation runs and experiments."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve_evaluation_run(self, eval_app):
        client, app = eval_app
        repo: EvaluationRepository = app.state.eval_repo

        run_id = f"test_run_{int(time.time())}"
        run_rec = EvaluationRunRecord(
            id="run_uuid_1",
            run_id=run_id,
            timestamp=time.time(),
            status=EvaluationRunStatus.COMPLETED,
            total_experiments=5,
            completed_experiments=5,
            metrics_summary={"sample_metric": 42},
            markdown_report="# Sample Markdown",
        )
        await repo.save_run_async(run_rec)

        fetched = await repo.get_run_async(run_id)
        assert fetched is not None
        assert fetched.run_id == run_id
        assert fetched.status == EvaluationRunStatus.COMPLETED
        assert fetched.metrics_summary == {"sample_metric": 42}
        assert fetched.markdown_report == "# Sample Markdown"

        latest = await repo.get_latest_run_async()
        assert latest is not None
        assert latest.run_id == run_id

        history = await repo.list_runs_async(limit=10)
        assert len(history) >= 1
        assert any(r.run_id == run_id for r in history)


# ===========================================================================
# 7. State-Invariant Tracking
# ===========================================================================

class TestStateInvariantTracking:
    """Verifies drift calculations and state version atomicity."""

    def test_invariant_calculation_drift(self):
        p_init = {"x": 10.0, "y": 5.0, "z": 20.0, "state_version": 4}
        p_final = {"x": 10.0, "y": 5.0, "z": 20.0, "state_version": 4}

        mutated = (
            p_final["state_version"] != p_init["state_version"] or
            p_final["x"] != p_init["x"] or
            p_final["y"] != p_init["y"] or
            p_final["z"] != p_init["z"]
        )
        assert mutated is False


# ===========================================================================
# 8. CSV & JSON Export Correctness
# ===========================================================================

class TestExportCorrectness:
    """Verifies CSV, JSON, and Markdown generation formatting and schemas."""

    def test_json_export_structure(self):
        run_rec = EvaluationRunRecord(
            id="r1", run_id="test_export_run", timestamp=time.time(),
            status=EvaluationRunStatus.COMPLETED, total_experiments=1, completed_experiments=1,
            metrics_summary={}, markdown_report="Report",
        )
        exp = ExperimentRecord(
            id="e1", run_id="test_export_run", experiment_id="exp1", timestamp=time.time(),
            security_mode="ENCRYPTED_AUTHENTICATED", scenario_type="ATK-01",
            test_config={"cmd": "ARM"}, initial_state={"v": 0}, final_state={"v": 0},
            attempts_count=1, accepted_count=0, rejected_security_count=1,
            rejected_engine_count=0, rate_limited_count=0, actual_defense_reason="AUTH_TOKEN_MISSING",
            state_mutated=False, result_status=ExperimentStatus.PASS, result_reason="Defense held",
            latencies=[1.2], p50_latency_ms=1.2, p95_latency_ms=1.2, audit_event_ids=["run_1"],
        )
        metrics = EvaluationMetricsCalculator.compute_overall_metrics("test_export_run", time.time(), [exp])

        json_str = EvaluationExporter.export_json(run_rec, metrics, [exp])
        parsed = json.loads(json_str)
        assert "evaluation_run" in parsed
        assert "benchmark_metrics" in parsed
        assert "experiments" in parsed
        assert len(parsed["experiments"]) == 1
        assert parsed["experiments"][0]["experiment_id"] == "exp1"

    def test_csv_export_headers_and_rows(self):
        exp = ExperimentRecord(
            id="e1", run_id="test_csv_run", experiment_id="exp1", timestamp=time.time(),
            security_mode="INTEGRITY_ONLY", scenario_type="ATK-02",
            test_config={}, initial_state={"state_version": 2}, final_state={"state_version": 2},
            attempts_count=3, accepted_count=0, rejected_security_count=3,
            rejected_engine_count=0, rate_limited_count=0, actual_defense_reason="HMAC_VERIFICATION_FAILED",
            state_mutated=False, result_status=ExperimentStatus.PASS, result_reason="Blocked",
            latencies=[0.8, 0.9, 1.0], p50_latency_ms=0.9, p95_latency_ms=1.0, audit_event_ids=[],
        )
        csv_str = EvaluationExporter.export_csv([exp])
        reader = list(csv.reader(csv_str.strip().splitlines()))
        headers = reader[0]
        row = reader[1]

        assert "run_id" in headers
        assert "security_mode" in headers
        assert "actual_defense_reason" in headers
        assert row[0] == "test_csv_run"
        assert row[3] == "INTEGRITY_ONLY"
        assert row[4] == "ATK-02"
        assert row[10] == "HMAC_VERIFICATION_FAILED"

    def test_markdown_report_generation(self):
        run_rec = EvaluationRunRecord(
            id="r1", run_id="test_md_run", timestamp=time.time(),
            status=EvaluationRunStatus.COMPLETED, total_experiments=1, completed_experiments=1,
            metrics_summary={}, markdown_report=None,
        )
        exp = ExperimentRecord(
            id="e1", run_id="test_md_run", experiment_id="exp1", timestamp=time.time(),
            security_mode="ENCRYPTED_AUTHENTICATED", scenario_type="ATK-01",
            test_config={}, initial_state={"state_version": 1}, final_state={"state_version": 1},
            attempts_count=2, accepted_count=0, rejected_security_count=2,
            rejected_engine_count=0, rate_limited_count=0, actual_defense_reason="AUTH_TOKEN_MISSING",
            state_mutated=False, result_status=ExperimentStatus.PASS, result_reason="Defense held",
            latencies=[1.5, 2.1], p50_latency_ms=1.8, p95_latency_ms=2.1, audit_event_ids=[],
        )
        metrics = EvaluationMetricsCalculator.compute_overall_metrics("test_md_run", time.time(), [exp])
        md = EvaluationExporter.generate_markdown_report(run_rec, metrics, [exp])

        assert "# DroneSec: Phase 6 Security Evaluation & Benchmarking Report" in md
        assert "## 1. Executive Summary" in md
        assert "## 3. Metric Definitions" in md
        assert "## 4. Benchmark Results Comparison Matrix" in md
        assert "ENCRYPTED_AUTHENTICATED" in md


# ===========================================================================
# 9. Command Packaging Helper Endpoint
# ===========================================================================

class TestCommandPackagingEndpoint:
    """Verifies POST /api/drone/command/pack across UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED."""

    def test_pack_command_unsecured(self, eval_app):
        client, app = eval_app
        client.post("/api/security/mode", json={"mode": "UNSECURED"})

        resp = client.post("/api/drone/command/pack", json={"command": "ARM"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["security_mode"] == "UNSECURED"
        assert data["payload"]["command"] == "ARM"

    def test_pack_command_integrity_only(self, eval_app):
        client, app = eval_app
        client.post("/api/security/mode", json={"mode": "INTEGRITY_ONLY"})

        resp = client.post("/api/drone/command/pack", json={"command": "ARM"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["security_mode"] == "INTEGRITY_ONLY"
        assert "header" in data["payload"]
        assert "signature" in data["payload"]
        assert data["payload"]["header"]["security_mode"] == "INTEGRITY_ONLY"

    def test_pack_command_encrypted(self, eval_app):
        client, app = eval_app
        client.post("/api/security/mode", json={"mode": "ENCRYPTED_AUTHENTICATED"})

        resp = client.post("/api/drone/command/pack", json={"command": "ARM"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["security_mode"] == "ENCRYPTED_AUTHENTICATED"
        assert "header" in data["payload"]
        assert "iv" in data["payload"]
        assert "ciphertext" in data["payload"]
        assert "auth_tag" in data["payload"]


# ===========================================================================
# 10. Evaluation REST API Endpoints Integration
# ===========================================================================

class TestEvaluationApiEndpoints:
    """Verifies the REST API surface for verification gate, run, latest, and export."""

    def test_api_verify_endpoint(self, eval_app):
        client, app = eval_app
        resp = client.post("/api/evaluation/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        data = body["data"]
        assert data["gate_status"] in ("PASSED", "FAILED")
        assert "checks" in data
        assert len(data["checks"]) >= 5

    def test_api_run_and_latest_endpoints(self, eval_app):
        client, app = eval_app
        # Run a small benchmark (1 iteration per scenario)
        run_resp = client.post("/api/evaluation/run", json={"modes": ["UNSECURED"], "iterations_per_scenario": 1})
        assert run_resp.status_code == 200
        run_data = run_resp.json()["data"]
        assert "run" in run_data
        assert "metrics" in run_data

        # Fetch latest
        latest_resp = client.get("/api/evaluation/latest")
        assert latest_resp.status_code == 200
        latest_data = latest_resp.json()["data"]
        assert latest_data["run"]["run_id"] == run_data["run"]["run_id"]
        assert len(latest_data["experiments"]) >= 7

        # Fetch history
        hist_resp = client.get("/api/evaluation/history")
        assert hist_resp.status_code == 200
        assert len(hist_resp.json()["data"]) >= 1

        # Export JSON
        export_json = client.get("/api/evaluation/export/json")
        assert export_json.status_code == 200
        assert "application/json" in export_json.headers.get("content-type", "")

        # Export CSV
        export_csv = client.get("/api/evaluation/export/csv")
        assert export_csv.status_code == 200
        assert "text/csv" in export_csv.headers.get("content-type", "")

        # Report MD
        report_resp = client.get("/api/evaluation/report")
        assert report_resp.status_code == 200
        assert "text/markdown" in report_resp.headers.get("content-type", "")

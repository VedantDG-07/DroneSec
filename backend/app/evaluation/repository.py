"""SQLite repository for evaluation runs and experiment records."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid
from typing import Any, Optional

from backend.app.evaluation.models import (
    EvaluationRunRecord,
    EvaluationRunStatus,
    ExperimentRecord,
    ExperimentStatus,
)
from backend.app.persistence.database import DatabaseManager


class EvaluationRepository:
    """Repository handling persistence, queries, and exports of benchmark evaluation data."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager

    def save_run(self, run: EvaluationRunRecord) -> EvaluationRunRecord:
        """Insert or update an evaluation run record."""
        metrics_json = json.dumps(run.metrics_summary) if run.metrics_summary else None
        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO evaluation_runs (
                        id, run_id, timestamp, status, total_experiments,
                        completed_experiments, metrics_summary, markdown_report
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id) DO UPDATE SET
                        status = excluded.status,
                        completed_experiments = excluded.completed_experiments,
                        metrics_summary = excluded.metrics_summary,
                        markdown_report = excluded.markdown_report;
                    """,
                    (
                        run.id,
                        run.run_id,
                        run.timestamp,
                        run.status.value,
                        run.total_experiments,
                        run.completed_experiments,
                        metrics_json,
                        run.markdown_report,
                    ),
                )
        finally:
            conn.close()
        return run

    async def save_run_async(self, run: EvaluationRunRecord) -> EvaluationRunRecord:
        return await asyncio.to_thread(self.save_run, run)

    def save_experiment(self, exp: ExperimentRecord) -> ExperimentRecord:
        """Insert an individual experiment record."""
        conn = self._db.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO evaluation_experiments (
                        id, run_id, experiment_id, timestamp, security_mode, scenario_type,
                        test_config, initial_state, final_state, attempts_count,
                        accepted_count, rejected_security_count, rejected_engine_count,
                        rate_limited_count, actual_defense_reason, state_mutated,
                        p50_latency_ms, p95_latency_ms, latencies, audit_event_ids,
                        result_status, result_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        exp.id,
                        exp.run_id,
                        exp.experiment_id,
                        exp.timestamp,
                        exp.security_mode,
                        exp.scenario_type,
                        json.dumps(exp.test_config),
                        json.dumps(exp.initial_state),
                        json.dumps(exp.final_state),
                        exp.attempts_count,
                        exp.accepted_count,
                        exp.rejected_security_count,
                        exp.rejected_engine_count,
                        exp.rate_limited_count,
                        exp.actual_defense_reason,
                        1 if exp.state_mutated else 0,
                        exp.p50_latency_ms,
                        exp.p95_latency_ms,
                        json.dumps(exp.latencies),
                        json.dumps(exp.audit_event_ids),
                        exp.result_status.value,
                        exp.result_reason,
                    ),
                )
        finally:
            conn.close()
        return exp

    async def save_experiment_async(self, exp: ExperimentRecord) -> ExperimentRecord:
        return await asyncio.to_thread(self.save_experiment, exp)

    def get_run(self, run_id: str) -> Optional[EvaluationRunRecord]:
        """Fetch a specific evaluation run by run_id."""
        conn = self._db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evaluation_runs WHERE run_id = ? LIMIT 1;", (run_id,))
            row = cursor.fetchone()
            cursor.close()
            if not row:
                return None
            return EvaluationRunRecord(
                id=row["id"],
                run_id=row["run_id"],
                timestamp=row["timestamp"],
                status=EvaluationRunStatus(row["status"]),
                total_experiments=row["total_experiments"],
                completed_experiments=row["completed_experiments"],
                metrics_summary=json.loads(row["metrics_summary"]) if row["metrics_summary"] else None,
                markdown_report=row["markdown_report"],
            )
        finally:
            conn.close()

    async def get_run_async(self, run_id: str) -> Optional[EvaluationRunRecord]:
        return await asyncio.to_thread(self.get_run, run_id)

    def get_latest_run(self) -> Optional[EvaluationRunRecord]:
        """Fetch the most recent evaluation run."""
        conn = self._db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evaluation_runs ORDER BY timestamp DESC LIMIT 1;")
            row = cursor.fetchone()
            cursor.close()
            if not row:
                return None
            return EvaluationRunRecord(
                id=row["id"],
                run_id=row["run_id"],
                timestamp=row["timestamp"],
                status=EvaluationRunStatus(row["status"]),
                total_experiments=row["total_experiments"],
                completed_experiments=row["completed_experiments"],
                metrics_summary=json.loads(row["metrics_summary"]) if row["metrics_summary"] else None,
                markdown_report=row["markdown_report"],
            )
        finally:
            conn.close()

    async def get_latest_run_async(self) -> Optional[EvaluationRunRecord]:
        return await asyncio.to_thread(self.get_latest_run)

    def list_runs(self, limit: int = 20, offset: int = 0) -> list[EvaluationRunRecord]:
        """List historical evaluation runs."""
        conn = self._db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM evaluation_runs ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [
                EvaluationRunRecord(
                    id=row["id"],
                    run_id=row["run_id"],
                    timestamp=row["timestamp"],
                    status=EvaluationRunStatus(row["status"]),
                    total_experiments=row["total_experiments"],
                    completed_experiments=row["completed_experiments"],
                    metrics_summary=json.loads(row["metrics_summary"]) if row["metrics_summary"] else None,
                    markdown_report=row["markdown_report"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    async def list_runs_async(self, limit: int = 20, offset: int = 0) -> list[EvaluationRunRecord]:
        return await asyncio.to_thread(self.list_runs, limit, offset)

    def get_experiments_for_run(self, run_id: str) -> list[ExperimentRecord]:
        """Fetch all individual experiment records belonging to a run."""
        conn = self._db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM evaluation_experiments WHERE run_id = ? ORDER BY timestamp ASC;",
                (run_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
            records: list[ExperimentRecord] = []
            for row in rows:
                records.append(
                    ExperimentRecord(
                        id=row["id"],
                        run_id=row["run_id"],
                        experiment_id=row["experiment_id"],
                        timestamp=row["timestamp"],
                        security_mode=row["security_mode"],
                        scenario_type=row["scenario_type"],
                        test_config=json.loads(row["test_config"]) if row["test_config"] else {},
                        initial_state=json.loads(row["initial_state"]) if row["initial_state"] else {},
                        final_state=json.loads(row["final_state"]) if row["final_state"] else {},
                        attempts_count=row["attempts_count"],
                        accepted_count=row["accepted_count"],
                        rejected_security_count=row["rejected_security_count"],
                        rejected_engine_count=row["rejected_engine_count"],
                        rate_limited_count=row["rate_limited_count"],
                        actual_defense_reason=row["actual_defense_reason"],
                        state_mutated=bool(row["state_mutated"]),
                        result_status=ExperimentStatus(row["result_status"]),
                        result_reason=row["result_reason"] or "",
                        latencies=json.loads(row["latencies"]) if row["latencies"] else [],
                        p50_latency_ms=row["p50_latency_ms"],
                        p95_latency_ms=row["p95_latency_ms"],
                        audit_event_ids=json.loads(row["audit_event_ids"]) if row["audit_event_ids"] else [],
                    )
                )
            return records
        finally:
            conn.close()

    async def get_experiments_for_run_async(self, run_id: str) -> list[ExperimentRecord]:
        return await asyncio.to_thread(self.get_experiments_for_run, run_id)

"""Data models, enums, and schemas for Phase 6 evaluation and benchmarking."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class ExperimentStatus(str, Enum):
    """Outcome classification of an individual evaluation experiment."""

    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"

    def __str__(self) -> str:
        return self.value


class EvaluationRunStatus(str, Enum):
    """Execution status of an overall evaluation run."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    def __str__(self) -> str:
        return self.value


class GateStatus(str, Enum):
    """Status of the pre-evaluation integration verification gate."""

    PASSED = "PASSED"
    FAILED = "FAILED"

    def __str__(self) -> str:
        return self.value


@dataclass
class VerificationCheck:
    """Individual verification check item outcome within the integration gate."""

    name: str
    description: str
    passed: bool
    details: dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationGateResult:
    """Aggregated outcome of the integration verification gate."""

    gate_status: GateStatus
    timestamp: float
    checks: list[VerificationCheck]
    summary: str
    passed_count: int
    failed_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_status": self.gate_status.value,
            "timestamp": self.timestamp,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class ExperimentRecord:
    """Persistent representation of an isolated evaluation experiment."""

    id: str
    run_id: str
    experiment_id: str
    timestamp: float
    security_mode: str
    scenario_type: str
    test_config: dict[str, Any]
    initial_state: dict[str, Any]
    final_state: dict[str, Any]
    attempts_count: int
    accepted_count: int
    rejected_security_count: int
    rejected_engine_count: int
    rate_limited_count: int
    actual_defense_reason: Optional[str]
    state_mutated: bool
    result_status: ExperimentStatus
    result_reason: str
    latencies: list[float] = field(default_factory=list)
    p50_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    audit_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["result_status"] = self.result_status.value
        return d


@dataclass
class ModeMetrics:
    """Quantitative evaluation metrics for a specific security operational mode."""

    security_mode: str
    total_experiments: int
    total_attack_attempts: int
    unauthorized_mutation_count: int
    unauthorized_mutation_rate: float
    attack_rejection_count: int
    attack_rejection_rate: float
    detection_count: int
    detection_rate: float
    replay_attempts_count: int
    replay_rejection_count: int
    replay_rejection_rate: float
    legitimate_commands_attempted: int
    legitimate_commands_succeeded: int
    legitimate_success_rate: float
    median_latency_ms: Optional[float]
    p95_latency_ms: Optional[float]
    rate_limit_activations: int
    inconclusive_count: int
    inconclusive_rate: float
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OverallBenchmarkMetrics:
    """Aggregated benchmark metrics across all evaluated operational modes."""

    run_id: str
    timestamp: float
    total_experiments: int
    mode_metrics: dict[str, ModeMetrics]
    overall_unauthorized_mutation_rate: float
    overall_attack_rejection_rate: float
    overall_legitimate_success_rate: float
    overall_median_latency_ms: Optional[float]
    overall_p95_latency_ms: Optional[float]
    overall_inconclusive_count: int
    verification_gate_passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "total_experiments": self.total_experiments,
            "mode_metrics": {k: v.to_dict() for k, v in self.mode_metrics.items()},
            "overall_unauthorized_mutation_rate": self.overall_unauthorized_mutation_rate,
            "overall_attack_rejection_rate": self.overall_attack_rejection_rate,
            "overall_legitimate_success_rate": self.overall_legitimate_success_rate,
            "overall_median_latency_ms": self.overall_median_latency_ms,
            "overall_p95_latency_ms": self.overall_p95_latency_ms,
            "overall_inconclusive_count": self.overall_inconclusive_count,
            "verification_gate_passed": self.verification_gate_passed,
        }


@dataclass
class EvaluationRunRecord:
    """Persistent representation of an entire evaluation execution session."""

    id: str
    run_id: str
    timestamp: float
    status: EvaluationRunStatus
    total_experiments: int
    completed_experiments: int
    metrics_summary: Optional[dict[str, Any]] = None
    markdown_report: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# Pydantic schemas for API requests and responses

class EvaluationVerifyResponse(BaseModel):
    """Schema for POST /api/evaluation/verify response."""

    gate_status: str
    timestamp: float
    passed_count: int
    failed_count: int
    summary: str
    checks: list[dict[str, Any]]


class EvaluationRunRequest(BaseModel):
    """Schema for POST /api/evaluation/run payload."""

    modes: Optional[list[str]] = Field(
        default=None,
        description="Optional subset of modes to evaluate: UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED",
    )
    iterations_per_scenario: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Number of attempts/iterations per attack scenario for sample stability.",
    )


class EvaluationLatestResponse(BaseModel):
    """Schema for GET /api/evaluation/latest response."""

    run: dict[str, Any]
    metrics: dict[str, Any]
    experiments: list[dict[str, Any]]

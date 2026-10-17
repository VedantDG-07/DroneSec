"""Phase 6: End-to-End Security Evaluation and Benchmarking System."""

from backend.app.evaluation.models import (
    ExperimentRecord,
    ExperimentStatus,
    EvaluationRunRecord,
    EvaluationRunStatus,
    GateStatus,
    ModeMetrics,
    OverallBenchmarkMetrics,
    VerificationCheck,
    VerificationGateResult,
)
from backend.app.evaluation.repository import EvaluationRepository
from backend.app.evaluation.metrics import EvaluationMetricsCalculator
from backend.app.evaluation.exporter import EvaluationExporter


def get_verification_gate():
    from backend.app.evaluation.verification_gate import VerificationGate
    return VerificationGate


def get_evaluation_runner():
    from backend.app.evaluation.runner import EvaluationRunner
    return EvaluationRunner


__all__ = [
    "ExperimentRecord",
    "ExperimentStatus",
    "EvaluationRunRecord",
    "EvaluationRunStatus",
    "GateStatus",
    "ModeMetrics",
    "OverallBenchmarkMetrics",
    "VerificationCheck",
    "VerificationGateResult",
    "EvaluationRepository",
    "EvaluationMetricsCalculator",
    "EvaluationExporter",
    "get_verification_gate",
    "get_evaluation_runner",
]

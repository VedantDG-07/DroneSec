"""Metrics calculation engine for Phase 6 security evaluation and benchmarking.

Formulas & Definitions:
1. Unauthorized State-Mutation Rate:
   Numerator: Count of attack attempts that caused unauthorized authoritative state mutation (state_mutated == True)
   Denominator: Total attack attempts evaluated
   Meaning: 0.0 in secured modes indicates strict invariant preservation; >0 in UNSECURED illustrates exploitability.

2. Attack Rejection Rate:
   Numerator: Count of attack attempts rejected by cryptographic or security pipeline defenses
   Denominator: Total attack attempts evaluated
   Meaning: Effectiveness of defensive controls in terminating adversarial payloads.

3. Detection Rate:
   Numerator: Count of attack scenarios where an explicit defensive security event or rejection reason was logged
   Denominator: Total attack scenarios evaluated
   Meaning: Observability and security audit coverage.

4. Replay Rejection Rate:
   Numerator: Count of replayed frames rejected by anti-replay sliding window or timestamp freshness
   Denominator: Total replayed frames submitted in replay attack scenarios
   Meaning: Anti-replay protection efficacy.

5. Legitimate-Command Success Rate:
   Numerator: Count of authorized, legitimate flight commands successfully executed
   Denominator: Total legitimate flight commands attempted
   Meaning: System availability and lack of false-positive command suppression.

6. Latency Metrics (p50 / p95):
   Percentiles computed over measured end-to-end command execution latencies (ms).

7. Rate-Limit Activation Counts:
   Total count of rate limiter triggers (HTTP 429 / RATE_LIMIT_EXCEEDED).

8. Inconclusive Rate:
   Numerator: Count of experiment runs classified as INCONCLUSIVE
   Denominator: Total experiment runs evaluated
"""

from __future__ import annotations

import math
from typing import Sequence
from backend.app.evaluation.models import (
    ExperimentRecord,
    ExperimentStatus,
    ModeMetrics,
    OverallBenchmarkMetrics,
)

MODE_NOTES = {
    "UNSECURED": (
        "Baseline comparison mode. Transmits raw unencrypted payloads without authentication, "
        "cryptographic signatures, or replay filters. Demonstrates clear vulnerability to injection, "
        "tampering, replay, and spoofing. NOT RECOMMENDED for production or operational deployment."
    ),
    "INTEGRITY_ONLY": (
        "Provides message integrity and sender authentication via HMAC-SHA-256 and Bearer tokens. "
        "Guarantees tampering detection and identity verification, but DOES NOT provide confidentiality "
        "(telemetry and command coordinates remain visible in transit)."
    ),
    "ENCRYPTED_AUTHENTICATED": (
        "Production-grade authenticated encryption using AES-256-GCM (AEAD) with HKDF key derivation, "
        "64-frame anti-replay sliding window, and Bearer authentication. Guarantees confidentiality, "
        "integrity, authenticity, and replay prevention."
    ),
}


def _safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide two numbers, avoiding ZeroDivisionError or NaN."""
    if denominator <= 0 or not math.isfinite(denominator) or not math.isfinite(numerator):
        return default
    return round(numerator / denominator, 4)


def _compute_percentile(sorted_values: list[float], percentile: float) -> float | None:
    """Compute percentile value (0.0 to 100.0) from a sorted float array."""
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return round(sorted_values[int(k)], 2)
    d0 = sorted_values[int(f)] * (c - k)
    d1 = sorted_values[int(c)] * (k - f)
    return round(d0 + d1, 2)


class EvaluationMetricsCalculator:
    """Computes rigorous, mathematically sound evaluation metrics from stored experiment records."""

    @staticmethod
    def compute_mode_metrics(
        security_mode: str,
        experiments: Sequence[ExperimentRecord],
    ) -> ModeMetrics:
        """Calculate metrics for a single security mode from its experiment records."""
        mode_exps = [e for e in experiments if e.security_mode == security_mode]
        total_experiments = len(mode_exps)

        # Separate attack scenarios from legitimate baseline commands
        attack_exps = [e for e in mode_exps if not e.scenario_type.startswith("LEGITIMATE_")]
        legit_exps = [e for e in mode_exps if e.scenario_type.startswith("LEGITIMATE_")]

        # Attack attempt counts
        total_attack_attempts = sum(e.attempts_count for e in attack_exps)
        
        # Unauthorized mutation count: attempts that resulted in unauthorized state mutation
        mutation_count = sum(e.attempts_count for e in attack_exps if e.state_mutated)
        unauthorized_mutation_rate = _safe_divide(mutation_count, total_attack_attempts, default=0.0)

        # Attack rejection counts: rejected by security defenses
        attack_rejection_count = sum(e.rejected_security_count for e in attack_exps)
        attack_rejection_rate = _safe_divide(attack_rejection_count, total_attack_attempts, default=0.0)

        # Detection rate: attack scenarios where a defense or security event was logged
        detection_count = sum(
            1 for e in attack_exps
            if e.actual_defense_reason or len(e.audit_event_ids) > 0
        )
        detection_rate = _safe_divide(detection_count, len(attack_exps), default=0.0)

        # Replay rejection rate (from ATK-03 replay attacks)
        replay_exps = [e for e in attack_exps if "REPLAY" in e.scenario_type.upper() or "ATK-03" in e.scenario_type.upper()]
        replay_attempts = sum(e.attempts_count for e in replay_exps)
        replay_rejections = sum(e.rejected_security_count for e in replay_exps)
        replay_rejection_rate = _safe_divide(replay_rejections, replay_attempts, default=0.0)

        # Legitimate command success rate
        legit_attempts = sum(e.attempts_count for e in legit_exps)
        legit_successes = sum(e.accepted_count for e in legit_exps)
        legit_success_rate = _safe_divide(legit_successes, legit_attempts, default=0.0)

        # Latencies aggregation across all experiments in this mode
        all_latencies: list[float] = []
        for e in mode_exps:
            all_latencies.extend(e.latencies)
        all_latencies.sort()

        p50 = _compute_percentile(all_latencies, 50.0)
        p95 = _compute_percentile(all_latencies, 95.0)

        # Rate limit triggers
        rate_limit_activations = sum(e.rate_limited_count for e in attack_exps)

        # Inconclusive runs
        inconclusive_count = sum(1 for e in mode_exps if e.result_status == ExperimentStatus.INCONCLUSIVE)
        inconclusive_rate = _safe_divide(inconclusive_count, total_experiments, default=0.0)

        notes = MODE_NOTES.get(security_mode, f"Custom security profile: {security_mode}")

        return ModeMetrics(
            security_mode=security_mode,
            total_experiments=total_experiments,
            total_attack_attempts=total_attack_attempts,
            unauthorized_mutation_count=mutation_count,
            unauthorized_mutation_rate=unauthorized_mutation_rate,
            attack_rejection_count=attack_rejection_count,
            attack_rejection_rate=attack_rejection_rate,
            detection_count=detection_count,
            detection_rate=detection_rate,
            replay_attempts_count=replay_attempts,
            replay_rejection_count=replay_rejections,
            replay_rejection_rate=replay_rejection_rate,
            legitimate_commands_attempted=legit_attempts,
            legitimate_commands_succeeded=legit_successes,
            legitimate_success_rate=legit_success_rate,
            median_latency_ms=p50,
            p95_latency_ms=p95,
            rate_limit_activations=rate_limit_activations,
            inconclusive_count=inconclusive_count,
            inconclusive_rate=inconclusive_rate,
            notes=notes,
        )

    @classmethod
    def compute_overall_metrics(
        cls,
        run_id: str,
        timestamp: float,
        experiments: Sequence[ExperimentRecord],
        verification_gate_passed: bool = True,
    ) -> OverallBenchmarkMetrics:
        """Calculate overall benchmark metrics across all evaluated modes."""
        modes = sorted(list({e.security_mode for e in experiments}))
        if not modes:
            modes = ["UNSECURED", "INTEGRITY_ONLY", "ENCRYPTED_AUTHENTICATED"]

        mode_metrics_dict: dict[str, ModeMetrics] = {}
        for m in modes:
            mode_metrics_dict[m] = cls.compute_mode_metrics(m, experiments)

        # Overall aggregate calculations
        total_experiments = len(experiments)
        all_attack_attempts = sum(m.total_attack_attempts for m in mode_metrics_dict.values())
        all_mutations = sum(m.unauthorized_mutation_count for m in mode_metrics_dict.values())
        all_rejections = sum(m.attack_rejection_count for m in mode_metrics_dict.values())
        all_legit_attempted = sum(m.legitimate_commands_attempted for m in mode_metrics_dict.values())
        all_legit_succeeded = sum(m.legitimate_commands_succeeded for m in mode_metrics_dict.values())
        all_inconclusive = sum(m.inconclusive_count for m in mode_metrics_dict.values())

        overall_mut_rate = _safe_divide(all_mutations, all_attack_attempts, default=0.0)
        overall_rej_rate = _safe_divide(all_rejections, all_attack_attempts, default=0.0)
        overall_legit_rate = _safe_divide(all_legit_succeeded, all_legit_attempted, default=0.0)

        all_latencies: list[float] = []
        for e in experiments:
            all_latencies.extend(e.latencies)
        all_latencies.sort()

        overall_p50 = _compute_percentile(all_latencies, 50.0)
        overall_p95 = _compute_percentile(all_latencies, 95.0)

        return OverallBenchmarkMetrics(
            run_id=run_id,
            timestamp=timestamp,
            total_experiments=total_experiments,
            mode_metrics=mode_metrics_dict,
            overall_unauthorized_mutation_rate=overall_mut_rate,
            overall_attack_rejection_rate=overall_rej_rate,
            overall_legitimate_success_rate=overall_legit_rate,
            overall_median_latency_ms=overall_p50,
            overall_p95_latency_ms=overall_p95,
            overall_inconclusive_count=all_inconclusive,
            verification_gate_passed=verification_gate_passed,
        )

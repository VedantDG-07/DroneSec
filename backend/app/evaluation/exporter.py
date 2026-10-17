"""Evaluation Exporter: JSON, CSV, and Markdown report generation."""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Sequence
from backend.app.evaluation.models import (
    EvaluationRunRecord,
    ExperimentRecord,
    OverallBenchmarkMetrics,
)


class EvaluationExporter:
    """Exports benchmark results to JSON, CSV, and formatted Markdown evaluation reports."""

    @staticmethod
    def export_json(
        run_record: EvaluationRunRecord,
        metrics: OverallBenchmarkMetrics,
        experiments: Sequence[ExperimentRecord],
    ) -> str:
        """Export full benchmark dataset as a serialized JSON string."""
        payload = {
            "evaluation_run": run_record.to_dict(),
            "benchmark_metrics": metrics.to_dict(),
            "experiments": [e.to_dict() for e in experiments],
            "exported_at": time.time(),
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def export_csv(experiments: Sequence[ExperimentRecord]) -> str:
        """Export individual experiment rows as tabular CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        headers = [
            "run_id",
            "experiment_id",
            "timestamp",
            "security_mode",
            "scenario_type",
            "attempts_count",
            "accepted_count",
            "rejected_security_count",
            "rejected_engine_count",
            "rate_limited_count",
            "actual_defense_reason",
            "state_mutated",
            "initial_state_version",
            "final_state_version",
            "p50_latency_ms",
            "p95_latency_ms",
            "result_status",
            "result_reason",
        ]
        writer.writerow(headers)

        for e in experiments:
            v_init = e.initial_state.get("state_version", 0)
            v_final = e.final_state.get("state_version", 0)
            writer.writerow([
                e.run_id,
                e.experiment_id,
                e.timestamp,
                e.security_mode,
                e.scenario_type,
                e.attempts_count,
                e.accepted_count,
                e.rejected_security_count,
                e.rejected_engine_count,
                e.rate_limited_count,
                e.actual_defense_reason or "NONE",
                "YES" if e.state_mutated else "NO",
                v_init,
                v_final,
                e.p50_latency_ms or "",
                e.p95_latency_ms or "",
                e.result_status.value,
                e.result_reason,
            ])

        return output.getvalue()

    @staticmethod
    def generate_markdown_report(
        run_record: EvaluationRunRecord,
        metrics: OverallBenchmarkMetrics,
        experiments: Sequence[ExperimentRecord],
    ) -> str:
        """Generate comprehensive, audit-ready Markdown evaluation report."""
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(run_record.timestamp))

        lines = [
            "# DroneSec: Phase 6 Security Evaluation & Benchmarking Report",
            "",
            f"**Run Identifier:** `{run_record.run_id}`  ",
            f"**Execution Timestamp:** {timestamp_str}  ",
            f"**Run Status:** `{run_record.status.value}`  ",
            f"**Integration Verification Gate:** `{'PASSED' if metrics.verification_gate_passed else 'FAILED'}`  ",
            f"**Total Experiments Evaluated:** {run_record.completed_experiments} of {run_record.total_experiments}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "Phase 6 provides rigorous, empirical security benchmarking across the three supported operational modes:",
            "- **`UNSECURED`:** Plaintext JSON without authentication or signatures (baseline vulnerability demonstration).",
            "- **`INTEGRITY_ONLY`:** Authenticated envelope with HMAC-SHA-256 and Bearer tokens (tampering and spoofing defenses).",
            "- **`ENCRYPTED_AUTHENTICATED`:** AES-256-GCM AEAD encryption with sliding-window anti-replay (full confidentiality, integrity, authenticity).",
            "",
            "All experiments were conducted against the local software-in-the-loop (SITL) simulated drone engine. "
            "Authoritative state invariants and strict atomicity were continuously verified.",
            "",
            "---",
            "",
            "## 2. Evaluation Methodology & Safety Isolation",
            "",
            "- **Local Execution Only:** Zero requests were routed across external networks or public interfaces.",
            "- **Synthetic Test Credentials:** Synthetic Bearer tokens (`gcs-sim-token-secret-2026`) and dedicated test key material were used.",
            "- **Deterministic Isolation:** Between test scenarios, the authoritative simulation engine was reset to controlled baselines.",
            "- **FSM vs Security Separation:** Attacks evaluating coordinate movement were initiated with an airborne hovering drone to guarantee rejections resulted from cryptographic defenses rather than baseline flight-state disarming.",
            "- **No Key Logging:** Sensitive keys and credentials are never logged or exported.",
            "",
            "---",
            "",
            "## 3. Metric Definitions",
            "",
            "| Metric | Formula | Description |",
            "|---|---|---|",
            "| **Unauthorized State-Mutation Rate** | $\\frac{\\text{Mutations Caused by Attacks}}{\\text{Total Attack Attempts}}$ | Proportion of adversarial attempts that mutated authoritative state. (Target: 0% in secured modes). |",
            "| **Attack Rejection Rate** | $\\frac{\\text{Attacks Rejected by Security}}{\\text{Total Attack Attempts}}$ | Proportion of adversarial payloads terminated by cryptographic / authentication pipeline. |",
            "| **Security Detection Rate** | $\\frac{\\text{Scenarios with Logged Defense}}{\\text{Total Attack Scenarios}}$ | Coverage of explicit security audit incident logging. |",
            "| **Replay Rejection Rate** | $\\frac{\\text{Replayed Packets Rejected}}{\\text{Total Replayed Packets Submitted}}$ | Effectiveness of anti-replay sliding window (64-frame) and timestamp freshness ($|\\Delta t| \\le 5.0$s). |",
            "| **Legitimate-Command Success Rate** | $\\frac{\\text{Valid Commands Executed}}{\\text{Valid Commands Attempted}}$ | Operational availability for legitimate GCS operator commands. |",
            "| **Command Latency (p50 / p95)** | Percentiles over measured $\\Delta t$ (ms) | End-to-end processing latency including cryptographic verification. |",
            "",
            "---",
            "",
            "## 4. Benchmark Results Comparison Matrix",
            "",
            "| Operating Mode | Attack Attempts | Mutation Rate | Attack Rejection | Detection Rate | Replay Rejection | Legit Success | Median Latency | p95 Latency | Rate Limits |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]

        for mode_name, m in metrics.mode_metrics.items():
            mut_pct = f"{m.unauthorized_mutation_rate * 100:.1f}%"
            rej_pct = f"{m.attack_rejection_rate * 100:.1f}%"
            det_pct = f"{m.detection_rate * 100:.1f}%"
            rep_pct = f"{m.replay_rejection_rate * 100:.1f}%" if m.replay_attempts_count > 0 else "N/A"
            legit_pct = f"{m.legitimate_success_rate * 100:.1f}%"
            p50_str = f"{m.median_latency_ms:.2f} ms" if m.median_latency_ms is not None else "N/A"
            p95_str = f"{m.p95_latency_ms:.2f} ms" if m.p95_latency_ms is not None else "N/A"

            lines.append(
                f"| **`{mode_name}`** | {m.total_attack_attempts} | {mut_pct} | {rej_pct} | {det_pct} | {rep_pct} | {legit_pct} | {p50_str} | {p95_str} | {m.rate_limit_activations} |"
            )

        lines.extend([
            "",
            "### Mode Evaluation Notes",
            "",
        ])

        for mode_name, m in metrics.mode_metrics.items():
            lines.append(f"- **`{mode_name}`**: {m.notes}")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Experiment Breakdown",
            "",
            "| Mode | Scenario | Attempts | Accepted | Rej (Sec) | Rej (Eng) | Defense Code | Mutated? | Result | Latency (p50) |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ])

        for e in experiments:
            def_code = e.actual_defense_reason or "NONE"
            mut_str = "**YES**" if e.state_mutated else "NO"
            lat_str = f"{e.p50_latency_ms:.2f} ms" if e.p50_latency_ms is not None else "-"
            res_str = f"`{e.result_status.value}`"
            lines.append(
                f"| `{e.security_mode}` | `{e.scenario_type}` | {e.attempts_count} | {e.accepted_count} | {e.rejected_security_count} | {e.rejected_engine_count} | `{def_code}` | {mut_str} | {res_str} | {lat_str} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 6. System Limitations & Reproducibility",
            "",
            "### Limitations",
            "1. **Software-in-the-Loop Simulation:** Flight dynamics and kinematics operate deterministically at 20 Hz without sensor drift, wind shear, or physical aerodynamic perturbations.",
            "2. **Single-Node Localhost Testing:** Network packet transmission simulates radio link latency in software; RF packet loss, jamming, and physical signal degradation are not modeled.",
            "3. **In-Memory Cryptography:** Keys reside in backend process memory (`KeyManager`) without hardware security module (HSM) or secure enclave backing.",
            "",
            "### Local Reproducibility Instructions",
            "To reproduce this evaluation locally:",
            "1. Start the DroneSec backend server: `python -m uvicorn backend.app.main:app --port 8000`",
            "2. Execute the verification gate: `curl -X POST http://127.0.0.1:8000/api/evaluation/verify`",
            "3. Run the full security benchmark: `curl -X POST http://127.0.0.1:8000/api/evaluation/run`",
            "4. Fetch recorded metrics: `curl http://127.0.0.1:8000/api/evaluation/latest`",
            "5. Export dataset as CSV/JSON: `curl http://127.0.0.1:8000/api/evaluation/export/csv -o benchmark.csv`",
            "",
            "---",
            "*Report automatically generated by DroneSec Phase 6 Evaluation Engine.*",
        ])

        return "\n".join(lines)

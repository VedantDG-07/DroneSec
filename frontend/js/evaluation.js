/**
 * DroneSec Security Evaluation & Benchmarking Dashboard (Phase 6)
 *
 * Coordinates:
 * - Integration Verification Gate execution (POST /api/evaluation/verify)
 * - Security Benchmark Orchestration (POST /api/evaluation/run)
 * - Quantitative Metrics & Mode Comparison (GET /api/evaluation/latest)
 * - JSON, CSV, and Markdown Export (GET /api/evaluation/export/*)
 */

export class EvaluationDashboard {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.isRunning = false;
    this.latestData = null;
    this.onToastCallbacks = [];

    this.bindDomEvents();
    this.fetchLatestEvaluation();
  }

  onToast(callback) {
    this.onToastCallbacks.push(callback);
  }

  notifyToast(msg, type = 'info') {
    this.onToastCallbacks.forEach((cb) => cb(msg, type));
  }

  bindDomEvents() {
    // Top-bar Evaluation Button
    const btnOpenEval = document.getElementById('btn-open-evaluation');
    if (btnOpenEval) {
      btnOpenEval.addEventListener('click', () => this.openModal());
    }

    // Modal Close
    const btnClose = document.getElementById('btn-close-eval-modal');
    if (btnClose) {
      btnClose.addEventListener('click', () => this.closeModal());
    }

    const modalOverlay = document.getElementById('modal-evaluation-dashboard');
    if (modalOverlay) {
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) this.closeModal();
      });
    }

    // Run Integration Gate Button
    const btnRunGate = document.getElementById('btn-run-gate');
    if (btnRunGate) {
      btnRunGate.addEventListener('click', () => this.runVerificationGate());
    }

    // Run Benchmark Button
    const btnRunBenchmark = document.getElementById('btn-run-benchmark');
    if (btnRunBenchmark) {
      btnRunBenchmark.addEventListener('click', () => this.runBenchmark());
    }

    // Export Buttons
    const btnExportJson = document.getElementById('btn-eval-export-json');
    if (btnExportJson) {
      btnExportJson.addEventListener('click', () => this.exportJson());
    }

    const btnExportCsv = document.getElementById('btn-eval-export-csv');
    if (btnExportCsv) {
      btnExportCsv.addEventListener('click', () => this.exportCsv());
    }

    const btnViewReport = document.getElementById('btn-eval-view-report');
    if (btnViewReport) {
      btnViewReport.addEventListener('click', () => this.viewMarkdownReport());
    }
  }

  openModal() {
    const modalEl = document.getElementById('modal-evaluation-dashboard');
    if (modalEl) {
      modalEl.classList.add('active');
      this.fetchLatestEvaluation();
    }
  }

  closeModal() {
    const modalEl = document.getElementById('modal-evaluation-dashboard');
    if (modalEl) {
      modalEl.classList.remove('active');
    }
  }

  async fetchLatestEvaluation() {
    try {
      const resp = await fetch(`${this.apiBase}/api/evaluation/latest`);
      if (!resp.ok) return;

      const body = await resp.json();
      if (body.status === 'success' && body.data) {
        this.latestData = body.data;
        this.renderEvaluation(body.data);
      }
    } catch (err) {
      console.warn('[Evaluation] Failed to fetch latest evaluation:', err);
    }
  }

  async runVerificationGate() {
    const btnGate = document.getElementById('btn-run-gate');
    if (btnGate) {
      btnGate.disabled = true;
      btnGate.textContent = 'VERIFYING INVARIANTS...';
    }
    this.notifyToast('Executing Integration Verification Gate...', 'warning');

    try {
      const resp = await fetch(`${this.apiBase}/api/evaluation/verify`, {
        method: 'POST',
      });
      const body = await resp.json();

      if (resp.ok && body.status === 'success') {
        const d = body.data;
        const passed = d.gate_status === 'PASSED';
        const type = passed ? 'success' : 'error';
        this.notifyToast(`Integration Gate ${d.gate_status}: ${d.passed_count}/${d.passed_count + d.failed_count} checks passed.`, type);
        this.renderGateResults(d);
      } else {
        const err = body.error || {};
        this.notifyToast(`Gate execution error: ${err.message || 'Error'}`, 'error');
      }
    } catch (netErr) {
      this.notifyToast(`Network Error: ${netErr.message}`, 'error');
    } finally {
      if (btnGate) {
        btnGate.disabled = false;
        btnGate.textContent = 'RUN VERIFICATION GATE';
      }
    }
  }

  async runBenchmark() {
    if (this.isRunning) return;

    this.isRunning = true;
    const btnBench = document.getElementById('btn-run-benchmark');
    const progressEl = document.getElementById('eval-progress-bar');
    const statusTextEl = document.getElementById('eval-run-status');

    if (btnBench) {
      btnBench.disabled = true;
      btnBench.textContent = 'EVALUATING SYSTEM...';
    }
    if (progressEl) progressEl.style.width = '30%';
    if (statusTextEl) statusTextEl.textContent = 'Executing benchmark across all security modes...';

    this.notifyToast('Running empirical security benchmark across UNSECURED, INTEGRITY_ONLY, ENCRYPTED_AUTHENTICATED...', 'warning');

    try {
      const resp = await fetch(`${this.apiBase}/api/evaluation/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iterations_per_scenario: 3 }),
      });

      const body = await resp.json();
      if (progressEl) progressEl.style.width = '100%';

      if (resp.ok && body.status === 'success') {
        this.notifyToast('Phase 6 Benchmark completed successfully!', 'success');
        if (statusTextEl) statusTextEl.textContent = 'Benchmark completed.';
        await this.fetchLatestEvaluation();
      } else {
        const err = body.error || {};
        this.notifyToast(`Benchmark failed: ${err.message || 'Unknown error'}`, 'error');
        if (statusTextEl) statusTextEl.textContent = 'Benchmark failed.';
      }
    } catch (netErr) {
      this.notifyToast(`Network error: ${netErr.message}`, 'error');
      if (statusTextEl) statusTextEl.textContent = 'Network error during benchmark.';
    } finally {
      this.isRunning = false;
      if (btnBench) {
        btnBench.disabled = false;
        btnBench.textContent = 'RUN FULL SECURITY BENCHMARK';
      }
      setTimeout(() => {
        if (progressEl && !this.isRunning) progressEl.style.width = '0%';
      }, 2000);
    }
  }

  renderGateResults(gateData) {
    const statusBadge = document.getElementById('eval-gate-badge');
    const checksList = document.getElementById('eval-gate-checks-list');

    if (statusBadge) {
      const passed = gateData.gate_status === 'PASSED';
      statusBadge.textContent = gateData.gate_status;
      statusBadge.className = `status-pill ${passed ? 'mode-encrypted_authenticated' : 'mode-unsecured'}`;
      statusBadge.style.padding = '4px 8px';
    }

    if (checksList && Array.isArray(gateData.checks)) {
      checksList.innerHTML = gateData.checks.map((c) => {
        const passIcon = c.passed
          ? `<span style="color: var(--emerald); font-weight: 700;">&#10003; PASS</span>`
          : `<span style="color: var(--crimson); font-weight: 700;">&#10007; FAIL</span>`;
        return `
          <div class="invariant-metric-row" style="padding: 4px 0;">
            <span style="font-weight: 600;">${c.name}</span>
            <span>${passIcon}</span>
          </div>
        `;
      }).join('');
    }
  }

  renderEvaluation(data) {
    const { run, metrics, experiments } = data;
    if (!run || !metrics) return;

    // Gate Status Pill
    const gateBadge = document.getElementById('eval-gate-badge');
    if (gateBadge) {
      const passed = metrics.verification_gate_passed;
      gateBadge.textContent = passed ? 'GATE PASSED' : 'GATE FAILED';
      gateBadge.className = `status-pill ${passed ? 'mode-encrypted_authenticated' : 'mode-unsecured'}`;
      gateBadge.style.padding = '4px 8px';
    }

    // Top Metric Cards
    const elMutRate = document.getElementById('metric-eval-mut-rate');
    const elRejRate = document.getElementById('metric-eval-rej-rate');
    const elLegitRate = document.getElementById('metric-eval-legit-rate');
    const elLatency = document.getElementById('metric-eval-latency');
    const elReplayRate = document.getElementById('metric-eval-replay-rate');
    const elTotalExps = document.getElementById('metric-eval-total-exps');

    if (elMutRate) {
      const rate = (metrics.overall_unauthorized_mutation_rate * 100).toFixed(1);
      elMutRate.textContent = `${rate}%`;
    }
    if (elRejRate) {
      const rate = (metrics.overall_attack_rejection_rate * 100).toFixed(1);
      elRejRate.textContent = `${rate}%`;
    }
    if (elLegitRate) {
      const rate = (metrics.overall_legitimate_success_rate * 100).toFixed(1);
      elLegitRate.textContent = `${rate}%`;
    }
    if (elLatency) {
      const p50 = metrics.overall_median_latency_ms !== null ? `${metrics.overall_median_latency_ms} ms` : '--';
      const p95 = metrics.overall_p95_latency_ms !== null ? `${metrics.overall_p95_latency_ms} ms` : '--';
      elLatency.textContent = `${p50} / ${p95}`;
    }
    if (elTotalExps) {
      elTotalExps.textContent = `${experiments ? experiments.length : 0}`;
    }

    // Render Mode Comparison Table
    const tableBody = document.getElementById('eval-matrix-table-body');
    if (tableBody && metrics.mode_metrics) {
      tableBody.innerHTML = Object.entries(metrics.mode_metrics).map(([modeName, m]) => {
        const mutPct = (m.unauthorized_mutation_rate * 100).toFixed(1);
        const rejPct = (m.attack_rejection_rate * 100).toFixed(1);
        const legitPct = (m.legitimate_success_rate * 100).toFixed(1);
        const repPct = m.replay_attempts_count > 0 ? `${(m.replay_rejection_rate * 100).toFixed(1)}%` : 'N/A';
        const p50 = m.median_latency_ms !== null ? `${m.median_latency_ms} ms` : '--';
        const p95 = m.p95_latency_ms !== null ? `${m.p95_latency_ms} ms` : '--';

        const mutColor = m.unauthorized_mutation_rate > 0 ? 'var(--crimson)' : 'var(--emerald)';

        return `
          <tr>
            <td><span class="status-pill mode-${modeName.toLowerCase()}" style="padding: 2px 6px; font-size: 10px;">${modeName}</span></td>
            <td>${m.total_attack_attempts}</td>
            <td style="color: ${mutColor}; font-weight: 700;">${mutPct}%</td>
            <td style="color: var(--cyber-cyan); font-weight: 700;">${rejPct}%</td>
            <td>${repPct}</td>
            <td style="color: var(--emerald); font-weight: 700;">${legitPct}%</td>
            <td style="font-family: var(--font-mono);">${p50}</td>
            <td style="font-family: var(--font-mono);">${p95}</td>
            <td>${m.rate_limit_activations}</td>
          </tr>
        `;
      }).join('');
    }

    // Render Experiments List Table
    const expTableBody = document.getElementById('eval-experiments-table-body');
    if (expTableBody && Array.isArray(experiments)) {
      expTableBody.innerHTML = experiments.map((e) => {
        const passPill = e.result_status === 'PASS'
          ? `<span class="result-status-badge result-BLOCKED_BY_DEFENSE" style="padding: 2px 6px; font-size: 9px;">PASS</span>`
          : `<span class="result-status-badge result-SUCCESSFUL_EXPLOIT" style="padding: 2px 6px; font-size: 9px;">${e.result_status}</span>`;

        const mutPill = e.state_mutated
          ? `<span style="color: var(--crimson); font-weight: 700;">MUTATED</span>`
          : `<span style="color: var(--emerald); font-weight: 700;">PRESERVED</span>`;

        const p50 = e.p50_latency_ms !== null ? `${e.p50_latency_ms} ms` : '--';

        return `
          <tr>
            <td><span class="status-pill mode-${e.security_mode.toLowerCase()}" style="padding: 2px 5px; font-size: 9px;">${e.security_mode}</span></td>
            <td style="font-weight: 600;">${e.scenario_type}</td>
            <td>${e.attempts_count}</td>
            <td>${e.accepted_count}</td>
            <td>${e.rejected_security_count}</td>
            <td style="font-family: var(--font-mono); font-size: 10px;">${e.actual_defense_reason || 'NONE'}</td>
            <td>${mutPill}</td>
            <td style="font-family: var(--font-mono); font-size: 10px;">${p50}</td>
            <td>${passPill}</td>
          </tr>
        `;
      }).join('');
    }
  }

  exportJson() {
    window.open(`${this.apiBase}/api/evaluation/export/json`, '_blank');
  }

  exportCsv() {
    window.open(`${this.apiBase}/api/evaluation/export/csv`, '_blank');
  }

  viewMarkdownReport() {
    window.open(`${this.apiBase}/api/evaluation/report`, '_blank');
  }
}

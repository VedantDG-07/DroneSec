/**
 * DroneSec Cyberattack Simulation Console
 *
 * Dispatches controlled local cyberattacks via:
 *   POST /api/attacks/{attack_type}
 *   GET  /api/attacks/history
 *
 * Implements scenarios:
 * - ATK-01: unauthorized_command
 * - ATK-02: message_tampering
 * - ATK-03: replay_attack
 * - ATK-04: spoofed_identity
 * - ATK-05: malformed_payload
 * - ATK-06: command_flood
 *
 * Renders real-time execution status and mathematical invariant verification results.
 */

export class AttackConsole {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.selectedScenario = 'unauthorized_command';
    this.isExecuting = false;

    this.onAttackCompleteCallbacks = [];
    this.onToastCallbacks = [];

    this.scenarioDefinitions = {
      unauthorized_command: {
        id: 'ATK-01',
        title: 'Unauthorized Command Injection',
        desc: 'Injects flight commands without valid cryptographic Bearer credentials.',
        defaultCommand: 'ARM',
        fields: ['target_command'],
      },
      message_tampering: {
        id: 'ATK-02',
        title: 'Message Tampering & Bit-Flipping',
        desc: 'Alters in-flight payload ciphertext or corrupts HMAC authentication tags.',
        defaultCommand: 'MOVE_FORWARD',
        fields: ['target_command', 'tamper_delta'],
      },
      replay_attack: {
        id: 'ATK-03',
        title: 'Command Replay Attack',
        desc: 'Captures a legitimate sequence packet and replays it at a later timestamp.',
        defaultCommand: 'MOVE_FORWARD',
        fields: ['target_command'],
      },
      spoofed_identity: {
        id: 'ATK-04',
        title: 'Sender Spoofing & Counterfeit Identity',
        desc: 'Emits commands claiming to be authorized GCS operator with mismatched keys.',
        defaultCommand: 'ARM',
        fields: ['target_command'],
      },
      malformed_payload: {
        id: 'ATK-05',
        title: 'Malformed Payload & Fuzzing Injection',
        desc: 'Submits out-of-range coordinates, corrupted types, and invalid command codes.',
        defaultCommand: 'DO_BARREL_ROLL',
        fields: [],
      },
      command_flood: {
        id: 'ATK-06',
        title: 'Bounded Message Flooding (DoS)',
        desc: 'Emits a high-frequency command burst exceeding token-bucket capacity.',
        defaultCommand: 'ARM',
        fields: ['flood_count'],
      },
    };

    this.bindDomEvents();
    this.renderFormForScenario(this.selectedScenario);
  }

  bindDomEvents() {
    // Attack scenario card selection
    document.querySelectorAll('.attack-card').forEach((card) => {
      card.addEventListener('click', (e) => {
        document.querySelectorAll('.attack-card').forEach((c) => c.classList.remove('selected'));
        const el = e.currentTarget;
        el.classList.add('selected');
        this.selectedScenario = el.dataset.scenario;
        this.renderFormForScenario(this.selectedScenario);
      });
    });

    // Launch Attack Button
    const btnLaunch = document.getElementById('btn-launch-attack');
    const btnCancel = document.getElementById('btn-cancel-attack');
    if (btnCancel) {
      btnCancel.addEventListener('click', async () => {
        try {
          const res = await fetch(`${this.apiBase}/api/attacks/cancel`, {
            method: 'POST',
            headers: { 'Authorization': 'Bearer gcs-sim-token-secret-2026' },
          });
          const d = await res.json();
          this.notifyToast(d.data?.message || 'Attack cancellation signaled.', 'info');
        } catch (e) {
          this.notifyToast('Failed to cancel attack: ' + e.message, 'error');
        }
      });
    }
    if (btnLaunch) {
      btnLaunch.addEventListener('click', () => this.launchAttack());
    }

    // View History Button
    const btnHistory = document.getElementById('btn-attack-history');
    if (btnHistory) {
      btnHistory.addEventListener('click', () => this.openHistoryModal());
    }

    // Close Modal Button
    const btnCloseModal = document.getElementById('btn-close-modal');
    if (btnCloseModal) {
      btnCloseModal.addEventListener('click', () => this.closeHistoryModal());
    }

    const modalOverlay = document.getElementById('modal-attack-history');
    if (modalOverlay) {
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) this.closeHistoryModal();
      });
    }
  }

  renderFormForScenario(scenarioKey) {
    const sc = this.scenarioDefinitions[scenarioKey];
    if (!sc) return;

    const formEl = document.getElementById('attack-form-fields');
    if (!formEl) return;

    let html = '';

    if (sc.fields.includes('target_command')) {
      html += `
        <div class="form-group">
          <label class="form-label">Target Drone Command</label>
          <select id="param-target-command" class="form-select">
            <option value="MOVE_FORWARD" ${sc.defaultCommand === 'MOVE_FORWARD' ? 'selected' : ''}>MOVE_FORWARD</option>
            <option value="ARM" ${sc.defaultCommand === 'ARM' ? 'selected' : ''}>ARM</option>
            <option value="TAKEOFF">TAKEOFF</option>
            <option value="MOVE_UP">MOVE_UP</option>
            <option value="MOVE_DOWN">MOVE_DOWN</option>
            <option value="MOVE_BACKWARD">MOVE_BACKWARD</option>
            <option value="MOVE_LEFT">MOVE_LEFT</option>
            <option value="MOVE_RIGHT">MOVE_RIGHT</option>
            <option value="LAND">LAND</option>
          </select>
        </div>
      `;
    }

    if (sc.fields.includes('tamper_delta')) {
      html += `
        <div class="form-group">
          <label class="form-label">Tamper Coordinate Delta (m)</label>
          <input type="number" id="param-tamper-delta" class="form-input" value="500.0" step="50" min="10" max="10000" />
        </div>
      `;
    }

    if (sc.fields.includes('flood_count')) {
      html += `
        <div class="form-group">
          <label class="form-label">Burst Request Count (10 - 50)</label>
          <input type="number" id="param-flood-count" class="form-input" value="40" step="5" min="10" max="50" />
        </div>
      `;
    }

    if (sc.fields.length === 0) {
      html = `<div style="color: var(--text-dim); font-size: 11px;">Standard automated fuzzing test suite will execute against parser.</div>`;
    }

    formEl.innerHTML = html;
  }

  collectParameters() {
    const params = {};
    const cmdEl = document.getElementById('param-target-command');
    const deltaEl = document.getElementById('param-tamper-delta');
    const floodEl = document.getElementById('param-flood-count');

    if (cmdEl) params.target_command = cmdEl.value;
    if (deltaEl) params.tamper_coordinate_delta = parseFloat(deltaEl.value) || 500.0;
    if (floodEl) params.flood_count = parseInt(floodEl.value, 10) || 40;

    return params;
  }

  async launchAttack() {
    if (this.isExecuting) return;

    this.isExecuting = true;
    const btnLaunch = document.getElementById('btn-launch-attack');
    const btnCancel = document.getElementById('btn-cancel-attack');
    if (btnCancel) {
      btnCancel.addEventListener('click', async () => {
        try {
          const res = await fetch(`${this.apiBase}/api/attacks/cancel`, {
            method: 'POST',
            headers: { 'Authorization': 'Bearer gcs-sim-token-secret-2026' },
          });
          const d = await res.json();
          this.notifyToast(d.data?.message || 'Attack cancellation signaled.', 'info');
        } catch (e) {
          this.notifyToast('Failed to cancel attack: ' + e.message, 'error');
        }
      });
    }
    if (btnLaunch) {
      btnLaunch.disabled = true;
      btnLaunch.textContent = 'EXECUTING SCENARIO...';
    }

    const scenarioKey = this.selectedScenario;
    const parameters = this.collectParameters();
    const sc = this.scenarioDefinitions[scenarioKey];

    this.notifyToast(`Launching attack scenario [${sc ? sc.id : scenarioKey}]...`, 'warning');

    try {
      const resp = await fetch(`${this.apiBase}/api/attacks/${scenarioKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ parameters }),
      });

      const body = await resp.json();

      // Backend envelope uses { status: "success"|"error", data/error: ... }
      if (resp.ok && body.status === 'success') {
        this.renderAttackResult(body.data);
        this.notifyAttackComplete(body.data);

        const status = body.data.attack_result;
        if (status === 'SUCCESSFUL_EXPLOIT') {
          this.notifyToast(`ALERT: [${body.data.attack_type}] successfully exploited target!`, 'error');
        } else {
          this.notifyToast(`Defense active: [${body.data.attack_type}] blocked (${body.data.defense_triggered || 'Blocked'}).`, 'success');
        }
      } else {
        const err = body.error || {};
        const codePrefix = err.code ? `[${err.code}] ` : '';
        this.notifyToast(`Attack execution rejected: ${codePrefix}${err.message || 'Unknown error'}`, 'error');
      }
    } catch (netErr) {
      this.notifyToast(`Network Error: ${netErr.message}`, 'error');
    } finally {
      this.isExecuting = false;
      if (btnLaunch) {
        btnLaunch.disabled = false;
        btnLaunch.textContent = 'LAUNCH ATTACK';
      }
    }
  }

  renderAttackResult(data) {
    const cardEl = document.getElementById('attack-result-display');
    if (!cardEl) return;

    cardEl.style.display = 'block';

    const drift = data.coordinates_drift || { delta_x: 0, delta_y: 0, delta_z: 0 };
    const driftNorm = Math.sqrt(drift.delta_x ** 2 + drift.delta_y ** 2 + drift.delta_z ** 2).toFixed(3);

    const isCompromised = data.state_compromised;
    const statusClass = `result-${data.attack_result}`;

    cardEl.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span class="result-status-badge ${statusClass}">${data.attack_result}</span>
        <span style="font-family: var(--font-mono); font-size: 10px; color: var(--text-dim);">${data.execution_duration_ms} ms</span>
      </div>
      <div class="invariant-metric-row">
        <span style="color: var(--text-dim);">Defense Triggered:</span>
        <span style="font-family: var(--font-mono); font-weight: 700; color: ${data.defense_triggered ? 'var(--emerald)' : 'var(--text-muted)'};">
          ${data.defense_triggered || 'None (Exploited)'}
        </span>
      </div>
      <div class="invariant-metric-row">
        <span style="color: var(--text-dim);">State Compromised:</span>
        <span style="font-family: var(--font-mono); font-weight: 700; color: ${isCompromised ? 'var(--crimson)' : 'var(--emerald)'};">
          ${isCompromised ? 'TRUE (MUTATED)' : 'FALSE (PRESERVED)'}
        </span>
      </div>
      <div class="invariant-metric-row">
        <span style="color: var(--text-dim);">State Version Invariant:</span>
        <span style="font-family: var(--font-mono);">${data.initial_state_version} &rarr; ${data.final_state_version}</span>
      </div>
      <div class="invariant-metric-row">
        <span style="color: var(--text-dim);">&Delta; Position Drift:</span>
        <span style="font-family: var(--font-mono); color: ${driftNorm > 0 ? 'var(--crimson)' : 'var(--emerald)'};">
          ||&Delta;p|| = ${driftNorm} m
        </span>
      </div>
    `;
  }

  async openHistoryModal() {
    const modalEl = document.getElementById('modal-attack-history');
    const tableBody = document.getElementById('history-table-body');
    if (!modalEl || !tableBody) return;

    modalEl.classList.add('active');
    tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">Loading audit history...</td></tr>`;

    try {
      const resp = await fetch(`${this.apiBase}/api/attacks/history?limit=25`);
      const body = await resp.json();

      if (resp.ok && (body.status === 'success' || body.success) && Array.isArray(body.data)) {
        if (body.data.length === 0) {
          tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No attack runs recorded yet.</td></tr>`;
          return;
        }

        tableBody.innerHTML = body.data
          .map((item) => {
            const timeStr = new Date(item.timestamp * 1000).toLocaleTimeString();
            const compromisedBadge = item.state_compromised
              ? `<span style="color: var(--crimson); font-weight: 700;">YES</span>`
              : `<span style="color: var(--emerald); font-weight: 700;">NO</span>`;

            return `
              <tr>
                <td style="color: var(--text-dim);">${timeStr}</td>
                <td style="font-weight: 700;">${item.attack_type}</td>
                <td><span class="status-pill mode-${(item.security_mode_active || '').toLowerCase()}" style="padding: 2px 6px; font-size: 9px;">${item.security_mode_active}</span></td>
                <td><span class="result-status-badge result-${item.attack_result}" style="padding: 2px 6px; font-size: 9px;">${item.attack_result}</span></td>
                <td>${item.defense_triggered || '-'}</td>
                <td>${compromisedBadge}</td>
              </tr>
            `;
          })
          .join('');
      } else {
        tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--crimson);">Failed to load history.</td></tr>`;
      }
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--crimson);">Network error loading history.</td></tr>`;
    }
  }

  closeHistoryModal() {
    const modalEl = document.getElementById('modal-attack-history');
    if (modalEl) modalEl.classList.remove('active');
  }

  onAttackComplete(callback) {
    this.onAttackCompleteCallbacks.push(callback);
  }

  onToast(callback) {
    this.onToastCallbacks.push(callback);
  }

  notifyAttackComplete(data) {
    this.onAttackCompleteCallbacks.forEach((cb) => cb(data));
  }

  notifyToast(msg, type = 'info') {
    this.onToastCallbacks.forEach((cb) => cb(msg, type));
  }
}

/**
 * DroneSec Communication Lab - C2 Message Pipeline Controller
 *
 * Implements:
 * - Visual block diagram pipeline with Attach/Detach controls
 * - Stage-flash animation when a real message travels through the pipeline
 * - Block-click detail panel showing security function, real input/output data
 * - Real backend synchronization via GET /api/security/status & POST /api/security/component
 * - Interactive Message Transformation Inspector (5-stage real message flow)
 * - Wireshark practical lab packet generation and capture reference
 */

// Block metadata for the detail panel
const BLOCK_DEFS = {
  gcs: {
    title: 'Ground Control Station (Origin)',
    zone: 'SENDER SIDE',
    icon: 'ðŸ–¥',
    security: 'None â€” command originates here as plaintext JSON.',
    input: 'Operator action (button press / keyboard shortcut / API call)',
    output: 'JSON command object: { command, parameters, sender_id, sequence_number, timestamp }',
    consequence: null,
    stageKey: 1,
  },
  sender_auth: {
    title: 'Sender Authentication',
    zone: 'SENDER SIDE',
    icon: 'ðŸ›¡',
    security: 'Bearer token credential attached to every HTTP request (Authorization header). Receiver validates token & authorized sender_id.',
    input: 'Plaintext command JSON',
    output: 'Same command JSON + Authorization: Bearer <token> header',
    consequence: 'If DETACHED: bearer header omitted. Any process on the network can inject commands without credentials.',
    stageKey: 2,
  },
  encryption: {
    title: 'AES-256-GCM Authenticated Encryption',
    zone: 'SENDER SIDE',
    icon: 'ðŸ”’',
    security: 'AEAD cipher: 12-byte random IV, 256-bit key, 16-byte authentication tag. Provides confidentiality (eavesdropper cannot read payload) and integrity (any bit-flip invalidates the tag).',
    input: 'Plaintext command JSON',
    output: '{ iv, ciphertext, auth_tag, key_id, sender_id, sequence_number } â€” opaque to passive observer',
    consequence: 'If DETACHED: full JSON command transmitted in cleartext. Capture with Wireshark â†’ Follow TCP Stream.',
    stageKey: 2,
  },
  tcp: {
    title: 'TCP Network Transport',
    zone: 'NETWORK',
    icon: 'ðŸŒ',
    security: 'TCP provides reliable ordered byte stream. No application-layer security here â€” confidentiality comes from the encryption block above.',
    input: 'HTTP/1.1 POST /api/drone/command with body',
    output: 'TCP segments carrying HTTP frames over loopback socket 127.0.0.1:8000',
    consequence: null,
    stageKey: 3,
  },
  rate_limiting: {
    title: 'Token-Bucket Rate Limiter',
    zone: 'RECEIVER SIDE',
    icon: 'â±',
    security: 'Token bucket with burst capacity 10 and refill 5 req/s. Rejects excess commands with HTTP 429. Prevents link exhaustion and CPU starvation from command floods.',
    input: 'Incoming HTTP request',
    output: '200 (pass) or 429 Too Many Requests (throttle)',
    consequence: 'If DETACHED: rate limiter bypassed. ATK-06 DoS burst will pass all requests through.',
    stageKey: 4,
  },
  anti_replay: {
    title: 'Anti-Replay Filter',
    zone: 'RECEIVER SIDE',
    icon: 'ðŸ”„',
    security: '64-bit sliding sequence window + 5.0 s timestamp freshness check. Rejects packets with a previously-seen sequence number or stale timestamp (HTTP 403).',
    input: 'Verified command envelope with sequence_number & timestamp',
    output: '200 (fresh & unique) or 403 Replay Attack Detected',
    consequence: 'If DETACHED: replayed packets accepted. ATK-03 can re-execute captured maneuvers.',
    stageKey: 4,
  },
  receiver_auth: {
    title: 'Receiver Verification Gate',
    zone: 'RECEIVER SIDE',
    icon: 'âœ…',
    security: 'Validates key_id, decrypts/verifies AEAD tag (or HMAC-SHA256 in integrity-only mode), enforces Pydantic schema constraints. Fail-closed: any mismatch â†’ rejection.',
    input: 'Encrypted or signed envelope',
    output: 'Decrypted & authorized plaintext command sent to Drone Engine, or rejection error',
    consequence: 'If DETACHED: cryptographic verification relaxed â€” unverified directives may reach the engine.',
    stageKey: 4,
  },
  drone: {
    title: 'Drone Engine (Flight FSM)',
    zone: 'RECEIVER SIDE',
    icon: 'ðŸš',
    security: 'Authoritative state machine: DISARMED â†’ ARMED â†’ TAKING_OFF â†’ HOVERING â†’ MOVING â†’ LANDING. Enforces state transition invariants independently of the security pipeline.',
    input: 'Validated plaintext command',
    output: 'Updated drone state + telemetry broadcast via WebSocket',
    consequence: null,
    stageKey: 5,
  },
};

export class CommunicationLab {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.components = {
      encryption: false,
      sender_auth: false,
      anti_replay: false,
      rate_limiting: true,
      receiver_auth: true,
    };
    this.currentMode = 'UNSECURED';
    this.activeStage = 1;
    this.lastPackedPayload = null;
    this.lastWirePayload = null;
    this.lastResponse = null;
    this.sequenceCounter = 1;
    this.activeDetailBlock = null;

    // Last real data per stage (populated during transmit)
    this.stageData = { 1: null, 2: null, 3: null, 4: null, 5: null };

    this.onToastCallbacks = [];
    this.onLogCallbacks = [];
    this.onStatusCallbacks = [];

    this.bindDomEvents();
    this.fetchSecurityStatus();
  }

  onToast(cb) { this.onToastCallbacks.push(cb); }
  onLog(cb) { this.onLogCallbacks.push(cb); }
  onStatusChange(cb) { this.onStatusCallbacks.push(cb); }

  notifyToast(msg, type = 'info') { this.onToastCallbacks.forEach((cb) => cb(msg, type)); }
  notifyLog(category, severity, msg, details = null) { this.onLogCallbacks.forEach((cb) => cb(category, severity, msg, details)); }

  bindDomEvents() {
    // Pipeline block Attach/Detach buttons
    document.querySelectorAll('.btn-pipe-toggle').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation(); // don't bubble to block click
        const comp = e.currentTarget.dataset.component;
        if (comp && this.components[comp] !== undefined) {
          this.toggleComponent(comp, !this.components[comp]);
        }
      });
    });

    // Pipeline Presets
    const btnPresetSecure = document.getElementById('btn-preset-secure');
    const btnPresetUnsecured = document.getElementById('btn-preset-unsecured');
    const btnPresetIntegrity = document.getElementById('btn-preset-integrity');
    if (btnPresetSecure) btnPresetSecure.addEventListener('click', () => this.applyPreset('SECURE'));
    if (btnPresetUnsecured) btnPresetUnsecured.addEventListener('click', () => this.applyPreset('UNSECURED'));
    if (btnPresetIntegrity) btnPresetIntegrity.addEventListener('click', () => this.applyPreset('INTEGRITY'));

    // Inspector Stage Tabs
    document.querySelectorAll('.stage-tab-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        this.selectInspectorStage(parseInt(e.currentTarget.dataset.stage, 10));
      });
    });

    // Diagram block clicks â€” show detail panel
    document.querySelectorAll('.pdiag-clickable').forEach((block) => {
      block.addEventListener('click', (e) => {
        if (e.target.closest('.btn-pipe-toggle')) return;
        const blockId = block.id || block.dataset.blockKey;
        this._openDetailPanel(block);
      });
    });

    // Detail panel close button
    const closeBtn = document.getElementById('pdiag-detail-close');
    if (closeBtn) closeBtn.addEventListener('click', () => this._closeDetailPanel());

    // Transmit buttons
    const btnTransmit = document.getElementById('btn-pipe-transmit');
    const btnTamper = document.getElementById('btn-pipe-tamper');
    const btnReplay = document.getElementById('btn-pipe-replay');
    if (btnTransmit) btnTransmit.addEventListener('click', () => this.executePipelineExperiment('send'));
    if (btnTamper) btnTamper.addEventListener('click', () => this.executePipelineExperiment('tamper'));
    if (btnReplay) btnReplay.addEventListener('click', () => this.executePipelineExperiment('replay'));

    // Wireshark copy filter button
    const btnCopyFilter = document.getElementById('btn-copy-ws-filter');
    if (btnCopyFilter) {
      btnCopyFilter.addEventListener('click', () => {
        navigator.clipboard.writeText('tcp.port == 8000');
        this.notifyToast('Copied "tcp.port == 8000" to clipboard.', 'success');
      });
    }
  }

  async fetchSecurityStatus() {
    try {
      const res = await fetch(`${this.apiBase}/api/security/status`);
      if (!res.ok) return;
      const json = await res.json();
      if ((json.status === 'success' || json.success) && json.data) {
        this.updateFromStatusData(json.data);
      }
    } catch (err) {
      console.warn('[CommunicationLab] Failed to fetch status:', err);
    }
  }

  syncSequenceNumber(highestSeq) {
    if (typeof highestSeq === 'number' && highestSeq >= this.sequenceCounter) {
      this.sequenceCounter = highestSeq + 1;
    }
  }

  updateFromStatusData(data) {
    const highest = data.replay_protection?.highest_sequence_number;
    if (typeof highest === 'number') {
      this.syncSequenceNumber(highest);
    }
    this.currentMode = data.current_mode || 'UNSECURED';
    if (data.components) {
      this.components = { ...this.components, ...data.components };
    } else {
      this.components.encryption = this.currentMode === 'ENCRYPTED_AUTHENTICATED';
      this.components.sender_auth = this.currentMode !== 'UNSECURED';
      this.components.anti_replay = this.currentMode !== 'UNSECURED';
    }

    this.renderPipelineBlocks();
    this.updateGlobalSecurityIndicator();
    this.onStatusCallbacks.forEach((cb) => cb(this.components, this.currentMode));
  }

  renderPipelineBlocks() {
    const compMap = {
      encryption:    { blockId: 'pipe-block-encryption',    badgeId: 'pipe-badge-encryption',    btnId: 'pipe-btn-encryption' },
      sender_auth:   { blockId: 'pipe-block-sender-auth',   badgeId: 'pipe-badge-sender-auth',   btnId: 'pipe-btn-sender-auth' },
      anti_replay:   { blockId: 'pipe-block-anti-replay',   badgeId: 'pipe-badge-anti-replay',   btnId: 'pipe-btn-anti-replay' },
      rate_limiting: { blockId: 'pipe-block-rate-limiting', badgeId: 'pipe-badge-rate-limiting', btnId: 'pipe-btn-rate-limiting' },
      receiver_auth: { blockId: 'pipe-block-receiver-auth', badgeId: 'pipe-badge-receiver-auth', btnId: 'pipe-btn-receiver-auth' },
    };

    Object.entries(compMap).forEach(([key, ids]) => {
      const isEnabled = !!this.components[key];
      const blockEl = document.getElementById(ids.blockId);
      const badgeEl = document.getElementById(ids.badgeId);
      const btnEl   = document.getElementById(ids.btnId);

      if (blockEl) {
        blockEl.classList.toggle('attached', isEnabled);
        blockEl.classList.toggle('detached', !isEnabled);
      }
      if (badgeEl) {
        badgeEl.textContent = isEnabled ? 'ATTACHED' : 'DETACHED';
        badgeEl.className = `pdiag-badge ${isEnabled ? 'badge-attached' : 'badge-detached'}`;
      }
      if (btnEl) {
        btnEl.textContent = isEnabled ? 'Detach' : 'Attach';
        btnEl.className   = `btn-pipe-toggle ${isEnabled ? 'btn-detach' : 'btn-attach'}`;
      }
    });

    // Update wire TCP visual â€” animate when encryption attached
    const wire = document.getElementById('pdiag-wire-tcp');
    if (wire) {
      wire.classList.toggle('wire-encrypted', !!this.components.encryption);
    }

    // Update replay button availability
    const btnReplay = document.getElementById('btn-pipe-replay');
    if (btnReplay) btnReplay.disabled = !this.lastPackedPayload;

    // Refresh detail panel if one is open
    if (this.activeDetailBlock) this._openDetailPanel(this.activeDetailBlock);
  }

  updateGlobalSecurityIndicator() {
    const pillText   = document.getElementById('header-sec-text');
    const headerPill = document.getElementById('header-sec-pill');
    if (!pillText) return;

    if (this.components.encryption && this.components.anti_replay && this.components.sender_auth) {
      pillText.textContent = 'AES-256-GCM SECURED';
      if (headerPill) headerPill.className = 'status-pill mode-pill secured';
    } else if (this.currentMode === 'INTEGRITY_ONLY' || (this.components.sender_auth && this.components.anti_replay)) {
      pillText.textContent = 'HMAC INTEGRITY ONLY';
      if (headerPill) headerPill.className = 'status-pill mode-pill integrity';
    } else if (!this.components.encryption && !this.components.sender_auth && !this.components.anti_replay) {
      pillText.textContent = 'UNSECURED (PLAINTEXT)';
      if (headerPill) headerPill.className = 'status-pill mode-pill unsecured';
    } else {
      pillText.textContent = `CUSTOM (${this.currentMode})`;
      if (headerPill) headerPill.className = 'status-pill mode-pill custom';
    }
  }

  async toggleComponent(component, targetState) {
    const btn = document.getElementById(`pipe-btn-${component.replace('_', '-')}`);
    if (btn) btn.disabled = true;

    try {
      const res = await fetch(`${this.apiBase}/api/security/component`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer gcs-sim-token-secret-2026' },
        body: JSON.stringify({ component, enabled: targetState, reason: 'Operator toggled via Communication Lab' }),
      });

      const body = await res.json();
      if (res.ok && (body.status === 'success' || body.success)) {
        const d = body.data;
        this.components[component] = d.enabled;
        if (d.components) this.components = { ...this.components, ...d.components };
        this.currentMode = d.active_mode;
        this.renderPipelineBlocks();
        this.updateGlobalSecurityIndicator();

        const actionStr = d.enabled ? 'ATTACHED' : 'DETACHED';
        this.notifyToast(`[${component}] ${actionStr} globally.`, d.enabled ? 'success' : 'warning');
        this.notifyLog('SECURITY', 'INFO', `Pipeline component '${component}' ${actionStr}. Active mode: ${d.active_mode}`);
      } else {
        const err = body.error || {};
        this.notifyToast(`Failed to toggle component: ${err.message || 'Error'}`, 'error');
      }
    } catch (err) {
      this.notifyToast(`Network error toggling component: ${err.message}`, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async applyPreset(presetName) {
    const modeMap = { SECURE: 'ENCRYPTED_AUTHENTICATED', UNSECURED: 'UNSECURED', INTEGRITY: 'INTEGRITY_ONLY' };
    const targetMode = modeMap[presetName];
    if (!targetMode) return;

    try {
      const res = await fetch(`${this.apiBase}/api/security/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer gcs-sim-token-secret-2026' },
        body: JSON.stringify({ mode: targetMode, reason: `Communication Lab Preset: ${presetName}` }),
      });
      const body = await res.json();
      if (res.ok && (body.status === 'success' || body.success)) {
        await this.fetchSecurityStatus();
        this.notifyToast(`Preset [${presetName}] applied.`, 'success');
        this.notifyLog('SECURITY', 'INFO', `Preset '${presetName}' (${targetMode}) applied.`);
      }
    } catch (err) {
      this.notifyToast(`Error applying preset: ${err.message}`, 'error');
    }
  }

  selectInspectorStage(stage) {
    this.activeStage = stage;
    document.querySelectorAll('.stage-tab-btn').forEach((btn) => {
      btn.classList.toggle('active', parseInt(btn.dataset.stage, 10) === stage);
    });
    document.querySelectorAll('.stage-card-panel').forEach((panel) => {
      panel.classList.toggle('active', parseInt(panel.dataset.stage, 10) === stage);
    });
  }

  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // DETAIL PANEL â€” shown below the diagram when a block is clicked
  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  _getBlockKey(blockEl) {
    if (blockEl.id === 'pdiag-gcs') return 'gcs';
    if (blockEl.id === 'pdiag-drone') return 'drone';
    if (blockEl.id === 'pipe-block-sender-auth') return 'sender_auth';
    if (blockEl.id === 'pipe-block-encryption') return 'encryption';
    if (blockEl.id === 'pipe-block-rate-limiting') return 'rate_limiting';
    if (blockEl.id === 'pipe-block-anti-replay') return 'anti_replay';
    if (blockEl.id === 'pipe-block-receiver-auth') return 'receiver_auth';
    // fallback for TCP zone separator â€” check data attribute
    const s = parseInt(blockEl.dataset.stage, 10);
    if (s === 3) return 'tcp';
    return null;
  }

  _openDetailPanel(blockEl) {
    this.activeDetailBlock = blockEl;
    const key = this._getBlockKey(blockEl);
    if (!key) return;

    const def = BLOCK_DEFS[key];
    if (!def) return;

    // Highlight active block
    document.querySelectorAll('.pdiag-clickable').forEach(b => b.classList.remove('pdiag-selected'));
    blockEl.classList.add('pdiag-selected');

    const panel = document.getElementById('pdiag-detail-panel');
    const titleEl = document.getElementById('pdiag-detail-title');
    const bodyEl = document.getElementById('pdiag-detail-body');
    if (!panel || !titleEl || !bodyEl) return;

    titleEl.textContent = def.title;

    // Is component optional?
    const compKey = ['sender_auth', 'encryption', 'rate_limiting', 'anti_replay', 'receiver_auth'].includes(key) ? key : null;
    const isEnabled = compKey ? !!this.components[compKey] : true;
    const stateLabel = compKey
      ? (isEnabled ? '<span class="text-emerald" style="font-weight:700">ATTACHED</span>' : '<span class="text-amber" style="font-weight:700">DETACHED</span>')
      : '<span style="color:var(--cyber-cyan);font-weight:700">ALWAYS ACTIVE</span>';

    // Real live data from last transmit (if available)
    const liveData = this.stageData[def.stageKey];
    const liveHtml = liveData
      ? `<div class="pdiag-detail-live">
           <div class="pdiag-detail-live-title">Live data from last transmission</div>
           <pre class="code-inspector" style="max-height:120px;margin-top:4px">${JSON.stringify(liveData, null, 2)}</pre>
         </div>`
      : `<div class="pdiag-detail-live" style="color:var(--text-dim);font-size:11px;font-style:italic">Transmit a command to see real pipeline data here.</div>`;

    bodyEl.innerHTML = `
      <div class="pdiag-detail-grid">
        <div class="pdiag-detail-row">
          <span class="pdiag-detail-lbl">Zone</span>
          <span class="pdiag-detail-val">${def.zone}</span>
        </div>
        <div class="pdiag-detail-row">
          <span class="pdiag-detail-lbl">Status</span>
          <span class="pdiag-detail-val">${stateLabel}</span>
        </div>
        <div class="pdiag-detail-row pdiag-detail-row--full">
          <span class="pdiag-detail-lbl">Security Function</span>
          <span class="pdiag-detail-val" style="color:#e2e8f0">${def.security}</span>
        </div>
        <div class="pdiag-detail-row">
          <span class="pdiag-detail-lbl">Input</span>
          <span class="pdiag-detail-val" style="font-family:var(--font-mono);font-size:11px">${def.input}</span>
        </div>
        <div class="pdiag-detail-row">
          <span class="pdiag-detail-lbl">Output</span>
          <span class="pdiag-detail-val" style="font-family:var(--font-mono);font-size:11px">${def.output}</span>
        </div>
        ${def.consequence ? `<div class="pdiag-detail-row pdiag-detail-row--full">
          <span class="pdiag-detail-lbl" style="color:var(--amber)">If Detached</span>
          <span class="pdiag-detail-val" style="color:var(--amber)">${def.consequence}</span>
        </div>` : ''}
      </div>
      ${liveHtml}
    `;

    panel.classList.add('open');
  }

  _closeDetailPanel() {
    this.activeDetailBlock = null;
    document.querySelectorAll('.pdiag-clickable').forEach(b => b.classList.remove('pdiag-selected'));
    const panel = document.getElementById('pdiag-detail-panel');
    if (panel) panel.classList.remove('open');
  }

  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // STAGE-FLASH â€” animate which blocks lit up as message passed through
  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  _flashStages(success) {
    const seq = ['pdiag-flash-1', 'pdiag-flash-2a', 'pdiag-flash-2b', 'pdiag-wire-tcp'];
    const receiverFlashes = ['pdiag-flash-4a', 'pdiag-flash-4b', 'pdiag-flash-4c', 'pdiag-flash-5'];

    let delay = 0;
    const flashEl = (id, color, d) => {
      setTimeout(() => {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.add('flashing');
        el.style.setProperty('--flash-color', color);
        setTimeout(() => el.classList.remove('flashing'), 600);
      }, d);
    };

    const cyan = 'var(--cyber-cyan)';
    const green = 'var(--emerald)';
    const red = 'var(--crimson)';
    const purple = 'var(--purple)';

    // GCS origin flash
    flashEl('pdiag-flash-1', cyan, 0); delay += 120;

    // Sender-side flashes
    if (this.components.sender_auth) { flashEl('pdiag-flash-2a', green, delay); }
    delay += 120;
    if (this.components.encryption) { flashEl('pdiag-flash-2b', green, delay); }
    delay += 120;

    // TCP wire
    flashEl('pdiag-wire-tcp', purple, delay); delay += 150;

    // Receiver flashes
    const outcomeColor = success ? green : red;
    if (this.components.rate_limiting) { flashEl('pdiag-flash-4a', outcomeColor, delay); delay += 100; }
    if (this.components.anti_replay)  { flashEl('pdiag-flash-4b', outcomeColor, delay); delay += 100; }
    if (this.components.receiver_auth){ flashEl('pdiag-flash-4c', outcomeColor, delay); delay += 100; }
    flashEl('pdiag-flash-5', success ? green : red, delay);
  }

  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // PIPELINE EXPERIMENT TRANSMITTER
  // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  async executePipelineExperiment(action = 'send') {
    const cmdSelect  = document.getElementById('pipe-cmd-select');
    const paramInput = document.getElementById('pipe-param-distance');

    const command  = cmdSelect ? cmdSelect.value : 'MOVE_FORWARD';
    const distance = paramInput ? parseFloat(paramInput.value) || 2.0 : 2.0;
    const parameters = ['MOVE_FORWARD', 'MOVE_BACKWARD', 'MOVE_LEFT', 'MOVE_RIGHT', 'MOVE_UP', 'MOVE_DOWN'].includes(command)
      ? { distance_meters: distance }
      : null;

    const seq = this.sequenceCounter++;

    // Stage 1: GCS Plaintext
    const rawPlaintext = {
      command,
      parameters,
      sender_id: 'GCS-PRIMARY',
      sequence_number: seq,
      timestamp: Date.now() / 1000,
    };
    this.stageData[1] = rawPlaintext;
    this.renderStage1(rawPlaintext);

    let payloadToSend = null;
    const authHeader = 'Bearer gcs-sim-token-secret-2026';

    if (action === 'replay') {
      if (!this.lastPackedPayload) {
        this.notifyToast('No previous packet to replay. Send a command first.', 'warning');
        return;
      }
      payloadToSend = JSON.parse(JSON.stringify(this.lastPackedPayload));
      this.notifyToast('Replaying exact previous packet envelope...', 'info');
    } else {
      try {
        const packRes = await fetch(`${this.apiBase}/api/drone/command/pack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command, parameters, sender_id: 'GCS-PRIMARY', sequence_number: seq }),
        });
        if (packRes.ok) {
          const packData = await packRes.json();
          payloadToSend = packData.data?.payload || rawPlaintext;
        } else {
          payloadToSend = rawPlaintext;
        }
      } catch (err) {
        payloadToSend = rawPlaintext;
      }

      if (action === 'tamper') {
        payloadToSend = this.tamperPayload(payloadToSend);
        this.notifyToast('Tampered with packet (bit-flip / modified command).', 'warning');
      }

      this.lastPackedPayload = JSON.parse(JSON.stringify(payloadToSend));
    }

    this.stageData[2] = payloadToSend;
    this.renderStage2(payloadToSend, action);

    const authUsed = this.components.sender_auth ? authHeader : '(Omitted â€” Sender Auth Detached)';
    this.stageData[3] = {
      method: 'POST /api/drone/command HTTP/1.1',
      host: '127.0.0.1:8000',
      authorization: authUsed,
      body: payloadToSend,
    };
    this.renderStage3(payloadToSend, authUsed);

    // Actual HTTP / TCP transmission
    const startTime = performance.now();
    let responseStatus = 0;
    let responseBody   = null;

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (this.components.sender_auth) headers['Authorization'] = authHeader;

      const postRes = await fetch(`${this.apiBase}/api/drone/command`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payloadToSend),
      });
      responseStatus = postRes.status;
      responseBody   = await postRes.json();
    } catch (netErr) {
      responseStatus = 0;
      responseBody   = { status: 'error', error: { code: 'NETWORK_ERROR', message: netErr.message } };
    }

    const durationMs = performance.now() - startTime;
    const success = responseStatus === 200;

    this.stageData[4] = { http_status: responseStatus, error: responseBody?.error, duration_ms: durationMs };
    this.stageData[5] = responseBody?.data || { error: responseBody?.error };

    this.renderStage4(responseStatus, responseBody, action);
    this.renderStage5(responseStatus, responseBody, durationMs);

    // Animate the diagram
    this._flashStages(success);

    // Jump inspector to relevant stage
    this.selectInspectorStage(success ? 5 : 4);

    // Refresh detail panel with new live data if one is open
    if (this.activeDetailBlock) this._openDetailPanel(this.activeDetailBlock);

    if (success) {
      this.notifyToast(`Pipeline success: [${command}] (HTTP 200, ${durationMs.toFixed(0)}ms)`, 'success');
      this.notifyLog('COMMAND', 'INFO', `Executed via pipeline: ${command} (${durationMs.toFixed(1)}ms)`);
    } else {
      const code = responseBody?.error?.code || 'REJECTED';
      this.notifyToast(`Pipeline rejected: ${code} (HTTP ${responseStatus})`, 'error');
      this.notifyLog('SECURITY', 'WARNING', `Pipeline rejection: ${code} â€” ${responseBody?.error?.message || ''}`);
    }

    this.renderPipelineBlocks();
  }

  tamperPayload(payload) {
    const copy = JSON.parse(JSON.stringify(payload));
    if (copy.ciphertext) {
      const ct = copy.ciphertext;
      copy.ciphertext = (ct[0] === 'A' ? 'B' : 'A') + ct.slice(1);
    } else if (copy.payload && copy.payload.command) {
      copy.payload.command = copy.payload.command === 'MOVE_FORWARD' ? 'MOVE_BACKWARD' : 'STOP';
    } else if (copy.command) {
      copy.command = copy.command === 'MOVE_FORWARD' ? 'MOVE_BACKWARD' : 'STOP';
    }
    return copy;
  }

  renderStage1(data) {
    const el = document.getElementById('inspector-stage-1-content');
    if (el) el.textContent = JSON.stringify(data, null, 2);
  }

  renderStage2(payload, action) {
    const el    = document.getElementById('inspector-stage-2-content');
    const badge = document.getElementById('inspector-stage-2-badge');
    if (el) el.textContent = JSON.stringify(payload, null, 2);
    if (badge) {
      if (payload.ciphertext) {
        badge.textContent = 'AES-256-GCM AEAD ENVELOPE';
        badge.className = 'status-pill mode-pill secured';
      } else if (payload.signature) {
        badge.textContent = 'HMAC-SHA-256 SIGNED (PLAINTEXT)';
        badge.className = 'status-pill mode-pill integrity';
      } else {
        badge.textContent = 'UNENCRYPTED PLAINTEXT PAYLOAD';
        badge.className = 'status-pill mode-pill unsecured';
      }
    }
  }

  renderStage3(payload, authHeader) {
    const el = document.getElementById('inspector-stage-3-content');
    if (!el) return;
    const payloadJson = JSON.stringify(payload);
    el.textContent = [
      `POST /api/drone/command HTTP/1.1`,
      `Host: 127.0.0.1:8000`,
      `Content-Type: application/json`,
      `Authorization: ${authHeader}`,
      `Content-Length: ${new TextEncoder().encode(payloadJson).length} bytes`,
      ``,
      payloadJson,
    ].join('\n');
  }

  renderStage4(status, body, action) {
    const el = document.getElementById('inspector-stage-4-checks');
    if (!el) return;

    const errCode = body?.error?.code;
    const checks = [
      {
        name: 'Rate Limiter (Token Bucket)',
        status: !this.components.rate_limiting ? 'BYPASSED (Detached)' : errCode === 'RATE_LIMIT_EXCEEDED' ? 'FAIL (HTTP 429 Throttle)' : 'PASS',
        color: !this.components.rate_limiting ? 'text-amber' : errCode === 'RATE_LIMIT_EXCEEDED' ? 'text-crimson' : 'text-emerald',
      },
      {
        name: 'Sender Identity & Bearer Auth',
        status: !this.components.sender_auth ? 'BYPASSED (Detached)' : ['AUTH_TOKEN_MISSING', 'AUTH_TOKEN_INVALID', 'SPOOFED_GCS_IDENTITY'].includes(errCode) ? `FAIL (${errCode})` : 'PASS',
        color: !this.components.sender_auth ? 'text-amber' : ['AUTH_TOKEN_MISSING', 'AUTH_TOKEN_INVALID', 'SPOOFED_GCS_IDENTITY'].includes(errCode) ? 'text-crimson' : 'text-emerald',
      },
      {
        name: 'Anti-Replay Filter (Seq Window)',
        status: !this.components.anti_replay ? 'BYPASSED (Detached)' : errCode === 'REPLAY_ATTACK_DETECTED' ? 'FAIL (Duplicate / Stale Seq)' : 'PASS',
        color: !this.components.anti_replay ? 'text-amber' : errCode === 'REPLAY_ATTACK_DETECTED' ? 'text-crimson' : 'text-emerald',
      },
      {
        name: 'Cryptographic AEAD / HMAC Integrity',
        status: !this.components.encryption && this.currentMode !== 'INTEGRITY_ONLY' ? 'BYPASSED (Plaintext Payload)' : ['CRYPTO_DECRYPTION_FAILED', 'HMAC_VERIFICATION_FAILED'].includes(errCode) ? 'FAIL (Tampered / Tag Mismatch)' : 'PASS',
        color: !this.components.encryption && this.currentMode !== 'INTEGRITY_ONLY' ? 'text-amber' : ['CRYPTO_DECRYPTION_FAILED', 'HMAC_VERIFICATION_FAILED'].includes(errCode) ? 'text-crimson' : 'text-emerald',
      },
      {
        name: 'Receiver Command Authorization',
        status: status === 200 ? 'AUTHORIZED' : errCode ? `REJECTED (${errCode})` : 'VALIDATED',
        color: status === 200 ? 'text-emerald' : 'text-crimson',
      },
    ];

    el.innerHTML = checks.map(c => `
      <div class="invariant-metric-row" style="padding:6px 0">
        <span style="font-weight:600">${c.name}:</span>
        <span class="${c.color}" style="font-family:var(--font-mono);font-weight:700">${c.status}</span>
      </div>`).join('');
  }

  renderStage5(status, body, durationMs) {
    const el = document.getElementById('inspector-stage-5-content');
    if (!el) return;

    const isSuccess = status === 200;
    const data = body.data || {};
    const err  = body.error || {};

    el.innerHTML = `
      <div class="result-status-badge ${isSuccess ? 'result-BLOCKED_BY_DEFENSE' : 'result-SUCCESSFUL_EXPLOIT'}" style="margin-bottom:12px;font-size:13px">
        ${isSuccess ? 'ACCEPTED & EXECUTED' : `FAIL-CLOSED REJECTION (${status})`}
      </div>
      <div class="invariant-metric-row">
        <span style="color:var(--text-dim)">HTTP Status:</span>
        <span style="font-family:var(--font-mono);font-weight:700">${status}</span>
      </div>
      <div class="invariant-metric-row">
        <span style="color:var(--text-dim)">Execution:</span>
        <span class="${isSuccess ? 'text-emerald' : 'text-crimson'}" style="font-weight:700">
          ${isSuccess ? data.execution_status || 'EXECUTED' : err.code || 'REJECTED'}
        </span>
      </div>
      <div class="invariant-metric-row">
        <span style="color:var(--text-dim)">Latency:</span>
        <span style="font-family:var(--font-mono)">${durationMs.toFixed(2)} ms</span>
      </div>
      <div class="invariant-metric-row">
        <span style="color:var(--text-dim)">State Version:</span>
        <span style="font-family:var(--font-mono);color:var(--cyber-cyan)">V${data.state_version_after ?? '--'}</span>
      </div>
      ${err.message ? `<div style="margin-top:10px;padding:8px;background:rgba(255,51,102,0.1);border-left:3px solid var(--crimson);font-size:11px">
        <strong>Error:</strong> ${err.message}
      </div>` : ''}
    `;
  }
}



/**
 * DroneSec Security Panel Manager
 *
 * Interfaces with:
 * - GET  /api/security/status
 * - POST /api/security/mode
 *
 * Synchronizes active security mode badges, cryptographic details,
 * anti-replay sliding window metrics, and token-bucket rate limiter gauges.
 */

export class SecurityPanel {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.currentMode = 'UNSECURED';
    this.onModeChangeCallbacks = [];
    this.onToastCallbacks = [];

    this.bindDomEvents();
    this.fetchSecurityStatus();
    // Poll security status every 4 seconds to keep rate-limiter & anti-replay metrics fresh
    this.pollInterval = setInterval(() => this.fetchSecurityStatus(), 4000);
  }

  bindDomEvents() {
    // Security Mode Switch Buttons
    const modeButtons = document.querySelectorAll('.sec-mode-btn');
    modeButtons.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const targetMode = e.currentTarget.dataset.mode;
        if (targetMode && targetMode !== this.currentMode) {
          this.switchSecurityMode(targetMode);
        }
      });
    });
  }

  async fetchSecurityStatus() {
    try {
      const resp = await fetch(`${this.apiBase}/api/security/status`);
      if (!resp.ok) return;

      const body = await resp.json();
      if (body.success && body.data) {
        this.renderStatus(body.data);
      }
    } catch (err) {
      console.warn('[SecurityPanel] Failed to fetch security status:', err);
    }
  }

  renderStatus(data) {
    const mode = data.current_mode || data.active_mode || 'UNSECURED';
    this.currentMode = mode;
    this.updateHeaderModeButtons(mode);

    // Update Cryptographic indicators
    const cipherEl = document.getElementById('sec-cipher-name');
    const authEl = document.getElementById('sec-auth-type');
    const replaySeqEl = document.getElementById('sec-replay-seq');
    const tokensEl = document.getElementById('sec-rate-tokens');

    if (cipherEl) {
      if (mode === 'ENCRYPTED_AUTHENTICATED') {
        cipherEl.textContent = 'AES-256-GCM (AEAD)';
        cipherEl.className = 'metric-value text-emerald';
      } else if (mode === 'INTEGRITY_ONLY') {
        cipherEl.textContent = 'Plaintext + HMAC-SHA256';
        cipherEl.className = 'metric-value text-amber';
      } else {
        cipherEl.textContent = 'Plaintext (None)';
        cipherEl.className = 'metric-value text-crimson';
      }
    }

    if (authEl) {
      authEl.textContent = mode === 'UNSECURED' ? 'Disabled' : 'Bearer Token + HMAC';
    }

    if (replaySeqEl) {
      const highestSeq = data.replay_protection?.highest_sequence_number ?? data.replay_last_seq ?? 0;
      const winSize = data.replay_protection?.window_size ?? 64;
      replaySeqEl.textContent = `${highestSeq} / ${winSize}-bit window`;
    }

    if (tokensEl) {
      const cap = data.rate_limiting?.burst_capacity ?? 10;
      const rate = data.rate_limiting?.rate_limit_per_second ?? 5;
      tokensEl.textContent = `${rate} req/s (Burst: ${cap})`;
    }
  }

  updateHeaderModeButtons(activeMode) {
    document.querySelectorAll('.sec-mode-btn').forEach((btn) => {
      btn.classList.remove('active');
      if (btn.dataset.mode === activeMode) {
        btn.classList.add('active');
      }
    });

    // Update security panel indicator pill
    const modeBadge = document.getElementById('sec-mode-badge');
    if (modeBadge) {
      modeBadge.textContent = activeMode;
      modeBadge.className = `status-pill mode-${activeMode.toLowerCase()}`;
    }
  }

  async switchSecurityMode(targetMode) {
    try {
      const resp = await fetch(`${this.apiBase}/api/security/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: targetMode,
          reason: 'Operator switched mode via Ground Control Station',
        }),
      });

      const body = await resp.json();
      if (resp.ok && body.success) {
        this.currentMode = targetMode;
        this.updateHeaderModeButtons(targetMode);
        this.notifyToast(`Security profile updated to [${targetMode}]`, 'success');
        this.notifyModeChange(targetMode);
        this.fetchSecurityStatus();
      } else {
        const err = body.error || {};
        this.notifyToast(`Failed to change security mode: ${err.message || 'Error'}`, 'error');
      }
    } catch (err) {
      this.notifyToast(`Network Error: ${err.message}`, 'error');
    }
  }

  onModeChange(callback) {
    this.onModeChangeCallbacks.push(callback);
  }

  onToast(callback) {
    this.onToastCallbacks.push(callback);
  }

  notifyModeChange(mode) {
    this.onModeChangeCallbacks.forEach((cb) => cb(mode));
  }

  notifyToast(msg, type = 'info') {
    this.onToastCallbacks.forEach((cb) => cb(msg, type));
  }

  destroy() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
    }
  }
}

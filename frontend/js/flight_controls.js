/**
 * DroneSec Flight Control Manager
 *
 * Dispatches authoritative flight commands via POST /api/drone/command:
 * - ARM, DISARM, TAKEOFF, LAND, STOP
 * - MOVE_FORWARD, MOVE_BACKWARD, MOVE_LEFT, MOVE_RIGHT, MOVE_UP, MOVE_DOWN
 *
 * Implements client-side FSM state rules to disable invalid buttons
 * while letting the backend remain the authoritative validator.
 */

export class FlightControls {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.currentFlightState = 'DISARMED';
    this.stepDistance = 2.0; // Default 2.0m step
    this.isSubmitting = false;
    this.sequenceNumber = 1;

    this.onCommandResultCallbacks = [];
    this.onToastCallbacks = [];

    this.bindDomEvents();
    this.bindKeyboardShortcuts();
  }

  bindDomEvents() {
    // Action buttons
    const btnArm = document.getElementById('btn-cmd-arm');
    const btnDisarm = document.getElementById('btn-cmd-disarm');
    const btnTakeoff = document.getElementById('btn-cmd-takeoff');
    const btnLand = document.getElementById('btn-cmd-land');
    const btnStop = document.getElementById('btn-cmd-stop');

    if (btnArm) btnArm.addEventListener('click', () => this.sendCommand('ARM'));
    if (btnDisarm) btnDisarm.addEventListener('click', () => this.sendCommand('DISARM'));
    if (btnTakeoff) btnTakeoff.addEventListener('click', () => this.sendCommand('TAKEOFF'));
    if (btnLand) btnLand.addEventListener('click', () => this.sendCommand('LAND'));
    if (btnStop) btnStop.addEventListener('click', () => this.sendCommand('STOP'));

    // D-Pad movement controls
    const dpadMap = {
      'btn-move-fwd': 'MOVE_FORWARD',
      'btn-move-back': 'MOVE_BACKWARD',
      'btn-move-left': 'MOVE_LEFT',
      'btn-move-right': 'MOVE_RIGHT',
      'btn-move-up': 'MOVE_UP',
      'btn-move-down': 'MOVE_DOWN',
    };

    Object.entries(dpadMap).forEach(([id, cmd]) => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('click', () => this.sendCommand(cmd, { distance_meters: this.stepDistance }));
      }
    });

    // Step distance chips
    document.querySelectorAll('.step-chip').forEach((chip) => {
      chip.addEventListener('click', (e) => {
        document.querySelectorAll('.step-chip').forEach((c) => c.classList.remove('active'));
        e.target.classList.add('active');
        this.stepDistance = parseFloat(e.target.dataset.step) || 2.0;
      });
    });
  }

  bindKeyboardShortcuts() {
    window.addEventListener('keydown', (e) => {
      // Don't trigger when typing in input or textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        return;
      }

      // Suppress OS key-repeat events — only process the initial keydown stroke
      if (e.repeat) return;

      const key = e.key.toUpperCase();
      switch (key) {
        case 'W':
          this.sendCommand('MOVE_FORWARD', { distance_meters: this.stepDistance });
          break;
        case 'S':
          this.sendCommand('MOVE_BACKWARD', { distance_meters: this.stepDistance });
          break;
        case 'A':
          this.sendCommand('MOVE_LEFT', { distance_meters: this.stepDistance });
          break;
        case 'D':
          this.sendCommand('MOVE_RIGHT', { distance_meters: this.stepDistance });
          break;
        case 'R':
          this.sendCommand('MOVE_UP', { distance_meters: this.stepDistance });
          break;
        case 'F':
          this.sendCommand('MOVE_DOWN', { distance_meters: this.stepDistance });
          break;
        case ' ':
          e.preventDefault();
          this.sendCommand('STOP');
          break;
      }
    });
  }

  updateFlightState(flightState) {
    this.currentFlightState = flightState;
    this.updateButtonStates();
  }

  updateButtonStates() {
    const s = this.currentFlightState;

    const btnArm = document.getElementById('btn-cmd-arm');
    const btnDisarm = document.getElementById('btn-cmd-disarm');
    const btnTakeoff = document.getElementById('btn-cmd-takeoff');
    const btnLand = document.getElementById('btn-cmd-land');
    const btnStop = document.getElementById('btn-cmd-stop');
    const dpadButtons = document.querySelectorAll('.dpad-btn');

    const isAirborne = ['HOVERING', 'MOVING'].includes(s);

    if (btnArm) btnArm.disabled = s !== 'DISARMED';
    if (btnDisarm) btnDisarm.disabled = s !== 'ARMED'; // Mid-air disarm prohibited!
    if (btnTakeoff) btnTakeoff.disabled = s !== 'ARMED';
    if (btnLand) btnLand.disabled = !isAirborne;
    if (btnStop) btnStop.disabled = !isAirborne;

    dpadButtons.forEach((btn) => {
      btn.disabled = !isAirborne;
    });
  }

  async sendCommand(command, parameters = null) {
    if (this.isSubmitting) return;

    this.isSubmitting = true;
    let payload = {
      command: command,
      parameters: parameters,
      client_id: 'GCS-PRIMARY',
    };

    try {
      // Pack command for active security mode if needed
      try {
        const packResp = await fetch(`${this.apiBase}/api/drone/command/pack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            command: command,
            parameters: parameters,
            sender_id: 'GCS-PRIMARY',
            sequence_number: this.sequenceNumber++,
          }),
        });
        if (packResp.ok) {
          const packData = await packResp.json();
          if (packData.data && packData.data.payload) {
            payload = packData.data.payload;
          }
        }
      } catch (packErr) {
        // Fall back to default payload
      }

      const response = await fetch(`${this.apiBase}/api/drone/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer gcs-sim-token-secret-2026',
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      // Backend envelope uses { status: "success"|"error", data/error: ... }
      if (response.ok && result.status === 'success') {
        this.notifyToast(`Command [${command}] executed successfully.`, 'success');
        this.notifyCommandResult({ command, success: true, data: result.data });
      } else {
        const err = result.error || {};
        const code = err.code || 'COMMAND_FAILED';
        const msg = err.message || 'Execution rejected by drone engine.';
        this.notifyToast(`[${code}] ${msg}`, 'error');
        this.notifyCommandResult({ command, success: false, error: err });
      }
    } catch (netErr) {
      this.notifyToast(`Network Error: ${netErr.message}`, 'error');
      this.notifyCommandResult({ command, success: false, error: { code: 'NETWORK_ERROR', message: netErr.message } });
    } finally {
      this.isSubmitting = false;
    }
  }

  onCommandResult(callback) {
    this.onCommandResultCallbacks.push(callback);
  }

  onToast(callback) {
    this.onToastCallbacks.push(callback);
  }

  notifyCommandResult(data) {
    this.onCommandResultCallbacks.forEach((cb) => cb(data));
  }

  notifyToast(message, type = 'info') {
    this.onToastCallbacks.forEach((cb) => cb(message, type));
  }
}

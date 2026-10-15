/**
 * DroneSec Ground Control Station - Main Application Controller
 *
 * Coordinates:
 * - 3D Simulation World (Three.js)
 * - Telemetry WebSocket Client (/ws/telemetry)
 * - Flight Controls (REST commands)
 * - Security Panel (Mode switching)
 * - Cyberattack Console (ATK-01 to ATK-06)
 * - Event & Audit Log Console
 */

import { SimulationWorld } from './simulation.js';
import { TelemetryClient } from './telemetry.js';
import { FlightControls } from './flight_controls.js';
import { SecurityPanel } from './security_panel.js';
import { AttackConsole } from './attack_console.js';
import { EventLogConsole } from './event_log.js';

document.addEventListener('DOMContentLoaded', () => {
  console.log('[DroneSec GCS] Initializing Ground Control Station...');

  // 1. Toast Notification Manager
  const toastContainer = document.getElementById('toast-container');
  const showToast = (message, type = 'info') => {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast-msg ${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(-20px)';
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  };

  // 2. Initialize 3D Simulation World
  const canvas = document.getElementById('three-canvas');
  let world = null;
  if (canvas) {
    world = new SimulationWorld(canvas);
  }

  // 3. Initialize Event Log Console
  const eventLog = new EventLogConsole();

  // 4. Initialize Flight Controls
  const flightControls = new FlightControls();
  flightControls.onToast((msg, type) => showToast(msg, type));
  flightControls.onCommandResult((res) => {
    const sev = res.success ? 'INFO' : 'WARNING';
    const msg = res.success
      ? `Executed command: ${res.command}`
      : `Rejected command: ${res.command} (${res.error?.code || 'ERROR'})`;
    eventLog.appendLog('COMMAND', sev, msg, res);
  });

  // 5. Initialize Security Panel
  const securityPanel = new SecurityPanel();
  securityPanel.onToast((msg, type) => showToast(msg, type));
  securityPanel.onModeChange((newMode) => {
    eventLog.appendLog('SECURITY', 'INFO', `Security operating mode switched to [${newMode}]`);
  });

  // 6. Initialize Attack Console
  const attackConsole = new AttackConsole();
  attackConsole.onToast((msg, type) => showToast(msg, type));
  attackConsole.onAttackComplete((result) => {
    const isExploit = result.attack_result === 'SUCCESSFUL_EXPLOIT';
    const sev = isExploit ? 'CRITICAL' : 'WARNING';
    eventLog.appendLog(
      'ATTACK',
      sev,
      `Scenario ${result.attack_type} result: ${result.attack_result} (Compromised: ${result.state_compromised})`,
      result
    );
  });

  // 7. Initialize Telemetry WebSocket Client
  const telemetryClient = new TelemetryClient();

  // Connection Status UI
  const statusDot = document.getElementById('conn-status-dot');
  const statusText = document.getElementById('conn-status-text');
  const pingEl = document.getElementById('conn-latency-val');

  telemetryClient.onStatusChange((status) => {
    if (!statusDot || !statusText) return;

    statusDot.className = `status-dot ${status}`;
    if (status === 'connected') {
      statusText.textContent = 'LIVE 20Hz';
      eventLog.appendLog('TELEMETRY', 'INFO', 'Connected to real-time telemetry stream.');
    } else if (status === 'connecting') {
      statusText.textContent = 'CONNECTING...';
    } else if (status === 'stale') {
      statusText.textContent = 'STALE DATA';
      statusDot.className = 'status-dot connecting';
    } else {
      statusText.textContent = 'DISCONNECTED';
      eventLog.appendLog('TELEMETRY', 'WARNING', 'WebSocket telemetry stream disconnected.');
    }
  });

  telemetryClient.onLatency((latMs) => {
    if (pingEl) pingEl.textContent = `${latMs}ms`;
  });

  // Telemetry Updates
  telemetryClient.onTelemetry((telemetry) => {
    // 1. Pass to 3D world
    if (world) {
      world.updateTelemetry(telemetry);
    }

    // 2. Pass to flight controls
    if (telemetry.flight_state) {
      flightControls.updateFlightState(telemetry.flight_state);
    }

    // 3. Update DOM Telemetry Display
    updateTelemetryDisplay(telemetry);
  });

  // Connect to WebSocket stream
  telemetryClient.connect();

  // 8. Fetch Baseline State on Initial Load
  fetchInitialState(world, flightControls, updateTelemetryDisplay);

  // 9. Camera HUD Controls
  setupCameraButtons(world);

  // 10. Start Header Clock
  startClock();
});

/**
 * Fetch authoritative baseline snapshot on initial page load.
 */
async function fetchInitialState(world, flightControls, updateTelemetryDisplay) {
  try {
    const res = await fetch('/api/drone/state');
    if (!res.ok) return;

    const body = await res.json();
    if (body.success && body.data) {
      const d = body.data;
      const flat = {
        state_version: d.state_version,
        flight_state: d.flight_state,
        x: d.position?.x ?? 0,
        y: d.position?.y ?? 0,
        z: d.position?.z ?? 0,
        latitude: d.geographic?.latitude ?? 0,
        longitude: d.geographic?.longitude ?? 0,
        altitude_msl: d.geographic?.altitude_msl ?? 0,
        heading: d.motion?.heading ?? 0,
        speed: d.motion?.speed ?? 0,
        battery_percent: d.battery?.level_percent ?? 100,
      };

      if (world) world.updateTelemetry(flat);
      if (flightControls) flightControls.updateFlightState(flat.flight_state);
      updateTelemetryDisplay(flat);
    }
  } catch (err) {
    console.warn('[DroneSec GCS] Failed to fetch initial baseline state:', err);
  }
}

/**
 * Update UI Telemetry Values with authoritative numbers.
 */
function updateTelemetryDisplay(t) {
  // Flight state badge
  const stateBadge = document.getElementById('flight-state-badge');
  if (stateBadge && t.flight_state) {
    stateBadge.textContent = t.flight_state;
    stateBadge.className = `flight-state-badge flight-state-${t.flight_state}`;
  }

  // State version
  const svEl = document.getElementById('val-state-version');
  if (svEl && typeof t.state_version === 'number') {
    svEl.textContent = `V${t.state_version}`;
  }

  // Altitude
  const altEl = document.getElementById('tel-altitude');
  if (altEl && typeof t.y === 'number') {
    altEl.textContent = t.y.toFixed(2);
  }

  // Speed
  const spdEl = document.getElementById('tel-speed');
  if (spdEl && typeof t.speed === 'number') {
    spdEl.textContent = t.speed.toFixed(2);
  }

  // Heading & Cardinal
  const hdgEl = document.getElementById('tel-heading');
  const cardEl = document.getElementById('tel-cardinal');
  if (hdgEl && typeof t.heading === 'number') {
    hdgEl.textContent = t.heading.toFixed(1);
    if (cardEl) cardEl.textContent = getCardinalDirection(t.heading);

    // Rotate compass dial
    const compassDial = document.getElementById('compass-dial');
    if (compassDial) {
      compassDial.style.transform = `rotate(${-t.heading}deg)`;
    }
  }

  // Local Coordinates (X, Y, Z)
  const xEl = document.getElementById('tel-coord-x');
  const yEl = document.getElementById('tel-coord-y');
  const zEl = document.getElementById('tel-coord-z');
  if (xEl && typeof t.x === 'number') xEl.textContent = t.x.toFixed(2);
  if (yEl && typeof t.y === 'number') yEl.textContent = t.y.toFixed(2);
  if (zEl && typeof t.z === 'number') zEl.textContent = t.z.toFixed(2);

  // GPS Coordinates (Lat, Lon)
  const latEl = document.getElementById('tel-lat');
  const lonEl = document.getElementById('tel-lon');
  if (latEl && typeof t.latitude === 'number') latEl.textContent = t.latitude.toFixed(6);
  if (lonEl && typeof t.longitude === 'number') lonEl.textContent = t.longitude.toFixed(6);

  // Battery Level & Bar
  const batVal = document.getElementById('tel-battery-val');
  const batBar = document.getElementById('tel-battery-fill');
  if (batVal && typeof t.battery_percent === 'number') {
    batVal.textContent = `${t.battery_percent.toFixed(1)}%`;

    if (batBar) {
      batBar.style.width = `${Math.max(0, Math.min(100, t.battery_percent))}%`;
      batBar.className = 'battery-bar-fill';
      if (t.battery_percent <= 15) {
        batBar.classList.add('critical');
      } else if (t.battery_percent <= 30) {
        batBar.classList.add('warning');
      }
    }
  }
}

/**
 * Return compass cardinal sector (N, NE, E, SE, S, SW, W, NW).
 */
function getCardinalDirection(deg) {
  const directions = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'];
  const index = Math.round(((deg % 360) + 360) % 360 / 45) % 8;
  return directions[index];
}

/**
 * Setup Camera Mode Switcher Buttons.
 */
function setupCameraButtons(world) {
  if (!world) return;

  const btnOrbit = document.getElementById('cam-mode-orbit');
  const btnChase = document.getElementById('cam-mode-chase');
  const btnTop = document.getElementById('cam-mode-top');
  const btnTower = document.getElementById('cam-mode-tower');
  const btnReset = document.getElementById('cam-reset');

  const btns = [btnOrbit, btnChase, btnTop, btnTower];

  const setActive = (targetBtn) => {
    btns.forEach((b) => b?.classList.remove('active'));
    targetBtn?.classList.add('active');
  };

  if (btnOrbit) {
    btnOrbit.addEventListener('click', () => {
      setActive(btnOrbit);
      world.setCameraMode('ORBIT');
    });
  }

  if (btnChase) {
    btnChase.addEventListener('click', () => {
      setActive(btnChase);
      world.setCameraMode('CHASE');
    });
  }

  if (btnTop) {
    btnTop.addEventListener('click', () => {
      setActive(btnTop);
      world.setCameraMode('TOPDOWN');
    });
  }

  if (btnTower) {
    btnTower.addEventListener('click', () => {
      setActive(btnTower);
      world.setCameraMode('TOWER');
    });
  }

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      setActive(btnOrbit);
      world.resetCamera();
    });
  }
}

/**
 * Live UTC Clock in GCS Header.
 */
function startClock() {
  const clockEl = document.getElementById('utc-clock');
  const update = () => {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = now.toUTCString().replace('GMT', 'UTC');
  };
  update();
  setInterval(update, 1000);
}

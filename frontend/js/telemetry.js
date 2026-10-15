/**
 * DroneSec Telemetry Client - WebSocket Connection & Heartbeat Manager
 *
 * Consumes the authoritative /ws/telemetry stream:
 * - Listens for TELEMETRY_UPDATE frames
 * - Emits periodic PING frames every 5s and calculates round-trip latency via PONG
 * - Handles auto-reconnection with exponential backoff
 * - Flags stale data when packets cease
 */

export class TelemetryClient {
  constructor(options = {}) {
    this.url = options.url || this.getDefaultWebSocketUrl();
    this.ws = null;
    this.isConnected = false;
    this.isConnecting = false;
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 10000;
    this.pingInterval = null;
    this.staleCheckInterval = null;
    this.lastPacketTimestamp = 0;
    this.lastPingSentTime = 0;
    this.currentLatencyMs = 0;

    // Listeners
    this.onTelemetryCallbacks = [];
    this.onStatusChangeCallbacks = [];
    this.onLatencyCallbacks = [];
  }

  getDefaultWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    return `${protocol}//${host}/ws/telemetry`;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isConnecting = true;
    this.notifyStatus('connecting');

    try {
      this.ws = new WebSocket(this.url);
    } catch (err) {
      console.error('[Telemetry] WebSocket instantiation failed:', err);
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      console.log('[Telemetry] Connected to /ws/telemetry');
      this.isConnected = true;
      this.isConnecting = false;
      this.reconnectAttempts = 0;
      this.lastPacketTimestamp = Date.now();
      this.notifyStatus('connected');

      this.startHeartbeat();
      this.startStaleChecker();
    };

    this.ws.onmessage = (event) => {
      this.lastPacketTimestamp = Date.now();
      try {
        const frame = JSON.parse(event.data);
        if (frame.type === 'TELEMETRY_UPDATE' && frame.payload) {
          this.notifyTelemetry(frame.payload);
        } else if (frame.type === 'PONG') {
          if (this.lastPingSentTime > 0) {
            this.currentLatencyMs = Math.max(1, Math.round(performance.now() - this.lastPingSentTime));
            this.notifyLatency(this.currentLatencyMs);
          }
        }
      } catch (e) {
        console.warn('[Telemetry] Malformed message received:', event.data);
      }
    };

    this.ws.onclose = (event) => {
      console.warn('[Telemetry] WebSocket closed (code:', event.code, ')');
      this.cleanup();
      this.notifyStatus('disconnected');
      this.scheduleReconnect();
    };

    this.ws.onerror = (err) => {
      console.error('[Telemetry] WebSocket error:', err);
      this.ws.close();
    };
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.lastPingSentTime = performance.now();
        this.ws.send(JSON.stringify({ type: 'PING' }));
      }
    }, 5000);
  }

  stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  startStaleChecker() {
    this.stopStaleChecker();
    this.staleCheckInterval = setInterval(() => {
      if (this.isConnected && Date.now() - this.lastPacketTimestamp > 2500) {
        this.notifyStatus('stale');
      }
    }, 1000);
  }

  stopStaleChecker() {
    if (this.staleCheckInterval) {
      clearInterval(this.staleCheckInterval);
      this.staleCheckInterval = null;
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelay);
    console.log(`[Telemetry] Reconnecting in ${Math.round(delay)}ms (attempt ${this.reconnectAttempts})...`);
    setTimeout(() => this.connect(), delay);
  }

  cleanup() {
    this.isConnected = false;
    this.isConnecting = false;
    this.stopHeartbeat();
    this.stopStaleChecker();
  }

  disconnect() {
    this.cleanup();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  // Event Subscription
  onTelemetry(callback) {
    this.onTelemetryCallbacks.push(callback);
  }

  onStatusChange(callback) {
    this.onStatusChangeCallbacks.push(callback);
  }

  onLatency(callback) {
    this.onLatencyCallbacks.push(callback);
  }

  notifyTelemetry(payload) {
    this.onTelemetryCallbacks.forEach((cb) => cb(payload));
  }

  notifyStatus(status) {
    this.onStatusChangeCallbacks.forEach((cb) => cb(status));
  }

  notifyLatency(latencyMs) {
    this.onLatencyCallbacks.forEach((cb) => cb(latencyMs));
  }
}

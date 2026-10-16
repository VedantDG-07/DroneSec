/**
 * DroneSec Event & Audit Log Console
 *
 * Interfaces with:
 *   GET /api/logs?limit=50&category=...&severity=...
 *
 * Features:
 * - Real-time client-side event appending
 * - Category filter tabs (ALL, COMMAND, SECURITY, ATTACK, TELEMETRY)
 * - Severity indicators (INFO, WARNING, CRITICAL)
 * - Safe DOM element construction (strict textContent to prevent HTML injection)
 * - Auto-scroll toggle and JSON log export
 */

export class EventLogConsole {
  constructor(options = {}) {
    this.apiBase = options.apiBase || '';
    this.logs = [];
    this.maxLogs = 200;
    this.activeFilter = 'ALL';
    this.autoScroll = true;

    this.bindDomEvents();
    this.fetchRecentLogs();
    this.pollInterval = setInterval(() => this.fetchRecentLogs(), 5000);
  }

  bindDomEvents() {
    // Drawer collapse/expand toggle
    const drawerHeader = document.getElementById('drawer-toggle-header');
    const drawerEl = document.getElementById('gcs-drawer');
    if (drawerHeader && drawerEl) {
      drawerHeader.addEventListener('click', (e) => {
        // Ignore if clicking on button/tabs in header
        if (e.target.closest('.drawer-controls')) return;
        drawerEl.classList.toggle('collapsed');
      });
    }

    // Category filter tabs
    document.querySelectorAll('.filter-tab').forEach((tab) => {
      tab.addEventListener('click', (e) => {
        document.querySelectorAll('.filter-tab').forEach((t) => t.classList.remove('active'));
        e.target.classList.add('active');
        this.activeFilter = e.target.dataset.filter || 'ALL';
        this.renderLogs();
      });
    });

    // Auto-scroll toggle checkbox
    const chkAutoScroll = document.getElementById('chk-autoscroll');
    if (chkAutoScroll) {
      chkAutoScroll.addEventListener('change', (e) => {
        this.autoScroll = e.target.checked;
      });
    }

    // Clear logs button
    const btnClear = document.getElementById('btn-clear-logs');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        this.logs = [];
        this.renderLogs();
      });
    }

    // Export logs button
    const btnExport = document.getElementById('btn-export-logs');
    if (btnExport) {
      btnExport.addEventListener('click', () => this.exportLogs());
    }
  }

  async fetchRecentLogs() {
    try {
      const resp = await fetch(`${this.apiBase}/api/logs?limit=30`);
      if (!resp.ok) return;

      const body = await resp.json();
      if ((body.status === 'success' || body.success) && Array.isArray(body.data)) {
        // Merge without duplicating existing IDs
        const existingIds = new Set(this.logs.map((l) => l.id));
        const newItems = body.data.filter((l) => !existingIds.has(l.id));

        if (newItems.length > 0) {
          this.logs = [...newItems, ...this.logs].slice(0, this.maxLogs);
          this.renderLogs();
        }
      }
    } catch (err) {
      console.warn('[EventLog] Failed to fetch remote logs:', err);
    }
  }

  appendLog(category, severity, message, details = null) {
    const logItem = {
      id: `client_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: Date.now() / 1000,
      category: category,
      severity: severity || 'INFO',
      message: message,
      details: details,
    };

    this.logs.unshift(logItem);
    if (this.logs.length > this.maxLogs) {
      this.logs.pop();
    }

    this.renderLogs();
  }

  renderLogs() {
    const tableBody = document.getElementById('log-table-body');
    if (!tableBody) return;

    const filtered = this.activeFilter === 'ALL'
      ? this.logs
      : this.logs.filter((l) => l.category === this.activeFilter);

    tableBody.innerHTML = '';

    if (filtered.length === 0) {
      const emptyRow = document.createElement('tr');
      const emptyCell = document.createElement('td');
      emptyCell.colSpan = 4;
      emptyCell.textContent = 'No event logs available.';
      emptyCell.style.color = 'var(--text-dim)';
      emptyCell.style.textAlign = 'center';
      emptyRow.appendChild(emptyCell);
      tableBody.appendChild(emptyRow);
      return;
    }

    filtered.forEach((log) => {
      const tr = document.createElement('tr');

      // Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'log-time';
      const d = new Date(log.timestamp * 1000);
      tdTime.textContent = d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
      tr.appendChild(tdTime);

      // Category
      const tdCat = document.createElement('td');
      tdCat.className = `log-cat ${log.category}`;
      tdCat.textContent = log.category;
      tr.appendChild(tdCat);

      // Severity
      const tdSev = document.createElement('td');
      const sevSpan = document.createElement('span');
      sevSpan.className = `log-sev sev-${log.severity || 'INFO'}`;
      sevSpan.textContent = log.severity || 'INFO';
      tdSev.appendChild(sevSpan);
      tr.appendChild(tdSev);

      // Message (Safe textContent prevents XSS)
      const tdMsg = document.createElement('td');
      tdMsg.textContent = log.message;
      tr.appendChild(tdMsg);

      tableBody.appendChild(tr);
    });

    if (this.autoScroll) {
      const container = document.getElementById('log-container');
      if (container) {
        container.scrollTop = 0;
      }
    }
  }

  exportLogs() {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(this.logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `dronesec_logs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  destroy() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
    }
  }
}

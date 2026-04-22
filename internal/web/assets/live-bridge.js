(function() {
  'use strict';

  const POLL_INTERVAL = 5000;
  const HEALTH_INTERVAL = 10000;
  const API_BASE = './api';

  async function fetchJSON(path, options) {
    try {
      const res = await fetch(API_BASE + path, options);
      if (!res.ok) return null;
      return await res.json();
    } catch (e) {
      return null;
    }
  }

  function createPanel() {
    const panel = document.createElement('div');
    panel.id = 'waf-live-panel';
    panel.innerHTML = `
      <div style="position:fixed;bottom:16px;right:16px;z-index:9999;width:300px;background:rgba(15,16,22,0.95);border:1px solid #2a2a35;border-radius:12px;padding:16px;font-family:Inter,system-ui,sans-serif;color:#f8f9fa;box-shadow:0 10px 25px rgba(0,0,0,0.4);backdrop-filter:blur(12px);">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
          <div id="waf-health-dot" style="width:8px;height:8px;border-radius:50%;background:#f97316;animation:pulse-live 2s infinite;"></div>
          <span style="font-weight:700;font-size:13px;letter-spacing:0.02em;text-transform:uppercase;">Live WAF Data</span>
          <span id="waf-health-text" style="margin-left:auto;font-size:10px;color:#4a4f60;">checking</span>
        </div>
        <div id="waf-live-metrics" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:12px;color:#a1a5b7;">
          <div><div style="color:#f97316;font-weight:700;font-size:16px;" id="waf-req">-</div>Requests</div>
          <div><div style="color:#ff3333;font-weight:700;font-size:16px;" id="waf-blk">-</div>Blocked</div>
          <div><div style="color:#00d084;font-weight:700;font-size:16px;" id="waf-pass">-</div>Passed</div>
          <div><div style="color:#8b5cf6;font-weight:700;font-size:16px;" id="waf-ips">-</div>Unique IPs</div>
          <div><div style="color:#ef4444;font-weight:700;font-size:16px;" id="waf-err">-</div>Errors</div>
          <div><div style="color:#38bdf8;font-weight:700;font-size:16px;" id="waf-mode-disp">-</div>Mode</div>
        </div>
        <div id="waf-mode-toggle" style="margin-top:10px;display:flex;gap:6px;">
          <button data-mode="active" style="flex:1;padding:4px 6px;font-size:11px;border:1px solid #2a2a35;border-radius:6px;background:#1a1b21;color:#a1a5b7;cursor:pointer;">Active</button>
          <button data-mode="detection" style="flex:1;padding:4px 6px;font-size:11px;border:1px solid #2a2a35;border-radius:6px;background:#1a1b21;color:#a1a5b7;cursor:pointer;">Detection</button>
          <button data-mode="learning" style="flex:1;padding:4px 6px;font-size:11px;border:1px solid #2a2a35;border-radius:6px;background:#1a1b21;color:#a1a5b7;cursor:pointer;">Learning</button>
        </div>
        <div style="margin-top:12px;padding-top:10px;border-top:1px solid #2a2a35;">
          <div style="font-size:11px;font-weight:600;color:#a1a5b7;margin-bottom:6px;">Recent Blocks</div>
          <div id="waf-blocks" style="display:flex;flex-direction:column;gap:6px;font-size:11px;color:#8b8f9e;">
            <div style="color:#4a4f60;">No recent blocks</div>
          </div>
        </div>
        <div style="margin-top:10px;padding-top:8px;border-top:1px solid #2a2a35;font-size:11px;color:#4a4f60;display:flex;justify-content:space-between;">
          <span id="waf-uptime">up: -</span>
        </div>
      </div>
    `;
    document.body.appendChild(panel);

    const toggle = document.getElementById('waf-mode-toggle');
    if (toggle) {
      toggle.addEventListener('click', async function(e) {
        const btn = e.target.closest('button[data-mode]');
        if (!btn) return;
        const mode = btn.getAttribute('data-mode');
        const res = await fetchJSON('/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: mode })
        });
        if (res && res.status === 'ok') {
          updateModeDisplay(res.mode || mode);
        }
      });
    }
  }

  function formatNum(n) {
    if (n == null) return '-';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return n.toString();
  }

  function formatDuration(sec) {
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h';
    return Math.floor(sec / 86400) + 'd';
  }

  function updateModeDisplay(mode) {
    const disp = document.getElementById('waf-mode-disp');
    if (disp) disp.textContent = mode || '-';
    const btns = document.querySelectorAll('#waf-mode-toggle button[data-mode]');
    btns.forEach(function(b) {
      const active = b.getAttribute('data-mode') === mode;
      b.style.borderColor = active ? '#f97316' : '#2a2a35';
      b.style.color = active ? '#f97316' : '#a1a5b7';
    });
  }

  async function updateHealth() {
    const data = await fetchJSON('/health');
    const dot = document.getElementById('waf-health-dot');
    const txt = document.getElementById('waf-health-text');
    if (data && data.status === 'ok') {
      if (dot) { dot.style.background = '#00d084'; dot.style.animation = 'pulse-live 2s infinite'; }
      if (txt) txt.textContent = 'healthy';
      if (data.mode) updateModeDisplay(data.mode);
    } else {
      if (dot) { dot.style.background = '#ef4444'; dot.style.animation = 'none'; }
      if (txt) txt.textContent = 'unhealthy';
    }
  }

  async function updateBlocks() {
    const data = await fetchJSON('/blocks');
    const container = document.getElementById('waf-blocks');
    if (!container) return;
    if (!data || !data.recent || data.recent.length === 0) {
      container.innerHTML = '<div style="color:#4a4f60;">No recent blocks</div>';
      return;
    }
    const items = data.recent.slice(0, 3);
    container.innerHTML = items.map(function(item) {
      const ip = item.ip || item.client_ip || 'unknown';
      const rule = item.rule_id || '-';
      const ts = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '-';
      return '<div style="display:flex;justify-content:space-between;gap:8px;"><span>' + ip + '</span><span style="color:#f97316;">' + rule + '</span><span>' + ts + '</span></div>';
    }).join('');
  }

  async function update() {
    const metrics = await fetchJSON('/metrics');
    const stats = await fetchJSON('/stats');

    if (metrics) {
      const reqEl = document.getElementById('waf-req');
      const blkEl = document.getElementById('waf-blk');
      const passEl = document.getElementById('waf-pass');
      const ipsEl = document.getElementById('waf-ips');
      const errEl = document.getElementById('waf-err');
      if (reqEl) reqEl.textContent = formatNum(metrics.total_requests);
      if (blkEl) blkEl.textContent = formatNum(metrics.blocked_requests);
      if (passEl) passEl.textContent = formatNum(metrics.passed_requests);
      if (ipsEl) ipsEl.textContent = formatNum(metrics.unique_ips);
      if (errEl) errEl.textContent = formatNum(metrics.errors);
    }

    if (stats) {
      const upEl = document.getElementById('waf-uptime');
      if (upEl) upEl.textContent = 'up: ' + formatDuration(stats.uptime_sec || 0);
      if (stats.mode) updateModeDisplay(stats.mode);
    }

    await updateBlocks();
  }

  function init() {
    if (document.getElementById('waf-live-panel')) return;
    createPanel();
    update();
    setInterval(update, POLL_INTERVAL);
    updateHealth();
    setInterval(updateHealth, HEALTH_INTERVAL);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

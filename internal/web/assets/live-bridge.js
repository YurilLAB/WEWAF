(function() {
  'use strict';

  const POLL_INTERVAL = 5000;
  const API_BASE = './api';

  async function fetchJSON(path) {
    try {
      const res = await fetch(API_BASE + path);
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
      <div style="position:fixed;bottom:16px;right:16px;z-index:9999;width:280px;background:rgba(15,16,22,0.95);border:1px solid #2a2a35;border-radius:12px;padding:16px;font-family:Inter,system-ui,sans-serif;color:#f8f9fa;box-shadow:0 10px 25px rgba(0,0,0,0.4);backdrop-filter:blur(12px);">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
          <div style="width:8px;height:8px;border-radius:50%;background:#f97316;animation:pulse-live 2s infinite;"></div>
          <span style="font-weight:700;font-size:13px;letter-spacing:0.02em;text-transform:uppercase;">Live WAF Data</span>
        </div>
        <div id="waf-live-metrics" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;color:#a1a5b7;">
          <div><div style="color:#f97316;font-weight:700;font-size:16px;" id="waf-req">-</div>Requests</div>
          <div><div style="color:#ff3333;font-weight:700;font-size:16px;" id="waf-blk">-</div>Blocked</div>
          <div><div style="color:#00d084;font-weight:700;font-size:16px;" id="waf-pass">-</div>Passed</div>
          <div><div style="color:#8b5cf6;font-weight:700;font-size:16px;" id="waf-ips">-</div>Unique IPs</div>
        </div>
        <div style="margin-top:12px;padding-top:10px;border-top:1px solid #2a2a35;font-size:11px;color:#4a4f60;display:flex;justify-content:space-between;">
          <span id="waf-mode">mode: -</span>
          <span id="waf-uptime">up: -</span>
        </div>
      </div>
    `;
    document.body.appendChild(panel);
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

  async function update() {
    const metrics = await fetchJSON('/metrics');
    const stats = await fetchJSON('/stats');

    if (metrics) {
      const reqEl = document.getElementById('waf-req');
      const blkEl = document.getElementById('waf-blk');
      const passEl = document.getElementById('waf-pass');
      const ipsEl = document.getElementById('waf-ips');
      if (reqEl) reqEl.textContent = formatNum(metrics.total_requests);
      if (blkEl) blkEl.textContent = formatNum(metrics.blocked_requests);
      if (passEl) passEl.textContent = formatNum(metrics.passed_requests);
      if (ipsEl) ipsEl.textContent = formatNum(metrics.unique_ips);
    }

    if (stats) {
      const modeEl = document.getElementById('waf-mode');
      const upEl = document.getElementById('waf-uptime');
      if (modeEl) modeEl.textContent = 'mode: ' + (stats.mode || '-');
      if (upEl) upEl.textContent = 'up: ' + formatDuration(stats.uptime_sec || 0);
    }
  }

  function init() {
    if (document.getElementById('waf-live-panel')) return;
    createPanel();
    update();
    setInterval(update, POLL_INTERVAL);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

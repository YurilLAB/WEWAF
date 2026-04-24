import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Cpu, HardDrive, Bell, Shield, Save, RotateCcw, Database, ArrowLeftRight, Network, Lock, Gauge, AlertTriangle } from 'lucide-react';
import { useWAF, type WAFSettings } from '../../store/wafStore';
import { api } from '../../services/api';

export default function SettingsPage() {
  const { state, dispatch } = useWAF();
  const { settings } = state;
  const [form, setForm] = useState({ ...settings });
  const [saved, setSaved] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [meshTestStatus, setMeshTestStatus] = useState<{ text: string; ok: boolean | null }>({ text: '', ok: null });
  const [egressStats, setEgressStats] = useState({ blocked: 0, allowed: 0 });

  // Rule-engine + safety knobs surfaced from /api/config. These aren't
  // part of the WAFSettings store because they're purely backend concerns
  // — we read and write them directly through the admin API.
  const [engineForm, setEngineForm] = useState({
    paranoia_level: 1,
    crs_enabled: true,
    failsafe_mode: 'closed' as 'closed' | 'open',
    shaper_enabled: false,
    shaper_max_rps: 2000,
    shaper_burst: 4000,
  });
  const [engineSaved, setEngineSaved] = useState(false);
  const [engineSaving, setEngineSaving] = useState(false);

  useEffect(() => {
    api.getConfig().then((cfg) => {
      if (!cfg) return;
      // Seed the rule-engine/safety form from the live config.
      const pl = (cfg as Record<string, unknown>).paranoia_level;
      const crs = (cfg as Record<string, unknown>).crs_enabled;
      const fsm = (cfg as Record<string, unknown>).failsafe_mode;
      const se = (cfg as Record<string, unknown>).shaper_enabled;
      const smr = (cfg as Record<string, unknown>).shaper_max_rps;
      const sb = (cfg as Record<string, unknown>).shaper_burst;
      setEngineForm((prev) => ({
        paranoia_level: typeof pl === 'number' ? pl : prev.paranoia_level,
        crs_enabled: typeof crs === 'boolean' ? crs : prev.crs_enabled,
        failsafe_mode: fsm === 'open' || fsm === 'closed' ? fsm : prev.failsafe_mode,
        shaper_enabled: typeof se === 'boolean' ? se : prev.shaper_enabled,
        shaper_max_rps: typeof smr === 'number' && smr > 0 ? smr : prev.shaper_max_rps,
        shaper_burst: typeof sb === 'number' && sb > 0 ? sb : prev.shaper_burst,
      }));
      const updates: Partial<WAFSettings> = {};
      if (cfg.history_rotate_hours) updates.historyRotateHours = cfg.history_rotate_hours;
      if (typeof cfg.egress_enabled === 'boolean') updates.egressEnabled = cfg.egress_enabled;
      if (typeof cfg.egress_addr === 'string') updates.egressAddr = cfg.egress_addr;
      if (Array.isArray(cfg.egress_allowlist)) updates.egressAllowlist = cfg.egress_allowlist.join(', ');
      if (typeof cfg.egress_block_private_ips === 'boolean') updates.egressBlockPrivateIPs = cfg.egress_block_private_ips;
      if (typeof cfg.mesh_enabled === 'boolean') updates.meshEnabled = cfg.mesh_enabled;
      if (Array.isArray(cfg.mesh_peers)) updates.meshPeers = cfg.mesh_peers.join(', ');
      if (typeof cfg.mesh_gossip_interval_sec === 'number') updates.meshGossipIntervalSec = cfg.mesh_gossip_interval_sec;
      if (typeof cfg.mesh_sync_timeout_sec === 'number') updates.meshSyncTimeoutSec = cfg.mesh_sync_timeout_sec;
      if (typeof cfg.mesh_api_key === 'string') updates.meshAPIKey = cfg.mesh_api_key;
      if (typeof cfg.security_headers_enabled === 'boolean') updates.securityHeadersEnabled = cfg.security_headers_enabled;
      if (Object.keys(updates).length > 0) {
        setForm((prev) => ({ ...prev, ...updates }));
        dispatch({ type: 'UPDATE_SETTINGS', payload: updates });
      }
    });
  }, [dispatch]);

  useEffect(() => {
    api.getMeshStatus().then((status) => {
      if (status) {
        dispatch({
          type: 'SET_MESH_STATUS',
          payload: {
            enabled: status.enabled,
            peers: status.peers || [],
            lastSync: status.last_sync || '',
            peerCount: status.peer_count || 0,
          },
        });
      }
    });
  }, [dispatch]);

  useEffect(() => {
    const poll = async () => {
      const metrics = await api.getMetrics();
      if (metrics) {
        setEgressStats({
          blocked: metrics.egress_blocked ?? 0,
          allowed: metrics.egress_allowed ?? 0,
        });
      }
    };
    poll();
    const id = setInterval(poll, 10000);
    return () => clearInterval(id);
  }, []);

  const handleSave = async () => {
    setBackendError(null);
    // Update local store
    dispatch({ type: 'SET_SETTINGS', payload: { ...form } });
    // Sync history rotation to backend
    try {
      const res = await api.updateConfig({
        history_rotate_hours: form.historyRotateHours,
        egress_enabled: form.egressEnabled,
        egress_addr: form.egressAddr,
        egress_allowlist: form.egressAllowlist.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        egress_block_private_ips: form.egressBlockPrivateIPs,
        mesh_enabled: form.meshEnabled,
        mesh_peers: form.meshPeers.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        mesh_gossip_interval_sec: form.meshGossipIntervalSec,
        mesh_sync_timeout_sec: form.meshSyncTimeoutSec,
        mesh_api_key: form.meshAPIKey,
        security_headers_enabled: form.securityHeadersEnabled,
      });
      if (res) {
        dispatch({ type: 'UPDATE_SETTINGS', payload: { ...form } });
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setBackendError('Failed to sync settings to backend.');
    }
  };

  const handleReset = () => {
    setForm({ ...settings });
    setBackendError(null);
    setMeshTestStatus({ text: '', ok: null });
  };

  const saveEngine = async () => {
    setEngineSaving(true);
    const res = await api.updateConfig({
      // These pass through the admin /api/config POST accept list.
      paranoia_level: engineForm.paranoia_level,
      crs_enabled: engineForm.crs_enabled,
      failsafe_mode: engineForm.failsafe_mode,
      shaper_enabled: engineForm.shaper_enabled,
      shaper_max_rps: engineForm.shaper_max_rps,
      shaper_burst: engineForm.shaper_burst,
    } as Parameters<typeof api.updateConfig>[0]);
    setEngineSaving(false);
    if (res) {
      setEngineSaved(true);
      setTimeout(() => setEngineSaved(false), 1500);
    }
  };

  const handleTestPeer = async () => {
    const peers = form.meshPeers.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    if (peers.length === 0) {
      setMeshTestStatus({ text: 'No peers configured.', ok: false });
      return;
    }
    setMeshTestStatus({ text: 'Testing...', ok: null });
    const res = await api.syncMeshPeer(peers[0], form.meshAPIKey);
    if (res) {
      setMeshTestStatus({ text: 'Connection successful!', ok: true });
    } else {
      setMeshTestStatus({ text: 'Connection failed.', ok: false });
    }
  };

  return (
    <div className="space-y-4 lg:space-y-6 max-w-4xl">
      <p className="text-waf-dim text-xs lg:text-sm">Configure WAF settings including resource limits, logging, and alerting.</p>

      {/* Rule engine + safety */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <Gauge className="w-4 h-4 text-waf-orange" /> Rule Engine &amp; Safety
        </h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Paranoia Level</label>
            <div className="flex gap-2">
              {[1, 2, 3, 4].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setEngineForm((f) => ({ ...f, paranoia_level: lvl }))}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    engineForm.paranoia_level === lvl
                      ? 'bg-waf-orange text-white'
                      : 'bg-waf-elevated text-waf-muted hover:text-waf-text border border-waf-border'
                  }`}
                >
                  PL{lvl}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-waf-dim mt-1">
              PL1 is the base rule set (lowest false-positive risk). Each level adds more
              aggressive rules. Start at PL1 and ratchet up after running in detection mode.
            </p>
          </div>

          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input
              type="checkbox" checked={engineForm.crs_enabled}
              onChange={(e) => setEngineForm((f) => ({ ...f, crs_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange"
            />
            <div>
              <div className="text-xs text-waf-text font-medium">OWASP Core Rule Set</div>
              <p className="text-[10px] text-waf-dim">
                Load the full CRS pack alongside the native WEWAF signatures. Disable to run with
                native rules only.
              </p>
            </div>
          </label>

          <div>
            <label className="text-xs text-waf-muted mb-2 block flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Failsafe mode on engine panic
            </label>
            <div className="flex gap-2">
              {(['closed', 'open'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setEngineForm((f) => ({ ...f, failsafe_mode: m }))}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    engineForm.failsafe_mode === m
                      ? (m === 'closed' ? 'bg-emerald-500 text-white' : 'bg-amber-500 text-white')
                      : 'bg-waf-elevated text-waf-muted hover:text-waf-text border border-waf-border'
                  }`}
                >
                  {m === 'closed' ? 'Fail closed (503)' : 'Fail open (pass)'}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-waf-dim mt-1">
              Controls what happens if the engine panics: fail-closed returns 503 so the client
              retries; fail-open forwards the request unfiltered with an <span className="font-mono">X-WAF-Failsafe</span> response header.
            </p>
          </div>

          <div className="pt-3 border-t border-waf-border/50 space-y-3">
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox" checked={engineForm.shaper_enabled}
                onChange={(e) => setEngineForm((f) => ({ ...f, shaper_enabled: e.target.checked }))}
                className="mt-0.5 accent-waf-orange"
              />
              <div>
                <div className="text-xs text-waf-text font-medium">Pre-WAF traffic shaper</div>
                <p className="text-[10px] text-waf-dim">
                  Admission-control token bucket running before rule evaluation. When enabled,
                  the shaper auto-tightens to 20% of its base rate while the DDoS detector
                  reports under-attack, protecting the WAF's own resources under load.
                </p>
              </div>
            </label>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-waf-muted mb-1 block">Max RPS</label>
                <input
                  type="number" min={10} max={100000}
                  disabled={!engineForm.shaper_enabled}
                  value={engineForm.shaper_max_rps}
                  onChange={(e) => setEngineForm((f) => ({ ...f, shaper_max_rps: parseInt(e.target.value) || 2000 }))}
                  className="w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1.5 text-xs text-waf-text font-mono focus:outline-none focus:border-waf-orange disabled:opacity-40"
                />
              </div>
              <div>
                <label className="text-[10px] text-waf-muted mb-1 block">Burst</label>
                <input
                  type="number" min={10} max={200000}
                  disabled={!engineForm.shaper_enabled}
                  value={engineForm.shaper_burst}
                  onChange={(e) => setEngineForm((f) => ({ ...f, shaper_burst: parseInt(e.target.value) || 4000 }))}
                  className="w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1.5 text-xs text-waf-text font-mono focus:outline-none focus:border-waf-orange disabled:opacity-40"
                />
              </div>
            </div>
            <p className="text-[10px] text-waf-dim">
              Set Max RPS above your traffic's realistic peak — the shaper's job is to cap
              catastrophic floods, not to enforce QoS. Typical starting point: 2× observed
              peak during the last seven days.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={saveEngine} disabled={engineSaving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
              <Save className="w-4 h-4" /> {engineSaved ? 'Saved' : 'Save engine settings'}
            </button>
          </div>
        </div>
      </motion.div>

      {/* Resource Management */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Cpu className="w-4 h-4 text-waf-orange" /> Resource Management</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Resource Mode</label>
            <div className="flex gap-2">
              {(['auto', 'manual'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setForm({ ...form, resourceMode: mode })}
                  className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
                    form.resourceMode === mode ? 'bg-waf-orange text-white' : 'bg-waf-elevated text-waf-muted hover:bg-waf-border'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
            <p className="text-waf-dim text-xs mt-2">
              {form.resourceMode === 'auto'
                ? 'WAF will automatically use all available system resources.'
                : 'Manually configure the resource limits for the WAF.'}
            </p>
          </div>

          {form.resourceMode === 'manual' && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">CPU Limit (%)</label>
                  <input
                    type="range" min={10} max={100} value={form.cpuLimit}
                    onChange={(e) => setForm({ ...form, cpuLimit: parseInt(e.target.value) })}
                    className="w-full accent-waf-orange"
                  />
                  <div className="flex justify-between text-xs text-waf-dim mt-1">
                    <span>10%</span>
                    <span className="text-waf-orange font-bold">{form.cpuLimit}%</span>
                    <span>100%</span>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Memory Limit (%)</label>
                  <input
                    type="range" min={10} max={100} value={form.memoryLimit}
                    onChange={(e) => setForm({ ...form, memoryLimit: parseInt(e.target.value) })}
                    className="w-full accent-waf-orange"
                  />
                  <div className="flex justify-between text-xs text-waf-dim mt-1">
                    <span>10%</span>
                    <span className="text-waf-orange font-bold">{form.memoryLimit}%</span>
                    <span>100%</span>
                  </div>
                </div>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Worker Threads</label>
                <input
                  type="number" min={1} max={64} value={form.workerThreads}
                  onChange={(e) => setForm({ ...form, workerThreads: parseInt(e.target.value) || 4 })}
                  className="w-32 bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
                />
                <p className="text-waf-dim text-xs mt-1">Number of worker threads processing incoming requests.</p>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Block Mode */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-waf-orange" /> Security Mode</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Block Mode</label>
            <div className="flex flex-wrap gap-2">
              {([
                { value: 'aggressive', label: 'Aggressive', desc: 'Block all suspicious traffic' },
                { value: 'standard', label: 'Standard', desc: 'Balanced protection' },
                { value: 'passive', label: 'Passive', desc: 'Log only, no blocking' },
              ] as const).map((mode) => (
                <button
                  key={mode.value}
                  onClick={() => setForm({ ...form, blockMode: mode.value })}
                  className={`flex flex-col items-start px-4 py-3 rounded-lg text-left transition-colors min-w-[120px] ${
                    form.blockMode === mode.value ? 'bg-waf-orange/10 border border-waf-orange/30' : 'bg-waf-elevated border border-waf-border hover:bg-waf-border'
                  }`}
                >
                  <span className={`text-sm font-medium ${form.blockMode === mode.value ? 'text-waf-orange' : 'text-waf-text'}`}>{mode.label}</span>
                  <span className="text-[10px] text-waf-dim mt-0.5">{mode.desc}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.challengeSuspicious} onChange={(e) => setForm({ ...form, challengeSuspicious: e.target.checked })} className="rounded border-waf-border" />
              Challenge suspicious requests
            </label>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.autoUpdateRules} onChange={(e) => setForm({ ...form, autoUpdateRules: e.target.checked })} className="rounded border-waf-border" />
              Auto-update WAF rules
            </label>
          </div>
        </div>
      </motion.div>

      {/* Logging */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><HardDrive className="w-4 h-4 text-waf-amber" /> Logging</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Log Level</label>
            <select value={form.logLevel} onChange={(e) => setForm({ ...form, logLevel: e.target.value as any })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Log Retention (days)</label>
            <input type="number" min={1} max={365} value={form.logRetention} onChange={(e) => setForm({ ...form, logRetention: parseInt(e.target.value) || 30 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
        </div>
      </motion.div>

      {/* History & Database */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Database className="w-4 h-4 text-waf-orange" /> History &amp; Database</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Database Rotation (hours)</label>
            <input
              type="range"
              min={1}
              max={720}
              step={1}
              value={form.historyRotateHours}
              onChange={(e) => setForm({ ...form, historyRotateHours: parseInt(e.target.value) || 168 })}
              className="w-full accent-waf-orange"
            />
            <div className="flex justify-between text-xs text-waf-dim mt-1">
              <span>1h</span>
              <span className="text-waf-orange font-bold">{form.historyRotateHours}h ({(form.historyRotateHours / 24).toFixed(0)} days)</span>
              <span>720h (30d)</span>
            </div>
            <p className="text-waf-dim text-[10px] mt-1">
              How often the SQLite history database rotates to a new file. Default is 168 hours (1 week).
            </p>
          </div>
        </div>
      </motion.div>

      {/* Egress Proxy */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.28 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><ArrowLeftRight className="w-4 h-4 text-waf-orange" /> Egress Proxy</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.egressEnabled} onChange={(e) => setForm({ ...form, egressEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable egress proxy (inspect outbound traffic from backend)
          </label>
          {form.egressEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Listen Address</label>
                <input type="text" value={form.egressAddr} onChange={(e) => setForm({ ...form, egressAddr: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder=":8081" />
                <p className="text-waf-dim text-[10px] mt-1">Backend app should route outbound HTTP through this address.</p>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Allowlist (comma or newline separated)</label>
                <textarea value={form.egressAllowlist} onChange={(e) => setForm({ ...form, egressAllowlist: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="api.stripe.com, api.sendgrid.com" />
                <p className="text-waf-dim text-[10px] mt-1">If non-empty, only these destinations are allowed. All others are blocked.</p>
              </div>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                <input type="checkbox" checked={form.egressBlockPrivateIPs} onChange={(e) => setForm({ ...form, egressBlockPrivateIPs: e.target.checked })} className="rounded border-waf-border" />
                Block requests to private IPs / localhost (SSRF protection)
              </label>
              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="bg-waf-elevated border border-waf-border rounded-lg p-3">
                  <div className="text-[10px] text-waf-dim uppercase tracking-wider">Blocked</div>
                  <div className="text-lg font-semibold text-waf-text">{egressStats.blocked}</div>
                </div>
                <div className="bg-waf-elevated border border-waf-border rounded-lg p-3">
                  <div className="text-[10px] text-waf-dim uppercase tracking-wider">Allowed</div>
                  <div className="text-lg font-semibold text-waf-text">{egressStats.allowed}</div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Threat Mesh */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.29 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Network className="w-4 h-4 text-waf-orange" /> Threat Mesh</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.meshEnabled} onChange={(e) => setForm({ ...form, meshEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable distributed threat mesh (share bans with peer WAF nodes)
          </label>
          {form.meshEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Peer URLs (comma or newline separated)</label>
                <textarea value={form.meshPeers} onChange={(e) => setForm({ ...form, meshPeers: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="http://waf-node-2:8443, http://waf-node-3:8443" />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Gossip Interval (sec)</label>
                  <input type="number" min={10} max={3600} value={form.meshGossipIntervalSec} onChange={(e) => setForm({ ...form, meshGossipIntervalSec: parseInt(e.target.value) || 60 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Sync Timeout (sec)</label>
                  <input type="number" min={1} max={60} value={form.meshSyncTimeoutSec || 10} onChange={(e) => setForm({ ...form, meshSyncTimeoutSec: parseInt(e.target.value) || 10 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Mesh API Key</label>
                <input type="password" value={form.meshAPIKey} onChange={(e) => setForm({ ...form, meshAPIKey: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="shared secret between peers" />
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleTestPeer}
                  className="px-3 py-1.5 bg-waf-elevated border border-waf-border rounded-lg text-xs text-waf-text hover:bg-waf-border transition-colors"
                >
                  Test Peer Connection
                </button>
                {meshTestStatus.text && (
                  <span className={`text-xs ${meshTestStatus.ok === true ? 'text-emerald-400' : meshTestStatus.ok === false ? 'text-red-400' : 'text-waf-dim'}`}>
                    {meshTestStatus.text}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-waf-dim">
                <Network className="w-3 h-3" />
                <span>Peers: {state.meshStatus.peerCount} | Last sync: {state.meshStatus.lastSync ? new Date(state.meshStatus.lastSync).toLocaleString() : 'Never'}</span>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Response Hardening */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.295 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Lock className="w-4 h-4 text-waf-orange" /> Response Hardening</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.securityHeadersEnabled} onChange={(e) => setForm({ ...form, securityHeadersEnabled: e.target.checked })} className="rounded border-waf-border" />
            Inject security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) and strip Server/X-Powered-By
          </label>
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.cspEnabled} onChange={(e) => setForm({ ...form, cspEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable Content-Security-Policy header
          </label>
          {form.cspEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}>
              <label className="text-xs text-waf-muted mb-1 block">CSP Policy</label>
              <textarea value={form.cspPolicy} onChange={(e) => setForm({ ...form, cspPolicy: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" />
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Alerts */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Bell className="w-4 h-4 text-waf-amber" /> Alerts</h3>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Alert Email</label>
            <input type="email" placeholder="alerts@example.com" value={form.alertEmail} onChange={(e) => setForm({ ...form, alertEmail: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-warning" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Webhook URL</label>
            <input type="url" placeholder="https://hooks.example.com/waf" value={form.alertWebhook} onChange={(e) => setForm({ ...form, alertWebhook: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-warning" />
          </div>
        </div>
      </motion.div>

      {/* Save Buttons */}
      <div className="space-y-3">
        {backendError && (
          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 text-xs text-red-500">
            {backendError}
          </div>
        )}
        <div className="flex gap-3">
          <button onClick={handleSave} className="flex items-center gap-2 px-6 py-2.5 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600 transition-colors">
            <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save Settings'}
          </button>
          <button onClick={handleReset} className="flex items-center gap-2 px-6 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors">
            <RotateCcw className="w-4 h-4" /> Reset
          </button>
        </div>
      </div>
    </div>
  );
}

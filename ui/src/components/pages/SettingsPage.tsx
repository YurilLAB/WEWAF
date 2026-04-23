import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Cpu, HardDrive, Bell, Shield, Save, RotateCcw, Database } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api } from '../../services/api';

export default function SettingsPage() {
  const { state, dispatch } = useWAF();
  const { settings } = state;
  const [form, setForm] = useState({ ...settings });
  const [saved, setSaved] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);

  useEffect(() => {
    api.getConfig().then((cfg) => {
      if (cfg && cfg.history_rotate_hours) {
        setForm((prev) => ({ ...prev, historyRotateHours: cfg.history_rotate_hours }));
        dispatch({ type: 'UPDATE_SETTINGS', payload: { historyRotateHours: cfg.history_rotate_hours } });
      }
    });
  }, [dispatch]);

  const handleSave = async () => {
    setBackendError(null);
    // Update local store
    dispatch({ type: 'SET_SETTINGS', payload: { ...form } });
    // Sync history rotation to backend
    try {
      const res = await api.updateConfig({ history_rotate_hours: form.historyRotateHours });
      if (res && res.history_rotate_hours) {
        dispatch({ type: 'UPDATE_SETTINGS', payload: { historyRotateHours: res.history_rotate_hours } });
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setBackendError('Failed to sync rotation setting to backend.');
    }
  };

  const handleReset = () => {
    setForm({ ...settings });
    setBackendError(null);
  };

  return (
    <div className="space-y-4 lg:space-y-6 max-w-4xl">
      <p className="text-waf-dim text-xs lg:text-sm">Configure WAF settings including resource limits, logging, and alerting.</p>

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

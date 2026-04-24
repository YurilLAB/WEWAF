import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, Server, Link2, RotateCcw, CheckCircle, XCircle,
  Wifi, WifiOff, Zap, Settings, Save, Loader2, Shield,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api } from '../../services/api';

export default function ConnectionManagementPage() {
  const { state, dispatch } = useWAF();
  const { connectionInfo, connectionState } = state;
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [form, setForm] = useState({ ...connectionInfo });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getConnectionConfig().then((data) => {
      if (data) {
        const merged = { ...connectionInfo, ...data };
        dispatch({ type: 'SET_CONNECTION_INFO', payload: merged });
        setForm(merged);
      }
    });
  }, [dispatch, connectionInfo.backend_url]);

  useEffect(() => {
    setForm({ ...connectionInfo });
  }, [connectionInfo]);

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    const startTime = Date.now();
    const MIN_TOTAL_MS = 2400;

    setTestResult({ success: true, message: 'Probing backend via admin API...' });
    try {
      const result = await api.testConnection();
      const elapsed = Date.now() - startTime;
      if (elapsed < MIN_TOTAL_MS) {
        await new Promise((r) => setTimeout(r, MIN_TOTAL_MS - elapsed));
      }
      if (result && result.success) {
        setTestResult({
          success: true,
          message: `Backend reachable — ${result.latency_ms}ms round-trip`,
        });
        dispatch({
          type: 'UPDATE_CONNECTION_INFO',
          payload: { last_ping_ms: result.latency_ms, connected: true },
        });
      } else {
        setTestResult({
          success: false,
          message: result
            ? `Backend unreachable — probe finished in ${result.latency_ms}ms`
            : 'Connection test failed — admin API did not respond',
        });
        dispatch({ type: 'UPDATE_CONNECTION_INFO', payload: { connected: false } });
      }
    } catch {
      setTestResult({ success: false, message: 'Connection test failed — admin API unreachable' });
      dispatch({ type: 'UPDATE_CONNECTION_INFO', payload: { connected: false } });
    }
    setTesting(false);
  };

  const handleSave = async () => {
    // Persist to the backend so the connection.Manager rebuilds its HTTP
    // client with the new timeout / backend URL. Falls back to local-only if
    // the API call fails so the form still reflects the user's intent.
    const result = await api.setConnectionConfig({
      backend_url: form.backend_url,
      listen_addr: form.listen_addr,
      admin_addr: form.admin_addr,
      poll_interval_sec: form.poll_interval_sec,
      retry_attempts: form.retry_attempts,
      timeout_ms: form.timeout_ms,
    });
    const merged = result ? { ...form, ...result } : { ...form };
    dispatch({ type: 'SET_CONNECTION_INFO', payload: merged });
    setForm(merged);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    // Snap back to a safe, documented baseline — the actual defaults the
    // backend expects if no overrides are configured.
    setForm({
      ...form,
      backend_url: 'http://localhost:3000',
      listen_addr: ':8080',
      admin_addr: ':8443',
      poll_interval_sec: 10,
      retry_attempts: 3,
      timeout_ms: 2000,
    });
  };

  const statusConfig = {
    connecting: { color: 'text-amber-500', bg: 'bg-amber-500/10', border: 'border-amber-500/20', icon: Activity, label: 'Connecting' },
    online: { color: 'text-emerald-500', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: Wifi, label: 'Online' },
    offline: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: WifiOff, label: 'Offline' },
    configured: { color: 'text-sky-400', bg: 'bg-sky-400/10', border: 'border-sky-400/20', icon: Shield, label: 'Configured' },
  };
  const cfg = statusConfig[connectionState];
  const StatusIcon = cfg.icon;

  return (
    <div className="space-y-4 lg:space-y-6 max-w-4xl">
      <p className="text-waf-dim text-xs lg:text-sm">Manage the connection between the WEWAF dashboard and the backend engine.</p>

      {/* Status Card */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className={`rounded-xl p-4 border ${cfg.bg} ${cfg.border}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${cfg.bg}`}>
              <StatusIcon className={`w-5 h-5 ${cfg.color}`} />
            </div>
            <div>
              <h3 className={`text-sm font-semibold ${cfg.color}`}>{cfg.label}</h3>
              <p className="text-waf-dim text-xs">
                {connectionState === 'online'
                  ? `Last ping: ${connectionInfo.last_ping_ms > 0 ? `${connectionInfo.last_ping_ms}ms` : 'N/A'}`
                  : connectionState === 'offline'
                  ? 'Backend unreachable'
                  : connectionState === 'configured'
                  ? 'Setup complete, waiting for first connection'
                  : 'Attempting to connect...'}
              </p>
            </div>
          </div>
          <div className={`px-2.5 py-1 rounded-full text-xs font-medium ${cfg.bg} ${cfg.color}`}>
            {connectionState.toUpperCase()}
          </div>
        </div>
      </motion.div>

      {/* Quick Actions */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Zap className="w-4 h-4 text-waf-orange" /> Quick Actions
        </h3>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleTestConnection}
            disabled={testing}
            className="flex items-center gap-2 px-4 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50"
          >
            {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />}
            Test Connection
          </button>
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors"
          >
            <RotateCcw className="w-4 h-4" /> Reset to Defaults
          </button>
        </div>

        {testResult && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`mt-3 flex items-center gap-2 p-3 rounded-lg border ${
              testResult.success
                ? 'bg-emerald-500/5 border-emerald-500/20'
                : 'bg-red-500/5 border-red-500/20'
            }`}
          >
            {testResult.success ? (
              <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-red-500 shrink-0" />
            )}
            <span className={`text-xs sm:text-sm ${testResult.success ? 'text-emerald-500' : 'text-red-500'}`}>
              {testResult.message}
            </span>
          </motion.div>
        )}
      </motion.div>

      {/* Connection Settings */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Settings className="w-4 h-4 text-waf-orange" /> Connection Settings
        </h3>
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Backend URL</label>
              <input
                type="text"
                value={form.backend_url}
                onChange={(e) => setForm({ ...form, backend_url: e.target.value })}
                placeholder="http://localhost:3000"
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">Your origin server where clean traffic is forwarded.</p>
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Listen Address</label>
              <input
                type="text"
                value={form.listen_addr}
                onChange={(e) => setForm({ ...form, listen_addr: e.target.value })}
                placeholder=":8080"
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">Port the WAF listens on for incoming traffic.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Admin Address</label>
              <input
                type="text"
                value={form.admin_addr}
                onChange={(e) => setForm({ ...form, admin_addr: e.target.value })}
                placeholder=":9090"
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">Dashboard/admin panel bind address.</p>
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Timeout (ms)</label>
              <input
                type="number"
                value={form.timeout_ms}
                onChange={(e) => setForm({ ...form, timeout_ms: parseInt(e.target.value) || 5000 })}
                min={1000}
                max={30000}
                step={500}
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">Request timeout in milliseconds.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Poll Interval (seconds)</label>
              <input
                type="number"
                value={form.poll_interval_sec}
                onChange={(e) => setForm({ ...form, poll_interval_sec: parseInt(e.target.value) || 5 })}
                min={1}
                max={60}
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">How often to poll the backend for updates.</p>
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Retry Attempts</label>
              <input
                type="number"
                value={form.retry_attempts}
                onChange={(e) => setForm({ ...form, retry_attempts: parseInt(e.target.value) || 3 })}
                min={1}
                max={10}
                className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange font-mono"
              />
              <p className="text-waf-dim text-[10px] mt-1">Number of retries before marking offline.</p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Connection Diagnostics */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Server className="w-4 h-4 text-waf-orange" /> Connection Diagnostics
        </h3>
        <div className="space-y-2">
          {[
            { label: 'Backend URL', value: form.backend_url, check: connectionState === 'online' || connectionState === 'configured' },
            { label: 'Listen Address', value: form.listen_addr, check: true },
            { label: 'Admin Address', value: form.admin_addr, check: true },
            { label: 'Last Ping', value: connectionInfo.last_ping_ms > 0 ? `${connectionInfo.last_ping_ms}ms` : 'N/A', check: connectionInfo.last_ping_ms > 0 },
            { label: 'Failover Active', value: connectionInfo.failover_active ? 'Yes' : 'No', check: !connectionInfo.failover_active },
          ].map((item, i) => (
            <div key={i} className="flex items-center justify-between py-2 border-b border-waf-border/50 last:border-0">
              <span className="text-xs text-waf-muted">{item.label}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-waf-text font-mono">{item.value}</span>
                {item.check ? (
                  <CheckCircle className="w-3 h-3 text-emerald-500" />
                ) : (
                  <XCircle className="w-3 h-3 text-waf-dim" />
                )}
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Save Buttons */}
      <div className="flex gap-3">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors"
        >
          <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save Settings'}
        </button>
        <button
          onClick={handleReset}
          className="flex items-center gap-2 px-6 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors"
        >
          <RotateCcw className="w-4 h-4" /> Reset
        </button>
      </div>
    </div>
  );
}

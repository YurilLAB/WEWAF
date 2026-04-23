import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Monitor, Cpu, HardDrive, MemoryStick, Network, Activity,
  Server, Clock, Globe, Loader2, RefreshCw, CheckCircle, XCircle,
  Wifi, WifiOff, TrendingUp, History, Zap, HeartPulse,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api } from '../../services/api';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds: number): string {
  if (!seconds) return '0s';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  return parts.join(' ') || '< 1m';
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function timeSince(iso: string): string {
  if (!iso) return 'never';
  const t = new Date(iso).getTime();
  const now = Date.now();
  const diff = now - t;
  if (diff < 0) return 'just now';
  return formatDuration(diff) + ' ago';
}

export default function HostMonitorPage() {
  const { state, dispatch } = useWAF();
  const { hostStats, hostResources, connectionState, sessionHistory } = state;
  const [refreshing, setRefreshing] = useState(false);
  const STEP_DELAY = 1000;

  interface CheckState {
    status: 'idle' | 'running' | 'pass' | 'fail';
    label: string;
  }

  const [checks, setChecks] = useState<Record<string, CheckState>>({
    apiCheck: { status: 'idle', label: 'API Health' },
    pingCheck: { status: 'idle', label: 'Host Stats' },
    statsCheck: { status: 'idle', label: 'System Stats' },
    resourceCheck: { status: 'idle', label: 'Resources' },
  });

  const [clockTick, setClockTick] = useState(0);
  const intervalRef = useRef<number | null>(null);

  // Live clock for uptime display
  useEffect(() => {
    intervalRef.current = window.setInterval(() => setClockTick((t) => t + 1), 1000);
    return () => { if (intervalRef.current) window.clearInterval(intervalRef.current); };
  }, []);

  const runOnlineChecks = async () => {
    setRefreshing(true);
    const startTime = Date.now();
    setChecks({
      apiCheck: { status: 'idle', label: 'API Health' },
      pingCheck: { status: 'idle', label: 'Host Stats' },
      statsCheck: { status: 'idle', label: 'System Stats' },
      resourceCheck: { status: 'idle', label: 'Resources' },
    });
    let anyPassed = false;

    setChecks((prev) => ({ ...prev, apiCheck: { ...prev.apiCheck, status: 'running' } }));
    const t1 = Date.now();
    try {
      const health = await api.getHealth();
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t1), 100)));
      if (health && health.status === 'ok') {
        anyPassed = true;
        setChecks((prev) => ({ ...prev, apiCheck: { ...prev.apiCheck, status: 'pass' } }));
        dispatch({ type: 'SET_HOST_STATS', payload: { ...state.hostStats, online: true } });
      } else {
        setChecks((prev) => ({ ...prev, apiCheck: { ...prev.apiCheck, status: 'fail' } }));
      }
    } catch {
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t1), 100)));
      setChecks((prev) => ({ ...prev, apiCheck: { ...prev.apiCheck, status: 'fail' } }));
    }

    setChecks((prev) => ({ ...prev, statsCheck: { ...prev.statsCheck, status: 'running' } }));
    const t2 = Date.now();
    try {
      const stats = await api.getStats();
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t2), 100)));
      if (stats) {
        anyPassed = true;
        setChecks((prev) => ({ ...prev, statsCheck: { ...prev.statsCheck, status: 'pass' } }));
        dispatch({ type: 'UPDATE_RESOURCE_USAGE', payload: { cpu: stats.cpu_percent || 0, memory: stats.memory_percent || 0, diskIO: stats.disk_io_percent || 0, networkLatency: stats.network_latency_ms || 0 } });
      } else {
        setChecks((prev) => ({ ...prev, statsCheck: { ...prev.statsCheck, status: 'fail' } }));
      }
    } catch {
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t2), 100)));
      setChecks((prev) => ({ ...prev, statsCheck: { ...prev.statsCheck, status: 'fail' } }));
    }

    setChecks((prev) => ({ ...prev, pingCheck: { ...prev.pingCheck, status: 'running' } }));
    const t3 = Date.now();
    try {
      const host = await api.getHostStats();
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t3), 100)));
      if (host) {
        anyPassed = true;
        setChecks((prev) => ({ ...prev, pingCheck: { ...prev.pingCheck, status: 'pass' } }));
        dispatch({ type: 'SET_HOST_STATS', payload: host });
      } else {
        setChecks((prev) => ({ ...prev, pingCheck: { ...prev.pingCheck, status: 'fail' } }));
      }
    } catch {
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t3), 100)));
      setChecks((prev) => ({ ...prev, pingCheck: { ...prev.pingCheck, status: 'fail' } }));
    }

    setChecks((prev) => ({ ...prev, resourceCheck: { ...prev.resourceCheck, status: 'running' } }));
    const t4 = Date.now();
    try {
      const resources = await api.getHostResources();
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t4), 100)));
      if (resources) {
        anyPassed = true;
        setChecks((prev) => ({ ...prev, resourceCheck: { ...prev.resourceCheck, status: 'pass' } }));
        dispatch({ type: 'SET_HOST_RESOURCES', payload: resources });
      } else {
        setChecks((prev) => ({ ...prev, resourceCheck: { ...prev.resourceCheck, status: 'fail' } }));
      }
    } catch {
      await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - t4), 100)));
      setChecks((prev) => ({ ...prev, resourceCheck: { ...prev.resourceCheck, status: 'fail' } }));
    }

    if (!anyPassed) dispatch({ type: 'SET_HOST_STATS', payload: { ...state.hostStats, online: false } });
    const elapsed = Date.now() - startTime;
    if (elapsed < 4000) await new Promise((r) => setTimeout(r, 4000 - elapsed));
    setRefreshing(false);
  };

  useEffect(() => { runOnlineChecks(); }, []);

  const isOnline = hostStats.online;
  const checkCount = Object.values(checks).filter((c) => c.status === 'pass').length;

  // Connection health calculations
  const recentEvents = sessionHistory.connection_events.slice(-20);
  const onlineEvents = recentEvents.filter((e) => e.state === 'online').length;
  const healthScore = recentEvents.length > 0 ? Math.round((onlineEvents / recentEvents.length) * 100) : 0;
  const pings = sessionHistory.ping_history.slice(-20);
  const avgPing = pings.length > 0 ? Math.round(pings.reduce((a, b) => a + b.ping_ms, 0) / pings.length) : 0;
  const uptimeSinceBoot = hostStats.uptime_seconds;
  const onlineSince = sessionHistory.last_online_at ? timeSince(sessionHistory.last_online_at) : 'never';
  const offlineSince = sessionHistory.last_offline_at ? timeSince(sessionHistory.last_offline_at) : 'never';

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-waf-dim text-xs lg:text-sm">Monitor the host machine running the WAF engine. Uses multiple verification methods for reliability.</p>
        <button
          onClick={runOnlineChecks}
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-waf-elevated border border-waf-border rounded-lg text-xs text-waf-muted hover:text-waf-text hover:bg-waf-border transition-colors disabled:opacity-50 shrink-0"
        >
          {refreshing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
          Refresh
        </button>
      </div>

      {/* Online Status Banner */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl p-4 border ${isOnline ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/5 border-red-500/20'}`}
      >
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${isOnline ? 'bg-emerald-500/10' : 'bg-red-500/10'}`}>
            {isOnline ? <Wifi className="w-5 h-5 text-emerald-500" /> : <WifiOff className="w-5 h-5 text-red-500" />}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className={`text-sm font-semibold truncate ${isOnline ? 'text-emerald-500' : 'text-red-500'}`}>
              {isOnline ? 'Host Machine Online' : 'Host Machine Offline'}
            </h3>
            <p className="text-waf-dim text-xs">
              {isOnline
                ? `${checkCount}/4 health checks passed — ${hostStats.hostname} (${hostStats.platform})`
                : 'All health check methods failed. The host may be unreachable.'}
            </p>
          </div>
          <div className={`px-2.5 py-1 rounded-full text-xs font-medium shrink-0 ${isOnline ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
            {isOnline ? 'ONLINE' : 'OFFLINE'}
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3">
          {[
            { key: 'apiCheck', label: 'API Health' },
            { key: 'pingCheck', label: 'Host Stats' },
            { key: 'statsCheck', label: 'System Stats' },
            { key: 'resourceCheck', label: 'Resources' },
          ].map((c) => {
            const check = checks[c.key];
            return (
              <div key={c.key} className="flex items-center gap-1.5 text-xs">
                {check.status === 'running' && <Loader2 className="w-3 h-3 text-waf-orange animate-spin" />}
                {check.status === 'pass' && <CheckCircle className="w-3 h-3 text-emerald-500" />}
                {check.status === 'fail' && <XCircle className="w-3 h-3 text-red-500" />}
                {check.status === 'idle' && <div className="w-3 h-3 rounded-full border border-waf-dim" />}
                <span className={check.status === 'pass' ? 'text-waf-muted' : check.status === 'fail' ? 'text-red-400' : check.status === 'running' ? 'text-waf-orange' : 'text-waf-dim'}>{c.label}</span>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Connection Health */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <HeartPulse className="w-4 h-4 text-waf-orange" /> Connection Health & Communication
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <TrendingUp className="w-3 h-3 text-waf-orange" />
              <span className="text-[10px] text-waf-muted uppercase tracking-wider">Health Score</span>
            </div>
            <p className={`text-xl font-bold ${healthScore > 80 ? 'text-emerald-500' : healthScore > 50 ? 'text-waf-amber' : 'text-red-500'}`}>{healthScore}%</p>
            <p className="text-waf-dim text-[10px]">Last {recentEvents.length} events</p>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <Zap className="w-3 h-3 text-waf-orange" />
              <span className="text-[10px] text-waf-muted uppercase tracking-wider">Avg Ping</span>
            </div>
            <p className="text-xl font-bold text-waf-text">{avgPing > 0 ? `${avgPing}ms` : 'N/A'}</p>
            <p className="text-waf-dim text-[10px]">{pings.length} samples</p>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <Clock className="w-3 h-3 text-waf-orange" />
              <span className="text-[10px] text-waf-muted uppercase tracking-wider">Online For</span>
            </div>
            <p className="text-xl font-bold text-waf-text">{onlineSince}</p>
            <p className="text-waf-dim text-[10px]">Last connection</p>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <History className="w-3 h-3 text-waf-orange" />
              <span className="text-[10px] text-waf-muted uppercase tracking-wider">Last Offline</span>
            </div>
            <p className="text-xl font-bold text-waf-text">{offlineSince}</p>
            <p className="text-waf-dim text-[10px]">Session started {timeSince(sessionHistory.session_start_at)}</p>
          </div>
        </div>

        {/* Ping Sparkline */}
        {pings.length > 1 && (
          <div className="mt-4">
            <p className="text-[10px] text-waf-muted mb-2 flex items-center gap-1.5">
              <Activity className="w-3 h-3" /> Ping History (last {pings.length} samples)
            </p>
            <div className="flex items-end gap-1 h-12">
              {(() => {
                const maxPing = Math.max(...pings.map((p) => p.ping_ms), 1);
                return pings.map((p, i) => (
                  <div
                    key={i}
                    className="flex-1 rounded-sm transition-all"
                    style={{
                      height: `${Math.min((p.ping_ms / maxPing) * 100, 100)}%`,
                      backgroundColor: p.ping_ms < 50 ? '#10b981' : p.ping_ms < 150 ? '#f97316' : '#ef4444',
                      opacity: 0.7 + (i / pings.length) * 0.3,
                    }}
                    title={`${p.ping_ms}ms @ ${new Date(p.timestamp).toLocaleTimeString()}`}
                  />
                ));
              })()}
            </div>
            <div className="flex justify-between text-[10px] text-waf-dim mt-1">
              <span>{new Date(pings[0].timestamp).toLocaleTimeString()}</span>
              <span>{new Date(pings[pings.length - 1].timestamp).toLocaleTimeString()}</span>
            </div>
          </div>
        )}
      </motion.div>

      {/* Connection Event Log */}
      {sessionHistory.connection_events.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-3 flex items-center gap-2">
            <History className="w-4 h-4 text-waf-orange" /> Connection Event Log
          </h3>
          <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
            {sessionHistory.connection_events.slice(-10).reverse().map((evt, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-waf-border/30 last:border-0 text-xs">
                <div className="flex items-center gap-2">
                  {evt.state === 'online' && <Wifi className="w-3 h-3 text-emerald-500" />}
                  {evt.state === 'offline' && <WifiOff className="w-3 h-3 text-red-500" />}
                  {evt.state === 'connecting' && <Loader2 className="w-3 h-3 text-waf-amber animate-spin" />}
                  {evt.state === 'configured' && <CheckCircle className="w-3 h-3 text-sky-400" />}
                  <span className={
                    evt.state === 'online' ? 'text-emerald-500' :
                    evt.state === 'offline' ? 'text-red-500' :
                    evt.state === 'connecting' ? 'text-waf-amber' :
                    'text-sky-400'
                  }>{evt.state.toUpperCase()}</span>
                </div>
                <div className="flex items-center gap-3">
                  {evt.ping_ms > 0 && <span className="text-waf-dim font-mono">{evt.ping_ms}ms</span>}
                  <span className="text-waf-dim">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* System Info Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 lg:gap-4">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Server className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-medium">Hostname</h3>
          </div>
          <p className="text-waf-muted text-lg font-semibold truncate">{hostStats.hostname}</p>
          <p className="text-waf-dim text-xs mt-1">{hostStats.platform} ({hostStats.architecture})</p>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-medium">Uptime</h3>
          </div>
          <p className="text-waf-muted text-lg font-semibold">{formatUptime(hostStats.uptime_seconds)}</p>
          <p className="text-waf-dim text-xs mt-1">Since last system boot</p>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-medium">Runtime</h3>
          </div>
          <p className="text-waf-muted text-lg font-semibold">{hostStats.go_version}</p>
          <p className="text-waf-dim text-xs mt-1">WEWAF {hostStats.waf_version}</p>
        </motion.div>
      </div>

      {/* Total Available Resources */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Monitor className="w-4 h-4 text-waf-orange" /> Total Available Resources
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Cpu className="w-4 h-4 text-waf-amber" />
              <span className="text-xs text-waf-muted">CPU Cores</span>
            </div>
            <p className="text-waf-text text-2xl font-bold">{hostResources.total_cpu_cores || '-'}</p>
            <div className="mt-2 h-1.5 bg-waf-elevated rounded-full overflow-hidden">
              <div className="h-full bg-waf-orange rounded-full transition-all" style={{ width: `${hostResources.total_cpu_cores ? (hostResources.allocated_cpu_cores / hostResources.total_cpu_cores) * 100 : 0}%` }} />
            </div>
            <p className="text-waf-dim text-[10px] mt-1">{hostResources.allocated_cpu_cores} allocated to WAF</p>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-2">
              <MemoryStick className="w-4 h-4 text-waf-amber" />
              <span className="text-xs text-waf-muted">Memory</span>
            </div>
            <p className="text-waf-text text-2xl font-bold">{hostResources.total_memory_mb ? `${hostResources.total_memory_mb} MB` : '-'}</p>
            <div className="mt-2 h-1.5 bg-waf-elevated rounded-full overflow-hidden">
              <div className="h-full bg-waf-orange rounded-full transition-all" style={{ width: `${hostResources.total_memory_mb ? (hostResources.allocated_memory_mb / hostResources.total_memory_mb) * 100 : 0}%` }} />
            </div>
            <p className="text-waf-dim text-[10px] mt-1">{hostResources.allocated_memory_mb} MB allocated to WAF</p>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-2">
              <HardDrive className="w-4 h-4 text-waf-amber" />
              <span className="text-xs text-waf-muted">Disk Storage</span>
            </div>
            <p className="text-waf-text text-2xl font-bold">{hostResources.total_disk_gb ? `${hostResources.total_disk_gb} GB` : '-'}</p>
            <div className="mt-2 h-1.5 bg-waf-elevated rounded-full overflow-hidden">
              <div className="h-full bg-waf-orange rounded-full transition-all" style={{ width: `${hostResources.total_disk_gb ? (hostResources.allocated_disk_gb / hostResources.total_disk_gb) * 100 : 0}%` }} />
            </div>
            <p className="text-waf-dim text-[10px] mt-1">{hostResources.allocated_disk_gb} GB allocated to WAF</p>
          </div>
        </div>
      </motion.div>

      {/* Live Usage */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-waf-orange" /> Real-Time Usage
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-waf-muted">CPU Usage</span>
              <span className="text-xs font-medium text-waf-orange">{hostResources.cpu_usage_percent.toFixed(1)}%</span>
            </div>
            <div className="h-2 bg-waf-border rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all ${hostResources.cpu_usage_percent > 90 ? 'bg-red-500' : hostResources.cpu_usage_percent > 70 ? 'bg-waf-amber' : 'bg-waf-orange'}`} style={{ width: `${Math.min(hostResources.cpu_usage_percent, 100)}%` }} />
            </div>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-waf-muted">Memory Usage</span>
              <span className="text-xs font-medium text-waf-orange">{hostResources.memory_usage_percent.toFixed(1)}%</span>
            </div>
            <div className="h-2 bg-waf-border rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all ${hostResources.memory_usage_percent > 90 ? 'bg-red-500' : hostResources.memory_usage_percent > 70 ? 'bg-waf-amber' : 'bg-waf-orange'}`} style={{ width: `${Math.min(hostResources.memory_usage_percent, 100)}%` }} />
            </div>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-waf-muted">Disk Usage</span>
              <span className="text-xs font-medium text-waf-orange">{hostResources.disk_usage_percent.toFixed(1)}%</span>
            </div>
            <div className="h-2 bg-waf-border rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all ${hostResources.disk_usage_percent > 90 ? 'bg-red-500' : hostResources.disk_usage_percent > 70 ? 'bg-waf-amber' : 'bg-waf-orange'}`} style={{ width: `${Math.min(hostResources.disk_usage_percent, 100)}%` }} />
            </div>
          </div>
        </div>
      </motion.div>

      {/* Load Average & Network */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 lg:gap-4">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Cpu className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-medium">Load Average</h3>
          </div>
          <div className="flex gap-4">
            {hostResources.load_average.map((load, i) => (
              <div key={i} className="text-center flex-1">
                <p className="text-waf-text text-lg font-semibold">{load.toFixed(2)}</p>
                <p className="text-waf-dim text-[10px]">{['1m', '5m', '15m'][i]}</p>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Network className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-medium">Network I/O</h3>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-waf-muted">Sent</span>
              <span className="text-waf-text font-mono">{formatBytes(hostResources.network_io.bytes_sent)}</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-waf-muted">Received</span>
              <span className="text-waf-text font-mono">{formatBytes(hostResources.network_io.bytes_recv)}</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-waf-muted">Packets</span>
              <span className="text-waf-text font-mono">{hostResources.network_io.packets_sent + hostResources.network_io.packets_recv}</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

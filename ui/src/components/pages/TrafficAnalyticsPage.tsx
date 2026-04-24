import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, BarChart3, ArrowUp, ArrowDown, Globe, Clock,
  Ban, ShieldCheck, Bot, Network,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api } from '../../services/api';

export default function TrafficAnalyticsPage() {
  const { state } = useWAF();
  const { trafficStats, requestLogs } = state;
  const [timeRange, setTimeRange] = useState('24h');

  const [egressBlocked, setEgressBlocked] = useState(0);
  const [egressAllowed, setEgressAllowed] = useState(0);
  const [botsDetected, setBotsDetected] = useState(0);
  const [meshStatus, setMeshStatus] = useState<{
    enabled: boolean;
    peerCount: number;
    lastSync: string;
  }>({ enabled: false, peerCount: 0, lastSync: '' });

  // Fetch metrics (includes egress and bot stats)
  useEffect(() => {
    api.getMetrics().then((data) => {
      if (data) {
        setEgressBlocked(data.egress_blocked ?? 0);
        setEgressAllowed(data.egress_allowed ?? 0);
        setBotsDetected(data.bots_detected ?? 0);
      }
    });
  }, []);

  // Fetch and poll mesh status every 10s
  useEffect(() => {
    const fetchMesh = async () => {
      const data = await api.getMeshStatus();
      if (data) {
        setMeshStatus({
          enabled: data.enabled,
          peerCount: data.peer_count ?? 0,
          lastSync: data.last_sync ?? '',
        });
      }
    };
    fetchMesh();
    const id = setInterval(fetchMesh, 10000);
    return () => clearInterval(id);
  }, []);

  const methodBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    requestLogs.forEach((l) => { counts[l.method] = (counts[l.method] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [requestLogs]);

  const statusBreakdown = useMemo(() => {
    const counts: Record<string, number> = { allowed: 0, blocked: 0, challenged: 0 };
    requestLogs.forEach((l) => { counts[l.status] = (counts[l.status] || 0) + 1; });
    return counts;
  }, [requestLogs]);

  const topCountries = useMemo(() => {
    const counts: Record<string, number> = {};
    requestLogs.forEach((l) => { counts[l.country] = (counts[l.country] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [requestLogs]);

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Analyze traffic patterns and performance metrics.</p>
        <select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} className="bg-waf-panel border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text w-full sm:w-auto">
          <option value="1h">Last 1 Hour</option>
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
        </select>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 lg:gap-4">
        <StatCard icon={Activity} label="Total Requests" value={trafficStats.totalRequests} color="text-waf-orange" />
        <StatCard icon={ArrowUp} label="Allowed" value={trafficStats.allowedRequests} color="text-waf-orange" />
        <StatCard icon={ArrowDown} label="Blocked" value={trafficStats.blockedRequests} color="text-red-500" />
        <StatCard icon={Globe} label="Unique IPs" value={trafficStats.uniqueIPs} color="text-waf-amber" />
      </div>

      {/* Egress & Bot Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3 lg:gap-4">
        <StatCard icon={Ban} label="Egress Blocked" value={egressBlocked} color="text-red-500" />
        <StatCard icon={ShieldCheck} label="Egress Allowed" value={egressAllowed} color="text-emerald-500" />
        <StatCard icon={Bot} label="Bots Detected" value={botsDetected} color="text-waf-amber" />
      </div>

      {/* Breakdown Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-5">
        <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><BarChart3 className="w-4 h-4 text-waf-orange" /> HTTP Methods</h3>
          {methodBreakdown.length === 0 ? (
            <p className="text-waf-dim text-sm text-center py-6">No data available yet</p>
          ) : (
            <div className="space-y-2">
              {methodBreakdown.map(([method, count]) => (
                <div key={method} className="flex items-center gap-3">
                  <span className="w-12 text-xs font-medium text-waf-muted uppercase">{method}</span>
                  <div className="flex-1 bg-waf-elevated rounded-full h-4 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.max(5, (count / methodBreakdown[0][1]) * 100)}%` }}
                      transition={{ duration: 0.8, ease: 'easeOut' }}
                      className="h-full bg-waf-orange rounded-full"
                    />
                  </div>
                  <span className="text-xs text-waf-muted tabular-nums w-8 text-right">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Activity className="w-4 h-4 text-waf-orange" /> Request Status</h3>
          <div className="space-y-3">
            {[
              { label: 'Allowed', value: statusBreakdown.allowed, color: 'bg-waf-success' },
              { label: 'Blocked', value: statusBreakdown.blocked, color: 'bg-red-500' },
              { label: 'Challenged', value: statusBreakdown.challenged, color: 'bg-waf-warning' },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${item.color}`} />
                  <span className="text-sm text-waf-muted">{item.label}</span>
                </div>
                <span className="text-sm font-bold text-waf-text tabular-nums">{item.value.toLocaleString()}</span>
              </div>
            ))}
            <div className="mt-2 h-3 bg-waf-elevated rounded-full overflow-hidden flex">
              {trafficStats.totalRequests > 0 && (
                <>
                  <div className="h-full bg-waf-success" style={{ width: `${(statusBreakdown.allowed / trafficStats.totalRequests) * 100}%` }} />
                  <div className="h-full bg-red-500" style={{ width: `${(statusBreakdown.blocked / trafficStats.totalRequests) * 100}%` }} />
                  <div className="h-full bg-waf-warning" style={{ width: `${(statusBreakdown.challenged / trafficStats.totalRequests) * 100}%` }} />
                </>
              )}
            </div>
          </div>
        </div>

        <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Globe className="w-4 h-4 text-waf-amber" /> Top Countries</h3>
          {topCountries.length === 0 ? (
            <p className="text-waf-dim text-sm text-center py-6">No data available yet</p>
          ) : (
            <div className="space-y-2">
              {topCountries.map(([country, count]) => (
                <div key={country} className="flex items-center justify-between py-1.5 border-b border-waf-border/30">
                  <span className="text-sm text-waf-muted">{country}</span>
                  <span className="text-sm font-bold text-waf-text tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Clock className="w-4 h-4 text-waf-amber" /> Response Times</h3>
          {requestLogs.length === 0 ? (
            <p className="text-waf-dim text-sm text-center py-6">No data available yet</p>
          ) : (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-waf-elevated rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-waf-orange">{Math.round(requestLogs.reduce((a, l) => a + l.responseTime, 0) / requestLogs.length)}<span className="text-sm font-normal text-waf-muted">ms</span></p>
                <p className="text-xs text-waf-dim mt-1">Average</p>
              </div>
              <div className="bg-waf-elevated rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-waf-orange">{Math.min(...requestLogs.map((l) => l.responseTime))}<span className="text-sm font-normal text-waf-muted">ms</span></p>
                <p className="text-xs text-waf-dim mt-1">Min</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Mesh Status */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5"
      >
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <Network className="w-4 h-4 text-waf-orange" /> Mesh Status
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-waf-elevated rounded-lg p-3 text-center">
            <p className="text-[10px] text-waf-muted uppercase tracking-wider mb-1">Status</p>
            <p className={`text-xl font-bold ${meshStatus.enabled ? 'text-emerald-500' : 'text-waf-dim'}`}>
              {meshStatus.enabled ? 'Enabled' : 'Disabled'}
            </p>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3 text-center">
            <p className="text-[10px] text-waf-muted uppercase tracking-wider mb-1">Peers</p>
            <p className="text-xl font-bold text-waf-text">{meshStatus.peerCount}</p>
          </div>
          <div className="bg-waf-elevated rounded-lg p-3 text-center">
            <p className="text-[10px] text-waf-muted uppercase tracking-wider mb-1">Last Sync</p>
            <p className="text-xl font-bold text-waf-text">
              {meshStatus.lastSync ? new Date(meshStatus.lastSync).toLocaleString() : 'Never'}
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-waf-muted text-xs">{label}</span>
      </div>
      <p className={`text-xl lg:text-2xl font-bold tabular-nums ${color}`}>{value.toLocaleString()}</p>
    </motion.div>
  );
}

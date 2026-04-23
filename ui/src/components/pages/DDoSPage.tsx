import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Zap, AlertTriangle, CheckCircle, Shield, Globe, Clock,
  TrendingUp, TrendingDown, Activity, Ban, Lock, Server,
  ChevronDown, ChevronUp, Save, RotateCcw, Flame,
  Eye, Radar, Timer, Target,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';

interface AttackPattern {
  type: string;
  count: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  trend: 'rising' | 'falling' | 'stable';
}

export default function DDoSPage() {
  const { state, dispatch } = useWAF();
  const { ddosConfig, securityEvents, trafficStats, settings, wafRules } = state;
  const [editMode, setEditMode] = useState(false);
  const [form, setForm] = useState({ ...ddosConfig });
  const [showMitigationLog, setShowMitigationLog] = useState(false);
  const [saved, setSaved] = useState(false);

  const ddosEvents = securityEvents.filter((e) => e.type === 'ddos' || e.type === 'rate_limit');
  const recentEvents = ddosEvents.slice(0, 10);

  // ---- SMART ANALYSIS ----
  const analysis = useMemo(() => {
    const now = Date.now();
    const hourAgo = now - 3600000;
    const dayAgo = now - 86400000;
    const eventsLastHour = ddosEvents.filter((e) => new Date(e.timestamp).getTime() > hourAgo).length;
    const eventsLastDay = ddosEvents.filter((e) => new Date(e.timestamp).getTime() > dayAgo).length;
    const avgPerHour = eventsLastDay / 24;
    const threatLevel = eventsLastHour > 20 ? 'critical' : eventsLastHour > 10 ? 'high' : eventsLastHour > 5 ? 'medium' : eventsLastHour > 0 ? 'low' : 'none';

    // Source analysis
    const countryCounts: Record<string, number> = {};
    const ipCounts: Record<string, number> = {};
    ddosEvents.forEach((e) => {
      countryCounts[e.country] = (countryCounts[e.country] || 0) + 1;
      ipCounts[e.sourceIP] = (ipCounts[e.sourceIP] || 0) + 1;
    });
    const topCountries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    // Rate analysis
    const currentRate = trafficStats.totalRequests;
    const isOverThreshold = currentRate > ddosConfig.rateThreshold;
    const isBursting = currentRate > ddosConfig.burstThreshold;

    // Mitigation effectiveness
    const blockedEvents = ddosEvents.filter((e) => e.action === 'blocked').length;
    const mitigationRate = ddosEvents.length > 0 ? Math.round((blockedEvents / ddosEvents.length) * 100) : 0;

    return {
      eventsLastHour,
      eventsLastDay,
      avgPerHour,
      threatLevel,
      topCountries,
      topIPs,
      currentRate,
      isOverThreshold,
      isBursting,
      mitigationRate,
    };
  }, [ddosEvents, trafficStats.totalRequests, ddosConfig.rateThreshold, ddosConfig.burstThreshold]);

  const handleSave = () => {
    dispatch({ type: 'SET_DDOS_CONFIG', payload: { ...form } });
    setSaved(true);
    setEditMode(false);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    setForm({ ...ddosConfig });
  };

  const threatConfig = {
    none: { color: 'text-emerald-500', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', label: 'No Threats', desc: 'No DDoS activity detected' },
    low: { color: 'text-waf-orange', bg: 'bg-waf-orange/10', border: 'border-waf-orange/20', label: 'Low Threat', desc: 'Minor probing activity detected' },
    medium: { color: 'text-waf-amber', bg: 'bg-waf-amber/10', border: 'border-waf-amber/20', label: 'Medium Threat', desc: 'Elevated request rate — monitoring closely' },
    high: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'High Threat', desc: 'Significant DDoS indicators — mitigation active' },
    critical: { color: 'text-red-500', bg: 'bg-red-500/15', border: 'border-red-500/30', label: 'CRITICAL', desc: 'Active DDoS attack in progress' },
  };
  const tc = threatConfig[analysis.threatLevel];

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">DDoS protection with intelligent threat detection, rate limiting, and automated mitigation.</p>

      {/* Threat Status Banner */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className={`rounded-xl p-4 border ${tc.bg} ${tc.border}`}>
        <div className="flex items-center gap-3">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${tc.bg}`}>
            <Flame className={`w-6 h-6 ${tc.color}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className={`text-base font-bold ${tc.color}`}>{tc.label}</h3>
              <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${tc.bg} ${tc.color}`}>{settings.mode} MODE</span>
            </div>
            <p className="text-waf-dim text-xs">{tc.desc}</p>
          </div>
          <div className="text-right shrink-0">
            <p className={`text-2xl font-bold ${tc.color}`}>{analysis.eventsLastHour}</p>
            <p className="text-waf-dim text-[10px]">events/hour</p>
          </div>
        </div>
      </motion.div>

      {/* Key Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Protection Level', value: ddosConfig.level, icon: Shield, color: ddosConfig.level === 'emergency' ? 'text-red-500' : ddosConfig.level === 'high' ? 'text-waf-amber' : 'text-waf-orange', format: (v: string) => v.charAt(0).toUpperCase() + v.slice(1) },
          { label: 'Current Rate', value: analysis.currentRate, icon: Activity, color: analysis.isOverThreshold ? 'text-red-500' : 'text-waf-orange', format: (v: number | string) => `${(v as number).toLocaleString()}/s` },
          { label: 'Auto Mitigate', value: ddosConfig.autoMitigate ? 'On' : 'Off', icon: Zap, color: ddosConfig.autoMitigate ? 'text-emerald-500' : 'text-waf-dim', format: (v: string | number) => String(v) },
          { label: 'Mitigation Rate', value: `${analysis.mitigationRate}%`, icon: Target, color: analysis.mitigationRate > 80 ? 'text-emerald-500' : 'text-waf-amber', format: (v: string | number) => String(v) },
        ].map((stat, i) => {
          const Icon = stat.icon;
          return (
            <motion.div key={stat.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }} className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`w-3.5 h-3.5 ${stat.color}`} />
                <span className="text-waf-muted text-[10px]">{stat.label}</span>
              </div>
              <p className={`text-lg font-bold ${stat.color}`}>{stat.format(stat.value as any)}</p>
            </motion.div>
          );
        })}
      </div>

      {/* Rate Visualization */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Radar className="w-4 h-4 text-waf-orange" /> Rate Analysis
        </h3>
        <div className="space-y-4">
          {/* Rate Threshold Bar */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-waf-muted">Current vs Rate Threshold ({ddosConfig.rateThreshold.toLocaleString()}/s)</span>
              <span className={`text-xs font-medium ${analysis.isOverThreshold ? 'text-red-500' : 'text-waf-orange'}`}>
                {analysis.currentRate.toLocaleString()}/s
              </span>
            </div>
            <div className="h-3 bg-waf-elevated rounded-full overflow-hidden relative">
              <div className="absolute top-0 bottom-0 w-0.5 bg-waf-dim z-10" style={{ left: `${Math.min((ddosConfig.rateThreshold / Math.max(analysis.currentRate, ddosConfig.rateThreshold, 1)) * 100, 100)}%` }} />
              <div className={`h-full rounded-full transition-all ${analysis.isOverThreshold ? 'bg-red-500' : 'bg-waf-orange'}`} style={{ width: `${Math.min((analysis.currentRate / Math.max(analysis.currentRate, ddosConfig.rateThreshold, 1)) * 100, 100)}%` }} />
            </div>
            <p className="text-[10px] text-waf-dim mt-1">{analysis.isOverThreshold ? 'EXCEEDING threshold — mitigation triggered' : 'Within normal range'}</p>
          </div>

          {/* Burst Threshold Bar */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-waf-muted">Current vs Burst Threshold ({ddosConfig.burstThreshold.toLocaleString()})</span>
              <span className={`text-xs font-medium ${analysis.isBursting ? 'text-red-500' : 'text-waf-orange'}`}>
                {analysis.currentRate.toLocaleString()}
              </span>
            </div>
            <div className="h-3 bg-waf-elevated rounded-full overflow-hidden relative">
              <div className="absolute top-0 bottom-0 w-0.5 bg-waf-dim z-10" style={{ left: `${Math.min((ddosConfig.burstThreshold / Math.max(analysis.currentRate, ddosConfig.burstThreshold, 1)) * 100, 100)}%` }} />
              <div className={`h-full rounded-full transition-all ${analysis.isBursting ? 'bg-red-500' : 'bg-waf-amber'}`} style={{ width: `${Math.min((analysis.currentRate / Math.max(analysis.currentRate, ddosConfig.burstThreshold, 1)) * 100, 100)}%` }} />
            </div>
            <p className="text-[10px] text-waf-dim mt-1">{analysis.isBursting ? 'BURST detected — emergency rules may apply' : 'Normal burst levels'}</p>
          </div>
        </div>
      </motion.div>

      {/* Attack Source Intelligence */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Top Attacker Countries */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-waf-orange" /> Top Attacker Sources
          </h3>
          {analysis.topCountries.length === 0 ? (
            <div className="text-center py-6">
              <Shield className="w-6 h-6 text-waf-dim mx-auto mb-2 opacity-40" />
              <p className="text-waf-dim text-xs">No DDoS source data collected yet</p>
            </div>
          ) : (
            <div className="space-y-3">
              {analysis.topCountries.map(([country, count], i) => {
                const max = analysis.topCountries[0][1];
                return (
                  <div key={country} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-waf-elevated flex items-center justify-center text-[10px] text-waf-muted">{i + 1}</span>
                        <span className="text-waf-muted">{country}</span>
                      </div>
                      <span className="text-waf-text font-medium">{count}</span>
                    </div>
                    <div className="h-1.5 bg-waf-elevated rounded-full overflow-hidden">
                      <motion.div initial={{ width: 0 }} animate={{ width: `${(count / max) * 100}%` }} className="h-full bg-red-500 rounded-full" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>

        {/* Top Attacker IPs */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
            <Ban className="w-4 h-4 text-waf-orange" /> Top Attacker IPs
          </h3>
          {analysis.topIPs.length === 0 ? (
            <div className="text-center py-6">
              <Ban className="w-6 h-6 text-waf-dim mx-auto mb-2 opacity-40" />
              <p className="text-waf-dim text-xs">No attacker IP data yet</p>
            </div>
          ) : (
            <div className="space-y-2">
              {analysis.topIPs.map(([ip, count], i) => (
                <div key={ip} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-waf-elevated flex items-center justify-center text-[10px] text-waf-muted">{i + 1}</span>
                    <span className="text-sm text-waf-text font-mono">{ip}</span>
                  </div>
                  <span className="text-sm font-bold text-red-500">{count}</span>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* DDoS Settings */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-waf-text font-medium text-sm flex items-center gap-2"><Zap className="w-4 h-4 text-waf-amber" /> DDoS Protection Settings</h3>
          <div className="flex gap-2">
            {editMode && (
              <button onClick={handleReset} className="flex items-center gap-1.5 px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border">
                <RotateCcw className="w-3.5 h-3.5" /> Reset
              </button>
            )}
            <button onClick={() => { if (editMode) handleReset(); setEditMode(!editMode); }} className="px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border">
              {editMode ? 'Cancel' : 'Edit'}
            </button>
          </div>
        </div>

        {editMode ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Protection Level</label>
                <select value={form.level} onChange={(e) => setForm({ ...form, level: e.target.value as any })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
                  <option value="low">Low — Minimal false positives</option>
                  <option value="medium">Medium — Balanced</option>
                  <option value="high">High — Aggressive blocking</option>
                  <option value="emergency">Emergency — Maximum protection</option>
                </select>
                <p className="text-waf-dim text-[10px] mt-1">Higher levels may block legitimate traffic during peak times.</p>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Rate Threshold (requests/sec)</label>
                <input type="number" value={form.rateThreshold} onChange={(e) => setForm({ ...form, rateThreshold: parseInt(e.target.value) || 0 })} min={100} max={100000} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                <p className="text-waf-dim text-[10px] mt-1">Requests above this rate trigger rate limiting.</p>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Burst Threshold (requests)</label>
                <input type="number" value={form.burstThreshold} onChange={(e) => setForm({ ...form, burstThreshold: parseInt(e.target.value) || 0 })} min={500} max={500000} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                <p className="text-waf-dim text-[10px] mt-1">Short-term spike limit before emergency mitigation.</p>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Brute Force Window (seconds)</label>
                <input type="number" value={form.bruteForceWindowSec} onChange={(e) => setForm({ ...form, bruteForceWindowSec: parseInt(e.target.value) || 60 })} min={10} max={3600} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                <p className="text-waf-dim text-[10px] mt-1">Time window for counting requests from a single IP.</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer bg-waf-elevated rounded-lg px-3 py-2 border border-waf-border">
                <input type="checkbox" checked={form.autoMitigate} onChange={(e) => setForm({ ...form, autoMitigate: e.target.checked })} className="rounded border-waf-border accent-waf-orange w-4 h-4" />
                <span>Auto Mitigate</span>
                <span className="text-[10px] text-waf-dim ml-2">Automatically trigger rules when thresholds exceeded</span>
              </label>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer bg-waf-elevated rounded-lg px-3 py-2 border border-waf-border">
                <input type="checkbox" checked={form.challengeSuspicious} onChange={(e) => setForm({ ...form, challengeSuspicious: e.target.checked })} className="rounded border-waf-border accent-waf-orange w-4 h-4" />
                <span>Challenge Suspicious</span>
                <span className="text-[10px] text-waf-dim ml-2">Serve CAPTCHA to suspicious IPs before allowing</span>
              </label>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer bg-waf-elevated rounded-lg px-3 py-2 border border-waf-border">
                <input type="checkbox" checked={form.geoBlockHighRisk} onChange={(e) => setForm({ ...form, geoBlockHighRisk: e.target.checked })} className="rounded border-waf-border accent-waf-orange w-4 h-4" />
                <span>Geo-Block High Risk</span>
                <span className="text-[10px] text-waf-dim ml-2">Block traffic from known high-risk regions</span>
              </label>
            </div>
            <div className="flex gap-2">
              <button onClick={handleSave} className="flex items-center gap-2 px-4 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors">
                <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save Settings'}
              </button>
              <button onClick={() => { handleReset(); setEditMode(false); }} className="px-4 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {[
              { label: 'Protection Level', value: ddosConfig.level.charAt(0).toUpperCase() + ddosConfig.level.slice(1), icon: Shield },
              { label: 'Rate Threshold', value: `${ddosConfig.rateThreshold.toLocaleString()} req/s`, icon: Activity },
              { label: 'Burst Threshold', value: ddosConfig.burstThreshold.toLocaleString(), icon: Zap },
              { label: 'Brute Force Window', value: `${ddosConfig.bruteForceWindowSec}s`, icon: Timer },
              { label: 'Auto Mitigate', value: ddosConfig.autoMitigate ? 'Enabled' : 'Disabled', icon: Lock, color: ddosConfig.autoMitigate ? 'text-emerald-500' : 'text-waf-dim' },
              { label: 'Challenge Suspicious', value: ddosConfig.challengeSuspicious ? 'Enabled' : 'Disabled', icon: Eye, color: ddosConfig.challengeSuspicious ? 'text-emerald-500' : 'text-waf-dim' },
              { label: 'Geo-Block High Risk', value: ddosConfig.geoBlockHighRisk ? 'Enabled' : 'Disabled', icon: Globe, color: ddosConfig.geoBlockHighRisk ? 'text-emerald-500' : 'text-waf-dim' },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0 text-sm">
                  <div className="flex items-center gap-2">
                    <Icon className="w-3.5 h-3.5 text-waf-orange" />
                    <span className="text-waf-muted">{item.label}</span>
                  </div>
                  <span className={`font-medium ${(item as any).color || 'text-waf-text'}`}>{item.value}</span>
                </div>
              );
            })}
          </div>
        )}
      </motion.div>

      {/* Recent DDoS Events / Mitigation Log */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-waf-text font-medium text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-waf-amber" /> Recent DDoS Events</h3>
          {recentEvents.length > 0 && (
            <button onClick={() => setShowMitigationLog(!showMitigationLog)} className="flex items-center gap-1 text-xs text-waf-muted hover:text-waf-text">
              {showMitigationLog ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              {showMitigationLog ? 'Hide' : `Show ${recentEvents.length} events`}
            </button>
          )}
        </div>

        {recentEvents.length === 0 ? (
          <div className="text-center py-6">
            <CheckCircle className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
            <p className="text-waf-muted text-sm">No DDoS events in recent history</p>
            <p className="text-waf-dim text-xs mt-1">Your infrastructure is currently safe from volumetric attacks.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {recentEvents.slice(0, showMitigationLog ? 10 : 3).map((event) => (
              <div key={event.id} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0">
                <div className="flex items-center gap-2 min-w-0">
                  <Zap className="w-3.5 h-3.5 text-waf-amber shrink-0" />
                  <span className="text-xs text-waf-muted truncate">{event.sourceIP}</span>
                  <span className="text-[10px] text-waf-dim shrink-0">{event.country}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${
                    event.action === 'blocked' ? 'bg-red-500/10 text-red-500' :
                    event.action === 'challenged' ? 'bg-waf-amber/10 text-waf-amber' :
                    'bg-emerald-500/10 text-emerald-500'
                  }`}>
                    {event.action}
                  </span>
                </div>
                <span className="text-[10px] text-waf-dim shrink-0">{new Date(event.timestamp).toLocaleString()}</span>
              </div>
            ))}
            {!showMitigationLog && recentEvents.length > 3 && (
              <button onClick={() => setShowMitigationLog(true)} className="w-full py-2 text-xs text-waf-muted hover:text-waf-text transition-colors text-center">
                Show {recentEvents.length - 3} more events...
              </button>
            )}
          </div>
        )}
      </motion.div>
    </div>
  );
}

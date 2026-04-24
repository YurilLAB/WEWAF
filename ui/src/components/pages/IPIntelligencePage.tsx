import { useEffect, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldAlert, Target, Loader2, CheckCircle, XCircle, Ban, TrendingUp, Search, ChevronRight,
} from 'lucide-react';
import { api } from '../../services/api';
import type { IPActivityEntry, IPInsights } from '../../services/api';

export default function IPIntelligencePage() {
  const [topIPs, setTopIPs] = useState<IPActivityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [insights, setInsights] = useState<IPInsights | null>(null);
  const [insightsLoading, setInsightsLoading] = useState(false);
  const [threshold, setThreshold] = useState(10);
  const [duration, setDuration] = useState(3600);
  const [mitigating, setMitigating] = useState(false);
  const [mitigationResult, setMitigationResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [searchIP, setSearchIP] = useState('');

  const loadTopIPs = useCallback(async () => {
    setLoading(true);
    const res = await api.getTopIPs(50);
    setTopIPs(res?.ips || []);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadTopIPs();
    const int = setInterval(loadTopIPs, 15000);
    return () => clearInterval(int);
  }, [loadTopIPs]);

  const loadInsights = async (ip: string) => {
    setSelectedIP(ip);
    setInsights(null);
    setInsightsLoading(true);
    const res = await api.getIPInsights(ip);
    setInsights(res);
    setInsightsLoading(false);
  };

  const runAutoMitigate = async () => {
    setMitigating(true);
    setMitigationResult(null);
    const res = await api.autoMitigate(threshold, duration);
    setMitigating(false);
    if (!res) {
      setMitigationResult({ ok: false, msg: 'Request failed' });
      return;
    }
    setMitigationResult({
      ok: true,
      msg: `Scanned ${res.scanned} IPs, banned ${res.banned.length}${res.banned.length > 0 ? ': ' + res.banned.join(', ') : ''}`,
    });
    loadTopIPs();
  };

  const banIP = async (ip: string) => {
    await api.banIP(ip, duration, 'manual ban from IP Intelligence');
    if (selectedIP === ip) loadInsights(ip);
    loadTopIPs();
  };

  const unbanIP = async (ip: string) => {
    await api.unbanIP(ip);
    if (selectedIP === ip) loadInsights(ip);
    loadTopIPs();
  };

  const onSearch = () => {
    const q = searchIP.trim();
    if (!q) return;
    loadInsights(q);
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">
        Drill into any IP's activity and auto-ban attackers that exceed a block threshold.
      </p>

      {/* Auto-Mitigation card */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5"
      >
        <div className="flex items-center gap-2 mb-3">
          <Target className="w-4 h-4 text-waf-orange" />
          <h3 className="text-waf-text text-sm font-semibold">Auto-Mitigation</h3>
        </div>
        <p className="text-waf-dim text-xs mb-4">
          Scan the last hour of activity and ban every IP whose block count exceeds the threshold.
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="text-[10px] text-waf-muted uppercase tracking-wider mb-1 block">
              Block threshold
            </label>
            <input
              type="number"
              min={1}
              value={threshold}
              onChange={(e) => setThreshold(parseInt(e.target.value) || 10)}
              className="w-28 bg-waf-elevated border border-waf-border rounded-md px-3 py-2 text-sm text-waf-text font-mono focus:outline-none focus:border-waf-orange"
            />
          </div>
          <div>
            <label className="text-[10px] text-waf-muted uppercase tracking-wider mb-1 block">
              Ban duration (s)
            </label>
            <input
              type="number"
              min={60}
              value={duration}
              onChange={(e) => setDuration(parseInt(e.target.value) || 3600)}
              className="w-28 bg-waf-elevated border border-waf-border rounded-md px-3 py-2 text-sm text-waf-text font-mono focus:outline-none focus:border-waf-orange"
            />
          </div>
          <button
            onClick={runAutoMitigate}
            disabled={mitigating}
            className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-md text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50"
          >
            {mitigating ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />}
            Run Auto-Mitigation
          </button>
        </div>

        {mitigationResult && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className={`mt-3 flex items-start gap-2 p-2.5 rounded-md border text-xs ${
              mitigationResult.ok ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400' : 'bg-red-500/5 border-red-500/20 text-red-400'
            }`}
          >
            {mitigationResult.ok ? <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" /> : <XCircle className="w-4 h-4 shrink-0 mt-0.5" />}
            <span>{mitigationResult.msg}</span>
          </motion.div>
        )}
      </motion.div>

      {/* IP lookup */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5"
      >
        <div className="flex items-center gap-2 mb-3">
          <Search className="w-4 h-4 text-waf-orange" />
          <h3 className="text-waf-text text-sm font-semibold">Look up an IP</h3>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="1.2.3.4 or ::1"
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onSearch()}
            className="flex-1 bg-waf-elevated border border-waf-border rounded-md px-3 py-2 text-sm text-waf-text font-mono focus:outline-none focus:border-waf-orange"
          />
          <button
            onClick={onSearch}
            className="px-4 py-2 bg-waf-elevated border border-waf-border rounded-md text-sm text-waf-muted hover:text-waf-text hover:bg-waf-border transition-colors"
          >
            Look up
          </button>
        </div>
      </motion.div>

      {/* Two-column: top IPs + insights drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Top attacker IPs */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-3 bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-waf-orange" />
              <h3 className="text-waf-text text-sm font-semibold">Top Attacker IPs (24h)</h3>
            </div>
            {loading && <Loader2 className="w-4 h-4 animate-spin text-waf-dim" />}
          </div>

          {topIPs.length === 0 && !loading ? (
            <div className="text-waf-dim text-xs py-6 text-center">No activity yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-waf-dim uppercase text-[10px] tracking-wider border-b border-waf-border">
                    <th className="text-left py-2 pr-2 font-medium">IP</th>
                    <th className="text-right py-2 px-2 font-medium">Requests</th>
                    <th className="text-right py-2 px-2 font-medium">Blocks</th>
                    <th className="text-right py-2 pl-2 font-medium">Last seen</th>
                    <th className="py-2 pl-2" />
                  </tr>
                </thead>
                <tbody>
                  {topIPs.map((ip) => (
                    <tr
                      key={ip.ip}
                      onClick={() => loadInsights(ip.ip)}
                      className={`border-b border-waf-border/40 hover:bg-waf-elevated/40 cursor-pointer transition-colors ${
                        selectedIP === ip.ip ? 'bg-waf-elevated/60' : ''
                      }`}
                    >
                      <td className="py-2 pr-2 text-waf-text font-mono">{ip.ip}</td>
                      <td className="py-2 px-2 text-right text-waf-muted tabular-nums">{ip.request_count}</td>
                      <td className="py-2 px-2 text-right tabular-nums">
                        <span className={ip.block_count > 0 ? 'text-red-400 font-semibold' : 'text-waf-dim'}>
                          {ip.block_count}
                        </span>
                      </td>
                      <td className="py-2 pl-2 text-right text-waf-dim">
                        {ip.last_seen ? new Date(ip.last_seen).toLocaleTimeString() : '—'}
                      </td>
                      <td className="py-2 pl-2 text-right">
                        <ChevronRight className="w-3.5 h-3.5 text-waf-dim inline" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>

        {/* Insights drawer */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="lg:col-span-2 bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5"
        >
          <h3 className="text-waf-text text-sm font-semibold mb-3">IP Insights</h3>
          {!selectedIP ? (
            <div className="text-waf-dim text-xs py-6 text-center">Select an IP to see details.</div>
          ) : insightsLoading || !insights ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="w-4 h-4 animate-spin text-waf-dim" />
            </div>
          ) : (
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-waf-text font-mono text-sm">{insights.ip}</span>
                {insights.banned ? (
                  <button
                    onClick={() => unbanIP(insights.ip)}
                    className="px-2 py-1 rounded-md text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors"
                  >
                    Unban
                  </button>
                ) : (
                  <button
                    onClick={() => banIP(insights.ip)}
                    className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors"
                  >
                    <Ban className="w-3 h-3" /> Ban
                  </button>
                )}
              </div>

              <div className="grid grid-cols-2 gap-2">
                <Stat label="Requests" value={insights.activity.request_count || 0} />
                <Stat label="Blocks" value={insights.activity.block_count || 0} accent="red" />
              </div>

              {insights.banned && insights.ban && (
                <div className="p-2 rounded-md bg-red-500/5 border border-red-500/20">
                  <div className="text-red-400 font-semibold text-[10px] uppercase tracking-wider mb-1">Currently banned</div>
                  <div className="text-waf-muted">{insights.ban.reason}</div>
                  <div className="text-waf-dim text-[10px]">Expires: {new Date(insights.ban.expires_at).toLocaleString()}</div>
                </div>
              )}

              {Object.keys(insights.categories).length > 0 && (
                <div>
                  <div className="text-[10px] text-waf-muted uppercase tracking-wider mb-1">Attack categories</div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(insights.categories).map(([cat, count]) => (
                      <span key={cat} className="px-2 py-0.5 rounded-md text-[10px] bg-waf-elevated text-waf-muted border border-waf-border">
                        {cat} <span className="text-waf-orange font-semibold">{count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {insights.recent_blocks.length > 0 && (
                <div>
                  <div className="text-[10px] text-waf-muted uppercase tracking-wider mb-1">Recent blocks</div>
                  <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                    {insights.recent_blocks.slice(-15).reverse().map((b, i) => (
                      <div key={i} className="p-1.5 rounded-md bg-waf-elevated/50 border border-waf-border/40">
                        <div className="flex items-center gap-1.5">
                          <span className="text-red-400 text-[10px]">{b.rule_id}</span>
                          <span className="text-waf-muted font-mono text-[10px] truncate">{b.method} {b.path}</span>
                        </div>
                        <div className="text-waf-dim text-[9px]">{new Date(b.timestamp).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: 'red' }) {
  return (
    <div className="p-2 rounded-md bg-waf-elevated border border-waf-border">
      <div className="text-[10px] text-waf-dim uppercase tracking-wider">{label}</div>
      <div className={`text-lg font-bold tabular-nums ${accent === 'red' ? 'text-red-400' : 'text-waf-text'}`}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

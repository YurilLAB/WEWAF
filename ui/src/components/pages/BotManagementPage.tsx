import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Plus, Trash2, Search, Bot, ToggleLeft, ToggleRight, Shield, AlertTriangle, Ban, CheckCircle } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api, startPolling } from '../../services/api';
import type { BotRule } from '../../store/wafStore';
import type { BlockRecord, MetricsResponse } from '../../services/api';

const categoryLabels: Record<string, string> = {
  search_engine: 'Search Engine', monitoring: 'Monitoring', scraping: 'Scraping',
  spam: 'Spam', credential_stuffing: 'Credential Stuffing', custom: 'Custom',
};

export default function BotManagementPage() {
  const { state, dispatch } = useWAF();
  const { botRules } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState('');
  const [form, setForm] = useState({ name: '', botName: '', category: 'custom' as BotRule['category'], action: 'block' as 'allow' | 'block' | 'challenge' });

  // Real backend data
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [botBlocks, setBotBlocks] = useState<BlockRecord[]>([]);

  const fetchData = async () => {
    const m = await api.getMetrics();
    if (m) setMetrics(m);

    const b = await api.getBlocks();
    if (b?.recent) {
      const filtered = b.recent.filter((r) => r.rule_id.toUpperCase().includes('BOT'));
      setBotBlocks(filtered);
    }
  };

  useEffect(() => {
    fetchData();
    const stop = startPolling(fetchData, 5000);
    return () => stop();
  }, []);

  const totalBotsDetected = metrics?.bots_detected || 0;
  const blockedBots = botBlocks.length;
  const allowedBots = Math.max(0, totalBotsDetected - blockedBots);

  const handleAdd = () => {
    if (!form.name.trim() || !form.botName.trim()) return;
    const rule: BotRule = {
      id: Date.now().toString(),
      name: form.name.trim(),
      botName: form.botName.trim(),
      category: form.category,
      action: form.action,
      enabled: true,
      hits: 0,
    };
    dispatch({ type: 'SET_BOT_RULES', payload: [...botRules, rule] });
    setForm({ name: '', botName: '', category: 'custom', action: 'block' });
    setShowAdd(false);
  };

  const toggleRule = (rule: BotRule) => {
    dispatch({ type: 'UPDATE_BOT_RULE', payload: { ...rule, enabled: !rule.enabled } });
  };

  const deleteRule = (id: string) => {
    dispatch({ type: 'SET_BOT_RULES', payload: botRules.filter((r) => r.id !== id) });
  };

  const filteredRules = botRules.filter((r) =>
    !search || r.name.toLowerCase().includes(search.toLowerCase()) || r.botName.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4 lg:space-y-6">
      <div>
        <h1 className="text-waf-text text-xl font-bold">Bot Management</h1>
        <p className="text-waf-dim text-xs lg:text-sm mt-1">Monitor bot traffic and manage bot detection rules.</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        <StatCard icon={Bot} label="Total Bots Detected" value={totalBotsDetected} color="text-waf-orange" />
        <StatCard icon={Ban} label="Blocked Bots" value={blockedBots} color="text-red-500" />
        <StatCard icon={CheckCircle} label="Allowed Bots" value={allowedBots} color="text-waf-success" />
      </div>

      {/* Recent Bot Detections */}
      <div>
        <h2 className="text-waf-text font-medium text-sm mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-waf-amber" /> Recent Bot Detections
        </h2>
        {botBlocks.length === 0 ? (
          <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
            <Shield className="w-10 h-10 text-waf-dim mx-auto mb-3" />
            <p className="text-waf-muted font-medium">No recent bot detections</p>
            <p className="text-waf-dim text-xs mt-1">Blocked bot events will appear here when detected.</p>
          </div>
        ) : (
          <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3">IP</th>
                    <th className="px-4 py-3 hidden sm:table-cell">Method</th>
                    <th className="px-4 py-3 hidden lg:table-cell">Path</th>
                    <th className="px-4 py-3">Rule</th>
                    <th className="px-4 py-3 hidden md:table-cell">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {botBlocks.map((block, i) => (
                    <motion.tr
                      key={`${block.timestamp}-${block.ip}-${i}`}
                      layout
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors"
                    >
                      <td className="px-4 py-3 text-xs text-waf-dim">{new Date(block.timestamp).toLocaleTimeString()}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted font-mono">{block.ip}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden sm:table-cell">
                        <span className="px-1.5 py-0.5 bg-waf-elevated text-waf-orange text-xs font-medium rounded">{block.method}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden lg:table-cell truncate max-w-[200px]">{block.path}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-waf-orange/10 text-waf-amber">{block.rule_id}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden md:table-cell">{block.score}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Bot Rules Management */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h2 className="text-waf-text font-medium text-sm flex items-center gap-2">
          <Bot className="w-4 h-4 text-waf-orange" /> Bot Rules
        </h2>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
            <input type="text" placeholder="Search bot rules..." value={search} onChange={(e) => setSearch(e.target.value)} className="w-full bg-waf-panel border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
            <Plus className="w-4 h-4" /> Add Rule
          </button>
        </div>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">New Bot Rule</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input type="text" placeholder="Rule name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Bot user-agent name" value={form.botName} onChange={(e) => setForm({ ...form, botName: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              {Object.entries(categoryLabels).map(([k, v]) => (<option key={k} value={k}>{v}</option>))}
            </select>
            <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="allow">Allow</option>
              <option value="block">Block</option>
              <option value="challenge">Challenge</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Add Rule</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      <div className="space-y-3">
        {filteredRules.map((rule) => (
          <motion.div key={rule.id} layout className="bg-waf-panel border border-waf-border rounded-xl p-4">
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <Bot className="w-4 h-4 text-waf-amber" />
                  <span className="text-waf-text font-medium text-sm">{rule.name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-waf-orange/10 text-waf-amber">{categoryLabels[rule.category]}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${rule.enabled ? 'bg-waf-success/10 text-waf-orange' : 'bg-waf-dim/10 text-waf-dim'}`}>{rule.enabled ? 'Active' : 'Disabled'}</span>
                </div>
                <div className="flex items-center gap-4 mt-1 text-xs text-waf-muted">
                  <span>Bot: {rule.botName}</span>
                  <span className={rule.action === 'block' ? 'text-red-500' : rule.action === 'allow' ? 'text-waf-orange' : 'text-waf-amber'}>Action: {rule.action}</span>
                  <span className="text-waf-orange font-bold">{rule.hits} hits</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => toggleRule(rule)} className="text-waf-muted hover:text-waf-text">
                  {rule.enabled ? <ToggleRight className="w-6 h-6 text-waf-orange" /> : <ToggleLeft className="w-6 h-6 text-waf-dim" />}
                </button>
                <button onClick={() => deleteRule(rule.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
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

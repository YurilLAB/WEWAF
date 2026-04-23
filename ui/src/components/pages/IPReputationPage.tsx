import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { UserX, Plus, Trash2, Search, Shield, AlertTriangle, Globe } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { IPReputationEntry } from '../../store/wafStore';
import { api } from '../../services/api';

const reputationColors: Record<string, string> = {
  known_malicious: 'bg-red-500/10 text-red-500', suspicious: 'bg-waf-orange/10 text-waf-amber',
  tor: 'bg-purple-500/10 text-purple-400', vpn: 'bg-waf-orange/10 text-waf-orange',
  datacenter: 'bg-waf-muted/10 text-waf-muted', whitelist: 'bg-waf-success/10 text-waf-orange',
};

export default function IPReputationPage() {
  const { state, dispatch } = useWAF();
  const { ipReputation } = state;

  useEffect(() => {
    api.getBans().then((data) => {
      if (data?.bans) {
        const entries: IPReputationEntry[] = data.bans.map((b) => ({
          id: `ban-${b.ip}`,
          ip: b.ip,
          country: 'Unknown',
          reputation: 'known_malicious',
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          threatCount: 0,
          action: 'block',
        }));
        dispatch({ type: 'SET_IP_REPUTATION', payload: entries });
      }
    });
  }, [dispatch]);
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState('');
  const [form, setForm] = useState({ ip: '', country: '', reputation: 'known_malicious' as IPReputationEntry['reputation'], action: 'block' as 'block' | 'challenge' | 'monitor' });

  const handleAdd = () => {
    if (!form.ip.trim()) return;
    const entry: IPReputationEntry = {
      id: Date.now().toString(),
      ip: form.ip.trim(),
      country: form.country.trim() || 'Unknown',
      reputation: form.reputation,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      threatCount: 0,
      action: form.action,
    };
    dispatch({ type: 'SET_IP_REPUTATION', payload: [...ipReputation, entry] });
    setForm({ ip: '', country: '', reputation: 'known_malicious', action: 'block' });
    setShowAdd(false);
  };

  const updateAction = (entry: IPReputationEntry, action: IPReputationEntry['action']) => {
    dispatch({ type: 'UPDATE_IP_REPUTATION', payload: { ...entry, action } });
  };

  const deleteEntry = (id: string) => {
    dispatch({ type: 'SET_IP_REPUTATION', payload: ipReputation.filter((e) => e.id !== id) });
  };

  const filtered = ipReputation.filter((e) =>
    !search || e.ip.includes(search) || e.country.toLowerCase().includes(search.toLowerCase())
  );

  const stats = {
    total: ipReputation.length,
    blocked: ipReputation.filter((e) => e.action === 'block').length,
    monitored: ipReputation.filter((e) => e.action === 'monitor').length,
    malicious: ipReputation.filter((e) => e.reputation === 'known_malicious').length,
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={UserX} label="Total IPs" value={stats.total} color="text-waf-text" />
        <StatCard icon={Shield} label="Blocked" value={stats.blocked} color="text-red-500" />
        <StatCard icon={AlertTriangle} label="Malicious" value={stats.malicious} color="text-waf-amber" />
        <StatCard icon={Globe} label="Monitored" value={stats.monitored} color="text-waf-orange" />
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
          <input type="text" placeholder="Search by IP or country..." value={search} onChange={(e) => setSearch(e.target.value)} className="w-full bg-waf-panel border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
        </div>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add IP
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">Add IP to Reputation List</h3>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <input type="text" placeholder="IP Address" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Country" value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <select value={form.reputation} onChange={(e) => setForm({ ...form, reputation: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="known_malicious">Known Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="tor">Tor Exit</option>
              <option value="vpn">VPN</option>
              <option value="datacenter">Datacenter</option>
              <option value="whitelist">Whitelist</option>
            </select>
            <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="block">Block</option>
              <option value="challenge">Challenge</option>
              <option value="monitor">Monitor</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Add IP</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      {filtered.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <UserX className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">{search ? 'No matching IPs' : 'No IP reputation data'}</p>
          <p className="text-waf-dim text-xs mt-1">{search ? 'Try a different search term.' : 'Add IPs to track their reputation.'}</p>
        </div>
      ) : (
        <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">Country</th>
                  <th className="px-4 py-3">Reputation</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Threats</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry) => (
                  <tr key={entry.id} className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors">
                    <td className="px-4 py-3 text-sm text-waf-text font-mono">{entry.ip}</td>
                    <td className="px-4 py-3 text-sm text-waf-muted">{entry.country}</td>
                    <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-[10px] font-medium capitalize ${reputationColors[entry.reputation]}`}>{entry.reputation.replace(/_/g, ' ')}</span></td>
                    <td className="px-4 py-3">
                      <select value={entry.action} onChange={(e) => updateAction(entry, e.target.value as any)} className="bg-waf-elevated border border-waf-border rounded px-2 py-1 text-xs text-waf-text focus:outline-none focus:border-waf-orange">
                        <option value="block">Block</option>
                        <option value="challenge">Challenge</option>
                        <option value="monitor">Monitor</option>
                      </select>
                    </td>
                    <td className="px-4 py-3 text-sm text-waf-muted">{entry.threatCount}</td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => deleteEntry(entry.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
      <div className="flex items-center gap-2 mb-1"><Icon className={`w-4 h-4 ${color}`} /><span className="text-waf-muted text-xs">{label}</span></div>
      <p className={`text-2xl font-bold tabular-nums ${color}`}>{value.toLocaleString()}</p>
    </motion.div>
  );
}

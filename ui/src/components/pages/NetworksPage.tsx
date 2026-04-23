import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Network, Plus, Trash2, Shield, Globe, Server, ArrowRight,
  Lock, AlertTriangle, CheckCircle, Activity, Zap, Eye,
  ChevronDown, ChevronUp, X, Filter, Search, ShieldCheck,
  Wifi, WifiOff, TrendingUp, Ban, ExternalLink,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { NetworkPolicy } from '../../store/wafStore';

export default function NetworksPage() {
  const { state, dispatch } = useWAF();
  const { networkPolicies, securityEvents, trafficStats, settings } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    name: '', description: '', subnets: '', ports: '', action: 'allow' as 'allow' | 'block',
  });
  const [filterAction, setFilterAction] = useState<'all' | 'allow' | 'block'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null);

  // ---- ANALYSIS ----
  const analysis = useMemo(() => {
    const activePolicies = networkPolicies.filter((p) => p.enabled);
    const blockPolicies = activePolicies.filter((p) => p.action === 'block');
    const allowPolicies = activePolicies.filter((p) => p.action === 'allow');
    const totalSubnets = activePolicies.reduce((a, p) => a + p.subnets.length, 0);
    const totalPorts = activePolicies.reduce((a, p) => a + p.allowedPorts.length, 0);
    const coveredCountries = new Set(activePolicies.flatMap((p) => p.subnets));
    const uncoveredEvents = securityEvents.filter((e) => !coveredCountries.has(e.country));
    return { activePolicies, blockPolicies, allowPolicies, totalSubnets, totalPorts, uncoveredEvents, hasPolicies: networkPolicies.length > 0 };
  }, [networkPolicies, securityEvents]);

  // ---- FLOW DATA ----
  const flowStats = useMemo(() => ({
    incoming: trafficStats.totalRequests,
    blocked: trafficStats.blockedRequests,
    passed: trafficStats.allowedRequests,
    blockRate: trafficStats.totalRequests > 0 ? Math.round((trafficStats.blockedRequests / trafficStats.totalRequests) * 100) : 0,
    mode: settings.mode,
  }), [trafficStats, settings.mode]);

  // ---- RECOMMENDATIONS ----
  const recommendations = useMemo(() => {
    const recs: { severity: 'critical' | 'warning' | 'info'; text: string; icon: React.ElementType }[] = [];
    if (networkPolicies.length === 0) recs.push({ severity: 'warning', text: 'No network policies. All traffic is implicitly allowed.', icon: AlertTriangle });
    if (analysis.uncoveredEvents.length > 5) recs.push({ severity: 'critical', text: `${analysis.uncoveredEvents.length} threats from regions not covered by any policy.`, icon: Shield });
    if (analysis.blockPolicies.length === 0 && networkPolicies.length > 0) recs.push({ severity: 'warning', text: 'No block policies. Add geo-blocking for high-risk regions.', icon: Lock });
    if (networkPolicies.some((p) => p.subnets.length === 0)) recs.push({ severity: 'info', text: 'Some policies have empty subnet lists — they will not match traffic.', icon: Eye });
    if (trafficStats.totalRequests > 100 && networkPolicies.length < 3) recs.push({ severity: 'info', text: 'High traffic with few policies. Consider more granular controls.', icon: Activity });
    return recs;
  }, [networkPolicies, analysis, trafficStats.totalRequests]);

  const handleAdd = () => {
    if (!newPolicy.name.trim() || !newPolicy.subnets.trim()) return;
    const policy: NetworkPolicy = {
      id: Date.now().toString(),
      name: newPolicy.name.trim(),
      description: newPolicy.description.trim(),
      subnets: newPolicy.subnets.split(',').map((s) => s.trim()).filter(Boolean),
      allowedPorts: newPolicy.ports.split(',').map((p) => parseInt(p.trim())).filter((p) => !isNaN(p) && p > 0),
      action: newPolicy.action,
      enabled: true,
    };
    dispatch({ type: 'SET_NETWORK_POLICIES', payload: [...networkPolicies, policy] });
    setNewPolicy({ name: '', description: '', subnets: '', ports: '', action: 'allow' });
    setShowAdd(false);
  };

  const togglePolicy = (p: NetworkPolicy) => {
    dispatch({ type: 'SET_NETWORK_POLICIES', payload: networkPolicies.map((np) => (np.id === p.id ? { ...np, enabled: !np.enabled } : np)) });
  };

  const deletePolicy = (id: string) => {
    dispatch({ type: 'SET_NETWORK_POLICIES', payload: networkPolicies.filter((p) => p.id !== id) });
  };

  const filteredPolicies = networkPolicies.filter((p) => {
    const matchesAction = filterAction === 'all' || p.action === filterAction;
    const matchesSearch = searchQuery === '' || p.name.toLowerCase().includes(searchQuery.toLowerCase()) || p.description.toLowerCase().includes(searchQuery.toLowerCase()) || p.subnets.some((s) => s.includes(searchQuery));
    return matchesAction && matchesSearch;
  });

  return (
    <div className="space-y-4 lg:space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Network access policies, traffic flow analysis, and security zone controls.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Policy
        </button>
      </div>

      {/* Traffic Flow Cards — replaces broken SVG */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-waf-orange" /> Traffic Flow
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 items-center">
          {/* Internet */}
          <div className="bg-waf-elevated rounded-lg p-3 border border-waf-border text-center">
            <Wifi className="w-5 h-5 text-waf-orange mx-auto mb-1.5" />
            <p className="text-xs text-waf-muted font-medium">Internet</p>
            <p className="text-lg font-bold text-waf-text mt-1">{flowStats.incoming.toLocaleString()}</p>
            <p className="text-[10px] text-waf-dim">requests</p>
          </div>

          {/* Arrow */}
          <div className="hidden sm:flex justify-center">
            <ArrowRight className="w-5 h-5 text-waf-dim" />
          </div>
          <div className="flex sm:hidden justify-center py-1">
            <ArrowRight className="w-5 h-5 text-waf-dim rotate-90" />
          </div>

          {/* WEWAF */}
          <div className={`rounded-lg p-3 border text-center ${flowStats.mode === 'active' ? 'bg-waf-orange/10 border-waf-orange/30' : 'bg-waf-elevated border-waf-border'}`}>
            <Shield className="w-5 h-5 text-waf-orange mx-auto mb-1.5" />
            <p className="text-xs text-waf-muted font-medium">WEWAF</p>
            <p className="text-lg font-bold text-waf-orange mt-1">{flowStats.blockRate}%</p>
            <p className="text-[10px] text-waf-dim">blocked</p>
          </div>

          {/* Arrow */}
          <div className="hidden sm:flex justify-center">
            <ArrowRight className="w-5 h-5 text-waf-dim" />
          </div>
          <div className="flex sm:hidden justify-center py-1">
            <ArrowRight className="w-5 h-5 text-waf-dim rotate-90" />
          </div>

          {/* Origin */}
          <div className="bg-waf-elevated rounded-lg p-3 border border-waf-border text-center">
            <Server className="w-5 h-5 text-emerald-500 mx-auto mb-1.5" />
            <p className="text-xs text-waf-muted font-medium">Origin</p>
            <p className="text-lg font-bold text-emerald-500 mt-1">{flowStats.passed.toLocaleString()}</p>
            <p className="text-[10px] text-waf-dim">passed through</p>
          </div>
        </div>

        {/* Mini bar */}
        <div className="mt-4 flex items-center gap-2">
          <div className="flex-1 h-2 bg-waf-elevated rounded-full overflow-hidden flex">
            <div className="h-full bg-red-500 rounded-full" style={{ width: `${flowStats.blockRate}%` }} />
            <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${100 - flowStats.blockRate}%` }} />
          </div>
          <span className="text-[10px] text-waf-muted shrink-0">{flowStats.blocked.toLocaleString()} blocked / {flowStats.passed.toLocaleString()} passed</span>
        </div>
      </motion.div>

      {/* Policy Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Active Policies', value: analysis.activePolicies.length, icon: ShieldCheck, color: 'text-waf-orange' },
          { label: 'Block Rules', value: analysis.blockPolicies.length, icon: Ban, color: 'text-red-500' },
          { label: 'Subnets', value: analysis.totalSubnets, icon: Globe, color: 'text-waf-amber' },
          { label: 'Ports', value: analysis.totalPorts, icon: Server, color: 'text-waf-orange' },
        ].map((stat, i) => {
          const Icon = stat.icon;
          return (
            <motion.div key={stat.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }} className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`w-3.5 h-3.5 ${stat.color}`} />
                <span className="text-waf-muted text-[10px]">{stat.label}</span>
              </div>
              <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
            </motion.div>
          );
        })}
      </div>

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <h3 className="text-waf-text text-sm font-medium mb-3 flex items-center gap-2">
            <Zap className="w-4 h-4 text-waf-orange" /> Recommendations
          </h3>
          <div className="space-y-2">
            {recommendations.map((rec, i) => {
              const Icon = rec.icon;
              return (
                <div key={i} className={`flex items-start gap-2 p-2.5 rounded-lg text-xs ${
                  rec.severity === 'critical' ? 'bg-red-500/5 border border-red-500/10' :
                  rec.severity === 'warning' ? 'bg-waf-amber/5 border border-waf-amber/10' :
                  'bg-waf-elevated/50 border border-waf-border/50'
                }`}>
                  <Icon className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${
                    rec.severity === 'critical' ? 'text-red-500' :
                    rec.severity === 'warning' ? 'text-waf-amber' :
                    'text-waf-dim'
                  }`} />
                  <p className="text-waf-muted">{rec.text}</p>
                </div>
              );
            })}
          </div>
        </motion.div>
      )}

      {/* Add Policy Form */}
      <AnimatePresence>
        {showAdd && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
            <h3 className="text-waf-text font-medium text-sm">New Network Policy</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" placeholder="Policy name" value={newPolicy.name} onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
              <input type="text" placeholder="Description" value={newPolicy.description} onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" placeholder="Subnets (comma separated)" value={newPolicy.subnets} onChange={(e) => setNewPolicy({ ...newPolicy, subnets: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
              <input type="text" placeholder="Allowed ports (comma separated)" value={newPolicy.ports} onChange={(e) => setNewPolicy({ ...newPolicy, ports: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-waf-muted">Action:</span>
              {(['allow', 'block'] as const).map((action) => (
                <button key={action} onClick={() => setNewPolicy({ ...newPolicy, action })} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  newPolicy.action === action ? (action === 'allow' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-red-500/20 text-red-500') : 'bg-waf-elevated text-waf-muted'
                }`}>
                  {action === 'allow' ? <CheckCircle className="w-3 h-3 inline mr-1" /> : <Lock className="w-3 h-3 inline mr-1" />}
                  {action.charAt(0).toUpperCase() + action.slice(1)}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <button onClick={handleAdd} disabled={!newPolicy.name.trim() || !newPolicy.subnets.trim()} className="px-4 py-2 bg-emerald-500 text-white rounded-lg text-sm font-medium hover:bg-emerald-600 transition-colors disabled:opacity-50">Create Policy</button>
              <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filters */}
      {networkPolicies.length > 0 && (
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
            <input type="text" placeholder="Search policies..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full bg-waf-elevated border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex items-center gap-1 bg-waf-elevated rounded-lg p-0.5 border border-waf-border">
            {(['all', 'allow', 'block'] as const).map((f) => (
              <button key={f} onClick={() => setFilterAction(f)} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${filterAction === f ? 'bg-waf-panel text-waf-text shadow-sm' : 'text-waf-muted hover:text-waf-text'}`}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Policies List */}
      {filteredPolicies.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Network className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">{networkPolicies.length === 0 ? 'No network policies' : 'No matching policies'}</p>
          <p className="text-waf-dim text-xs mt-1">{networkPolicies.length === 0 ? 'Add policies to control network access.' : 'Try adjusting your filters.'}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredPolicies.map((policy) => {
            const isExpanded = expandedPolicy === policy.id;
            return (
              <motion.div key={policy.id} layout className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
                <div className="p-4 cursor-pointer" onClick={() => setExpandedPolicy(isExpanded ? null : policy.id)}>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Network className="w-4 h-4 text-waf-orange shrink-0" />
                        <span className="text-waf-text font-medium text-sm">{policy.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${
                          policy.enabled ? (policy.action === 'allow' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500') : 'bg-waf-dim/10 text-waf-dim'
                        }`}>
                          {policy.enabled ? policy.action : 'Disabled'}
                        </span>
                        {policy.subnets.length === 0 && <span className="px-2 py-0.5 rounded text-[10px] bg-waf-amber/10 text-waf-amber">Empty subnets</span>}
                      </div>
                      <p className="text-waf-dim text-xs mt-1">{policy.description || 'No description'}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={(e) => { e.stopPropagation(); togglePolicy(policy); }} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${policy.enabled ? 'bg-waf-elevated text-waf-muted hover:bg-waf-border' : 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20'}`}>
                        {policy.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); deletePolicy(policy.id); }} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-waf-dim" /> : <ChevronDown className="w-4 h-4 text-waf-dim" />}
                    </div>
                  </div>
                </div>
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="border-t border-waf-border px-4 py-3">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                        <div>
                          <p className="text-waf-muted mb-1.5">Subnets ({policy.subnets.length})</p>
                          <div className="flex flex-wrap gap-1.5">
                            {policy.subnets.length > 0 ? policy.subnets.map((s) => (
                              <span key={s} className="px-2 py-0.5 bg-waf-elevated text-waf-muted rounded border border-waf-border font-mono">{s}</span>
                            )) : <span className="text-waf-dim italic">No subnets configured</span>}
                          </div>
                        </div>
                        <div>
                          <p className="text-waf-muted mb-1.5">Ports ({policy.allowedPorts.length})</p>
                          <div className="flex flex-wrap gap-1.5">
                            {policy.allowedPorts.length > 0 ? policy.allowedPorts.map((p) => (
                              <span key={p} className="px-2 py-0.5 bg-waf-elevated text-waf-muted rounded border border-waf-border font-mono">{p}</span>
                            )) : <span className="text-waf-dim italic">All ports</span>}
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}

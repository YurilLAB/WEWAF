import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Fingerprint, Plus, Trash2, Shield, Globe, Lock, Users, Search,
  CheckCircle, XCircle, Eye, TrendingUp, MapPin, Wifi, AlertTriangle,
  ChevronDown, ChevronUp, Ban, Check,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { AccessPolicy } from '../../store/wafStore';

export default function AccessControlsPage() {
  const { state, dispatch } = useWAF();
  const { accessPolicies, securityEvents, trafficStats } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'disabled'>('all');
  const [form, setForm] = useState({
    name: '', description: '', allowedIPs: '', blockedIPs: '',
    allowedCountries: '', blockedCountries: '', requireAuth: false,
    requireMFA: false, allowedUserAgents: '',
  });

  // ---- ANALYSIS ----
  const stats = useMemo(() => {
    const total = accessPolicies.length;
    const active = accessPolicies.filter((p) => p.enabled).length;
    const totalAllowedIPs = accessPolicies.reduce((a, p) => a + p.allowedIPs.length, 0);
    const totalBlockedIPs = accessPolicies.reduce((a, p) => a + p.blockedIPs.length, 0);
    const totalAllowedCountries = accessPolicies.reduce((a, p) => a + p.allowedCountries.length, 0);
    const totalBlockedCountries = accessPolicies.reduce((a, p) => a + p.blockedCountries.length, 0);
    const authRequired = accessPolicies.filter((p) => p.enabled && p.requireAuth).length;
    return { total, active, totalAllowedIPs, totalBlockedIPs, totalAllowedCountries, totalBlockedCountries, authRequired };
  }, [accessPolicies]);

  // ---- RECOMMENDATIONS ----
  const recommendations = useMemo(() => {
    const recs: { severity: 'critical' | 'warning' | 'info'; text: string; icon: React.ElementType }[] = [];
    if (accessPolicies.length === 0) recs.push({ severity: 'warning', text: 'No access policies configured. All resources are implicitly accessible.', icon: AlertTriangle });
    if (stats.totalBlockedIPs === 0 && stats.total > 0) recs.push({ severity: 'info', text: 'No IP blocks configured. Add known malicious IPs to blocked list.', icon: Ban });
    if (stats.authRequired === 0 && stats.active > 0) recs.push({ severity: 'warning', text: 'No policies require authentication. Enable "Require Auth" for sensitive resources.', icon: Lock });
    if (securityEvents.length > 20 && stats.totalBlockedCountries === 0) recs.push({ severity: 'critical', text: `${securityEvents.length} threats but no geo-blocking in place.`, icon: Globe });
    return recs;
  }, [accessPolicies, stats, securityEvents.length]);

  const handleAdd = () => {
    if (!form.name.trim()) return;
    const policy: AccessPolicy = {
      id: Date.now().toString(),
      name: form.name.trim(),
      description: form.description.trim(),
      allowedIPs: form.allowedIPs.split(',').map((s) => s.trim()).filter(Boolean),
      blockedIPs: form.blockedIPs.split(',').map((s) => s.trim()).filter(Boolean),
      allowedCountries: form.allowedCountries.split(',').map((s) => s.trim()).filter(Boolean),
      blockedCountries: form.blockedCountries.split(',').map((s) => s.trim()).filter(Boolean),
      requireAuth: form.requireAuth,
      enabled: true,
    };
    dispatch({ type: 'SET_ACCESS_POLICIES', payload: [...accessPolicies, policy] });
    setForm({ name: '', description: '', allowedIPs: '', blockedIPs: '', allowedCountries: '', blockedCountries: '', requireAuth: false, requireMFA: false, allowedUserAgents: '' });
    setShowAdd(false);
  };

  const togglePolicy = (p: AccessPolicy) => {
    dispatch({ type: 'UPDATE_ACCESS_POLICY', payload: { ...p, enabled: !p.enabled } });
  };

  const deletePolicy = (id: string) => {
    dispatch({ type: 'SET_ACCESS_POLICIES', payload: accessPolicies.filter((p) => p.id !== id) });
  };

  const filteredPolicies = accessPolicies.filter((p) => {
    const matchesStatus = filterStatus === 'all' || (filterStatus === 'active' ? p.enabled : !p.enabled);
    const matchesSearch = searchQuery === '' || p.name.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Access control policies for protected resources — who can access what and from where.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Policy
        </button>
      </div>

      {/* Stats Overview */}
      {stats.total > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-waf-orange" /> Policy Overview</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { label: 'Total Policies', value: stats.total, icon: Fingerprint, color: 'text-waf-orange' },
              { label: 'Active', value: stats.active, icon: CheckCircle, color: 'text-emerald-500' },
              { label: 'Allowed IPs', value: stats.totalAllowedIPs, icon: Wifi, color: 'text-waf-amber' },
              { label: 'Blocked IPs', value: stats.totalBlockedIPs, icon: Ban, color: 'text-red-500' },
              { label: 'Allowed Geo', value: stats.totalAllowedCountries, icon: Globe, color: 'text-waf-orange' },
              { label: 'Auth Required', value: stats.authRequired, icon: Lock, color: 'text-waf-amber' },
            ].map((s, i) => {
              const Icon = s.icon;
              return (
                <motion.div key={s.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }} className="bg-waf-elevated rounded-lg p-3 text-center">
                  <Icon className={`w-4 h-4 ${s.color} mx-auto mb-1`} />
                  <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                  <p className="text-[10px] text-waf-muted">{s.label}</p>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <h3 className="text-waf-text text-sm font-medium mb-3 flex items-center gap-2"><TrendingUp className="w-4 h-4 text-waf-orange" /> Recommendations</h3>
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

      {/* Add Form */}
      <AnimatePresence>
        {showAdd && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
            <h3 className="text-waf-text font-medium text-sm">New Access Policy</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" placeholder="Policy name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
              <input type="text" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" placeholder="Allowed IPs (comma separated)" value={form.allowedIPs} onChange={(e) => setForm({ ...form, allowedIPs: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
              <input type="text" placeholder="Blocked IPs (comma separated)" value={form.blockedIPs} onChange={(e) => setForm({ ...form, blockedIPs: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" placeholder="Allowed countries (comma separated)" value={form.allowedCountries} onChange={(e) => setForm({ ...form, allowedCountries: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
              <input type="text" placeholder="Blocked countries (comma separated)" value={form.blockedCountries} onChange={(e) => setForm({ ...form, blockedCountries: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            </div>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer bg-waf-elevated rounded-lg px-3 py-2 border border-waf-border">
              <input type="checkbox" checked={form.requireAuth} onChange={(e) => setForm({ ...form, requireAuth: e.target.checked })} className="rounded border-waf-border accent-waf-orange w-4 h-4" />
              <Lock className="w-3.5 h-3.5" />
              <span>Require Authentication</span>
            </label>
            <div className="flex gap-2">
              <button onClick={handleAdd} disabled={!form.name.trim()} className="px-4 py-2 bg-emerald-500 text-white rounded-lg text-sm font-medium hover:bg-emerald-600 disabled:opacity-50">Create Policy</button>
              <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filters */}
      {accessPolicies.length > 0 && (
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
            <input type="text" placeholder="Search policies..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full bg-waf-elevated border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex items-center gap-1 bg-waf-elevated rounded-lg p-0.5 border border-waf-border">
            {(['all', 'active', 'disabled'] as const).map((f) => (
              <button key={f} onClick={() => setFilterStatus(f)} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${filterStatus === f ? 'bg-waf-panel text-waf-text shadow-sm' : 'text-waf-muted hover:text-waf-text'}`}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Policies List */}
      {filteredPolicies.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Fingerprint className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">{accessPolicies.length === 0 ? 'No access policies' : 'No matching policies'}</p>
          <p className="text-waf-dim text-xs mt-1">{accessPolicies.length === 0 ? 'Create policies to control who can access your resources.' : 'Try adjusting your filters.'}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredPolicies.map((policy) => {
            const isExpanded = expandedId === policy.id;
            return (
              <motion.div key={policy.id} layout className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
                <div className="p-4" onClick={() => setExpandedId(isExpanded ? null : policy.id)}>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${policy.enabled ? 'bg-waf-orange/10' : 'bg-waf-elevated'}`}>
                        <Lock className={`w-5 h-5 ${policy.enabled ? 'text-waf-orange' : 'text-waf-dim'}`} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-waf-text font-medium text-sm truncate">{policy.name}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase shrink-0 ${policy.enabled ? 'bg-emerald-500/10 text-emerald-500' : 'bg-waf-dim/10 text-waf-dim'}`}>{policy.enabled ? 'Active' : 'Disabled'}</span>
                        </div>
                        <p className="text-waf-dim text-xs truncate">{policy.description || 'No description'}</p>
                      </div>
                    </div>
                    <div className="flex-1" />
                    <div className="flex items-center gap-2 shrink-0 flex-wrap">
                      {/* Mini stat badges */}
                      {policy.allowedIPs.length > 0 && <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-500 rounded text-[10px]">{policy.allowedIPs.length} allowed IPs</span>}
                      {policy.blockedIPs.length > 0 && <span className="px-2 py-0.5 bg-red-500/10 text-red-500 rounded text-[10px]">{policy.blockedIPs.length} blocked IPs</span>}
                      {policy.blockedCountries.length > 0 && <span className="px-2 py-0.5 bg-red-500/10 text-red-500 rounded text-[10px]">{policy.blockedCountries.length} blocked geo</span>}
                      {policy.requireAuth && <span className="px-2 py-0.5 bg-waf-amber/10 text-waf-amber rounded text-[10px]">Auth</span>}
                      <button onClick={(e) => { e.stopPropagation(); togglePolicy(policy); }} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${policy.enabled ? 'bg-waf-elevated text-waf-muted hover:bg-waf-border' : 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20'}`}>
                        {policy.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); deletePolicy(policy.id); }} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500">
                        <Trash2 className="w-4 h-4" />
                      </button>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-waf-dim" /> : <ChevronDown className="w-4 h-4 text-waf-dim" />}
                    </div>
                  </div>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="border-t border-waf-border px-4 py-3">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                        {policy.allowedIPs.length > 0 && (
                          <div>
                            <p className="text-waf-muted mb-1.5 flex items-center gap-1"><CheckCircle className="w-3 h-3 text-emerald-500" /> Allowed IPs ({policy.allowedIPs.length})</p>
                            <div className="flex flex-wrap gap-1.5">
                              {policy.allowedIPs.map((ip) => (
                                <span key={ip} className="px-2 py-0.5 bg-emerald-500/5 text-emerald-500 rounded border border-emerald-500/10 font-mono">{ip}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {policy.blockedIPs.length > 0 && (
                          <div>
                            <p className="text-waf-muted mb-1.5 flex items-center gap-1"><Ban className="w-3 h-3 text-red-500" /> Blocked IPs ({policy.blockedIPs.length})</p>
                            <div className="flex flex-wrap gap-1.5">
                              {policy.blockedIPs.map((ip) => (
                                <span key={ip} className="px-2 py-0.5 bg-red-500/5 text-red-500 rounded border border-red-500/10 font-mono">{ip}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {policy.allowedCountries.length > 0 && (
                          <div>
                            <p className="text-waf-muted mb-1.5 flex items-center gap-1"><Globe className="w-3 h-3 text-waf-orange" /> Allowed Countries ({policy.allowedCountries.length})</p>
                            <div className="flex flex-wrap gap-1.5">
                              {policy.allowedCountries.map((c) => (
                                <span key={c} className="px-2 py-0.5 bg-waf-orange/5 text-waf-orange rounded border border-waf-orange/10">{c}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {policy.blockedCountries.length > 0 && (
                          <div>
                            <p className="text-waf-muted mb-1.5 flex items-center gap-1"><Globe className="w-3 h-3 text-red-500" /> Blocked Countries ({policy.blockedCountries.length})</p>
                            <div className="flex flex-wrap gap-1.5">
                              {policy.blockedCountries.map((c) => (
                                <span key={c} className="px-2 py-0.5 bg-red-500/5 text-red-500 rounded border border-red-500/10">{c}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {policy.requireAuth && (
                          <div className="sm:col-span-2">
                            <p className="text-waf-muted mb-1.5 flex items-center gap-1"><Lock className="w-3 h-3 text-waf-amber" /> Authentication Required</p>
                            <p className="text-waf-dim">Users must authenticate before accessing resources covered by this policy.</p>
                          </div>
                        )}
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

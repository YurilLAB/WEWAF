import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Plus, Trash2, Monitor, CheckCircle, XCircle, AlertTriangle,
  Lock, Wifi, HardDrive, Globe, Smartphone, Laptop, Tablet,
  ChevronDown, ChevronUp, TrendingUp, Eye, Fingerprint,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { DevicePosture } from '../../store/wafStore';

const OS_ICONS: Record<string, React.ElementType> = {
  windows: Laptop,
  macos: Laptop,
  linux: Laptop,
  ios: Smartphone,
  android: Smartphone,
  any: Monitor,
};

export default function DevicePosturePage() {
  const { state, dispatch } = useWAF();
  const { devicePostures } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: '', os: 'any', minVersion: '', requireEncryption: true,
    requireFirewall: false, requireAntivirus: false, requireMFA: false,
    maxRiskScore: 70,
  });

  // ---- ANALYSIS ----
  const stats = useMemo(() => {
    const total = devicePostures.length;
    const active = devicePostures.filter((p) => p.enabled).length;
    const byOS: Record<string, number> = {};
    devicePostures.forEach((p) => { byOS[p.os] = (byOS[p.os] || 0) + 1; });
    const requirements = {
      encryption: devicePostures.filter((p) => p.enabled && p.requireEncryption).length,
      firewall: devicePostures.filter((p) => p.enabled && p.requireFirewall).length,
      antivirus: devicePostures.filter((p) => p.enabled && p.requireAntivirus).length,
    };
    const complianceRate = total > 0 ? Math.round((active / total) * 100) : 0;
    return { total, active, byOS, requirements, complianceRate };
  }, [devicePostures]);

  const handleAdd = () => {
    if (!form.name.trim()) return;
    const posture: DevicePosture = {
      id: Date.now().toString(),
      name: form.name.trim(),
      os: form.os,
      minVersion: form.minVersion.trim(),
      requireEncryption: form.requireEncryption,
      requireFirewall: form.requireFirewall,
      requireAntivirus: form.requireAntivirus,
      enabled: true,
    };
    dispatch({ type: 'SET_DEVICE_POSTURES', payload: [...devicePostures, posture] });
    setForm({ name: '', os: 'any', minVersion: '', requireEncryption: true, requireFirewall: false, requireAntivirus: false, requireMFA: false, maxRiskScore: 70 });
    setShowAdd(false);
  };

  const togglePosture = (p: DevicePosture) => {
    dispatch({ type: 'SET_DEVICE_POSTURES', payload: devicePostures.map((dp) => (dp.id === p.id ? { ...dp, enabled: !dp.enabled } : dp)) });
  };

  const deletePosture = (id: string) => {
    dispatch({ type: 'SET_DEVICE_POSTURES', payload: devicePostures.filter((p) => p.id !== id) });
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Device compliance requirements for Zero Trust network access.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Posture
        </button>
      </div>

      {/* Compliance Score */}
      {stats.total > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-waf-text text-sm font-medium flex items-center gap-2"><Shield className="w-4 h-4 text-waf-orange" /> Compliance Overview</h3>
            <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${stats.complianceRate >= 80 ? 'bg-emerald-500/10 text-emerald-500' : stats.complianceRate >= 50 ? 'bg-waf-amber/10 text-waf-amber' : 'bg-red-500/10 text-red-500'}`}>
              {stats.complianceRate}% Compliant
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Total', value: stats.total, icon: Monitor, color: 'text-waf-orange' },
              { label: 'Active', value: stats.active, icon: CheckCircle, color: 'text-emerald-500' },
              { label: 'Encryption', value: stats.requirements.encryption, icon: Lock, color: 'text-waf-amber' },
              { label: 'Firewall', value: stats.requirements.firewall, icon: Wifi, color: 'text-waf-orange' },
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

      {/* Add Form */}
      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">New Device Posture</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input type="text" placeholder="Posture name (e.g. Corporate Laptop)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <select value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="any">Any OS</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="linux">Linux</option>
              <option value="ios">iOS</option>
              <option value="android">Android</option>
            </select>
            <input type="text" placeholder="Min OS version (e.g. 11.0)" value={form.minVersion} onChange={(e) => setForm({ ...form, minVersion: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex flex-wrap gap-3">
            {([
              { key: 'requireEncryption', label: 'Disk Encryption', icon: Lock },
              { key: 'requireFirewall', label: 'Host Firewall', icon: Wifi },
              { key: 'requireAntivirus', label: 'Antivirus / EDR', icon: Shield },
            ] as const).map((req) => {
              const Icon = req.icon;
              return (
                <label key={req.key} className={`flex items-center gap-2 text-sm cursor-pointer rounded-lg px-3 py-2 border transition-colors ${form[req.key] ? 'bg-waf-orange/10 border-waf-orange/20 text-waf-orange' : 'bg-waf-elevated border-waf-border text-waf-muted'}`}>
                  <input type="checkbox" checked={form[req.key]} onChange={(e) => setForm({ ...form, [req.key]: e.target.checked })} className="rounded border-waf-border accent-waf-orange w-4 h-4" />
                  <Icon className="w-3.5 h-3.5" />
                  <span>{req.label}</span>
                </label>
              );
            })}
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} disabled={!form.name.trim()} className="px-4 py-2 bg-emerald-500 text-white rounded-lg text-sm font-medium hover:bg-emerald-600 disabled:opacity-50">Create Posture</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      {/* Postures */}
      {devicePostures.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Monitor className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No device postures configured</p>
          <p className="text-waf-dim text-xs mt-1">Set device requirements for Zero Trust network access.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {devicePostures.map((posture) => {
            const isExpanded = expandedId === posture.id;
            const OsIcon = OS_ICONS[posture.os] || Monitor;
            return (
              <motion.div key={posture.id} layout className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
                <div className="p-4" onClick={() => setExpandedId(isExpanded ? null : posture.id)}>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${posture.enabled ? 'bg-waf-orange/10' : 'bg-waf-elevated'}`}>
                        <OsIcon className={`w-5 h-5 ${posture.enabled ? 'text-waf-orange' : 'text-waf-dim'}`} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-waf-text font-medium text-sm">{posture.name}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${posture.enabled ? 'bg-emerald-500/10 text-emerald-500' : 'bg-waf-dim/10 text-waf-dim'}`}>{posture.enabled ? 'Active' : 'Disabled'}</span>
                        </div>
                        <p className="text-waf-dim text-xs">{posture.os}{posture.minVersion ? ` >= ${posture.minVersion}` : ''}</p>
                      </div>
                    </div>
                    <div className="flex-1" />
                    <div className="flex items-center gap-2 shrink-0">
                      {/* Requirement badges */}
                      <div className="hidden sm:flex items-center gap-1">
                        {posture.requireEncryption && (
                          <span title="Encryption required"><Lock className="w-3 h-3 text-waf-amber" /></span>
                        )}
                        {posture.requireFirewall && (
                          <span title="Firewall required"><Wifi className="w-3 h-3 text-waf-orange" /></span>
                        )}
                        {posture.requireAntivirus && (
                          <span title="Antivirus required"><Shield className="w-3 h-3 text-emerald-500" /></span>
                        )}
                      </div>
                      <button onClick={(e) => { e.stopPropagation(); togglePosture(posture); }} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${posture.enabled ? 'bg-waf-elevated text-waf-muted hover:bg-waf-border' : 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20'}`}>
                        {posture.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); deletePosture(posture.id); }} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500">
                        <Trash2 className="w-4 h-4" />
                      </button>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-waf-dim" /> : <ChevronDown className="w-4 h-4 text-waf-dim" />}
                    </div>
                  </div>
                </div>

                {isExpanded && (
                  <div className="border-t border-waf-border px-4 py-3">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {([
                        { key: 'requireEncryption', label: 'Disk Encryption', icon: Lock },
                        { key: 'requireFirewall', label: 'Host Firewall', icon: Wifi },
                        { key: 'requireAntivirus', label: 'Antivirus / EDR', icon: Shield },
                      ] as const).map((req) => {
                        const Icon = req.icon;
                        const enabled = posture[req.key];
                        return (
                          <div key={req.key} className={`flex items-center gap-2 p-2 rounded-lg text-xs ${enabled ? 'bg-emerald-500/5 border border-emerald-500/10' : 'bg-waf-elevated border border-waf-border'}`}>
                            {enabled ? <CheckCircle className="w-3.5 h-3.5 text-emerald-500" /> : <XCircle className="w-3.5 h-3.5 text-waf-dim" />}
                            <Icon className={`w-3.5 h-3.5 ${enabled ? 'text-emerald-500' : 'text-waf-dim'}`} />
                            <span className={enabled ? 'text-emerald-500' : 'text-waf-dim'}>{req.label}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}

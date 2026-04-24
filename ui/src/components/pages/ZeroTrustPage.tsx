import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Plus, Trash2, Save, Loader2, CheckCircle, AlertTriangle, FileText,
  Clock, Globe, Key, EyeOff,
} from 'lucide-react';
import { api } from '../../services/api';
import type { ZeroTrustPolicy } from '../../services/api';

type SaveState = 'idle' | 'saving' | 'saved' | 'error';

const EMPTY_POLICY: ZeroTrustPolicy = {
  id: '',
  description: '',
  path_prefix: '/',
  methods: [],
  simulate: true,
  fallback_allow: true,
};

export default function ZeroTrustPage() {
  const [policies, setPolicies] = useState<ZeroTrustPolicy[]>([]);
  const [templates, setTemplates] = useState<ZeroTrustPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [saveState, setSaveState] = useState<SaveState>('idle');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    const [p, t] = await Promise.all([
      api.getZeroTrustPolicies(),
      api.getZeroTrustTemplates(),
    ]);
    setPolicies(p?.policies || []);
    setTemplates(t?.templates || []);
    setLoading(false);
  }

  async function save() {
    setSaveState('saving');
    setError(null);
    // Basic validation: every policy needs an ID and at least one path selector.
    for (const p of policies) {
      if (!p.id.trim()) {
        setSaveState('error');
        setError('Every policy needs a unique ID.');
        return;
      }
      if (!p.path_prefix && !p.path_exact && !p.path_regex) {
        setSaveState('error');
        setError(`Policy "${p.id}" has no path_prefix, path_exact, or path_regex.`);
        return;
      }
    }
    const res = await api.setZeroTrustPolicies(policies);
    if (!res || res.status !== 'ok') {
      setSaveState('error');
      setError('Save failed — check the backend logs.');
      return;
    }
    setSaveState('saved');
    setTimeout(() => setSaveState('idle'), 1500);
  }

  function addEmpty() {
    const n = policies.length + 1;
    setPolicies([...policies, { ...EMPTY_POLICY, id: `policy-${n}` }]);
  }

  function applyTemplate(t: ZeroTrustPolicy) {
    const copy: ZeroTrustPolicy = { ...t, id: `${t.id}-${Date.now().toString().slice(-5)}` };
    setPolicies([...policies, copy]);
  }

  function updatePolicy(idx: number, patch: Partial<ZeroTrustPolicy>) {
    setPolicies((prev) => prev.map((p, i) => i === idx ? { ...p, ...patch } : p));
  }

  function removePolicy(idx: number) {
    setPolicies((prev) => prev.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">
        Zero-trust policies run <span className="text-waf-text">before</span> the rule engine.
        Mark a policy <span className="text-amber-400">simulate</span> to log would-block
        decisions without actually blocking — useful for staging.
      </p>

      {/* Templates */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <div className="flex items-center gap-2 mb-3">
          <FileText className="w-4 h-4 text-waf-orange" />
          <h3 className="text-waf-text text-sm font-semibold">Templates</h3>
        </div>
        <p className="text-waf-dim text-xs mb-3">
          Click one to add it to your policy list. All templates ship in simulate mode.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {templates.map((t) => (
            <button
              key={t.id} onClick={() => applyTemplate(t)}
              className="text-left p-3 rounded-md bg-waf-elevated border border-waf-border hover:border-waf-orange hover:bg-waf-border/40 transition-colors"
            >
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-3.5 h-3.5 text-waf-orange" />
                <span className="text-waf-text text-xs font-semibold">{t.id}</span>
              </div>
              <p className="text-waf-dim text-[10px]">{t.description}</p>
              <div className="flex flex-wrap gap-1 mt-2">
                {t.path_prefix && <Pill>prefix {t.path_prefix}</Pill>}
                {t.require_mtls && <Pill>mTLS</Pill>}
                {t.time_start && <Pill><Clock className="w-2.5 h-2.5 inline mr-0.5" />{t.time_start}-{t.time_end}</Pill>}
                {t.allowed_countries && t.allowed_countries.length > 0 && <Pill><Globe className="w-2.5 h-2.5 inline mr-0.5" />{t.allowed_countries.join(',')}</Pill>}
                {t.deny_by_default && <Pill>deny-default</Pill>}
              </div>
            </button>
          ))}
        </div>
      </motion.div>

      {/* Policies */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-waf-orange" />
            <h3 className="text-waf-text text-sm font-semibold">Active Policies ({policies.length})</h3>
          </div>
          <button onClick={addEmpty}
            className="flex items-center gap-1 px-2 py-1 rounded-md text-xs bg-waf-elevated border border-waf-border text-waf-muted hover:text-waf-text transition-colors">
            <Plus className="w-3 h-3" /> Add empty
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-4 h-4 animate-spin text-waf-dim" />
          </div>
        ) : policies.length === 0 ? (
          <div className="text-center py-6 text-waf-dim text-xs">
            No policies yet. Apply a template or click "Add empty".
          </div>
        ) : (
          <div className="space-y-3">
            {policies.map((p, i) => (
              <PolicyEditor key={i} policy={p} onChange={(patch) => updatePolicy(i, patch)} onRemove={() => removePolicy(i)} />
            ))}
          </div>
        )}

        {error && (
          <div className="mt-3 flex items-center gap-2 p-2 rounded-md bg-red-500/5 border border-red-500/20 text-red-400 text-[11px]">
            <AlertTriangle className="w-3.5 h-3.5" /> {error}
          </div>
        )}

        <div className="mt-4 flex items-center gap-3">
          <button onClick={save} disabled={saveState === 'saving'}
            className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
            {saveState === 'saving' ? <Loader2 className="w-4 h-4 animate-spin" />
              : saveState === 'saved' ? <CheckCircle className="w-4 h-4" />
              : <Save className="w-4 h-4" />}
            {saveState === 'saved' ? 'Saved' : 'Save policies'}
          </button>
          <button onClick={loadAll}
            className="px-4 py-2 rounded-md bg-waf-elevated text-waf-muted text-sm hover:text-waf-text hover:bg-waf-border transition-colors">
            Revert
          </button>
        </div>
      </motion.div>
    </div>
  );
}

function PolicyEditor({ policy, onChange, onRemove }: {
  policy: ZeroTrustPolicy;
  onChange: (p: Partial<ZeroTrustPolicy>) => void;
  onRemove: () => void;
}) {
  return (
    <div className="p-3 rounded-lg bg-waf-elevated/50 border border-waf-border">
      <div className="flex items-start gap-2 mb-3">
        <input type="text" placeholder="policy-id" value={policy.id}
          onChange={(e) => onChange({ id: e.target.value })}
          className="flex-1 bg-waf-elevated border border-waf-border rounded-md px-2 py-1.5 text-xs font-mono text-waf-text focus:outline-none focus:border-waf-orange" />
        <label className="flex items-center gap-1 text-[10px] text-waf-muted cursor-pointer">
          <input type="checkbox" checked={policy.simulate || false}
            onChange={(e) => onChange({ simulate: e.target.checked })}
            className="accent-amber-400" />
          <EyeOff className="w-3 h-3" /> simulate
        </label>
        <label className="flex items-center gap-1 text-[10px] text-waf-muted cursor-pointer">
          <input type="checkbox" checked={policy.deny_by_default || false}
            onChange={(e) => onChange({ deny_by_default: e.target.checked })}
            className="accent-red-400" />
          deny-default
        </label>
        <button onClick={onRemove}
          className="p-1 rounded text-red-400 hover:bg-red-500/10">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <input type="text" placeholder="Description (optional)" value={policy.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        className="w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1 text-[11px] text-waf-text focus:outline-none focus:border-waf-orange mb-2" />

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <FieldRow label="Path prefix" value={policy.path_prefix || ''} onChange={(v) => onChange({ path_prefix: v })} mono placeholder="/admin" />
        <FieldRow label="Path exact" value={policy.path_exact || ''} onChange={(v) => onChange({ path_exact: v })} mono placeholder="/login" />
        <FieldRow label="Path regex (RE2)" value={policy.path_regex || ''} onChange={(v) => onChange({ path_regex: v })} mono placeholder="^/api/v[12]/" />
        <FieldRow label="Methods (csv)" value={(policy.methods || []).join(',')} onChange={(v) => onChange({ methods: v.split(',').map(s => s.trim()).filter(Boolean) })} mono placeholder="GET,POST" />
        <FieldRow label={<span className="flex items-center gap-1"><Key className="w-3 h-3" /> Require header</span>} value={policy.require_auth_header || ''} onChange={(v) => onChange({ require_auth_header: v })} mono placeholder="Authorization" />
        <FieldRow label="Allowed CIDRs (csv)" value={(policy.allowed_cidrs || []).join(',')} onChange={(v) => onChange({ allowed_cidrs: v.split(',').map(s => s.trim()).filter(Boolean) })} mono placeholder="10.0.0.0/8" />
        <FieldRow label="Blocked CIDRs (csv)" value={(policy.blocked_cidrs || []).join(',')} onChange={(v) => onChange({ blocked_cidrs: v.split(',').map(s => s.trim()).filter(Boolean) })} mono placeholder="203.0.113.0/24" />
        <FieldRow label="Allowed countries" value={(policy.allowed_countries || []).join(',')} onChange={(v) => onChange({ allowed_countries: v.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) })} mono placeholder="US,CA,GB" />
        <FieldRow label="Blocked countries" value={(policy.blocked_countries || []).join(',')} onChange={(v) => onChange({ blocked_countries: v.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) })} mono placeholder="RU,KP" />
        <FieldRow label="Time start (UTC HH:MM)" value={policy.time_start || ''} onChange={(v) => onChange({ time_start: v })} mono placeholder="09:00" />
        <FieldRow label="Time end (UTC HH:MM)" value={policy.time_end || ''} onChange={(v) => onChange({ time_end: v })} mono placeholder="17:00" />
      </div>

      <div className="flex items-center gap-3 mt-2 pt-2 border-t border-waf-border/40 text-[10px] text-waf-dim">
        <label className="flex items-center gap-1 cursor-pointer">
          <input type="checkbox" checked={policy.require_mtls || false}
            onChange={(e) => onChange({ require_mtls: e.target.checked })}
            className="accent-waf-orange" />
          Require mTLS
        </label>
        <label className="flex items-center gap-1 cursor-pointer">
          <input type="checkbox" checked={policy.fallback_allow || false}
            onChange={(e) => onChange({ fallback_allow: e.target.checked })}
            className="accent-waf-orange" />
          Allow on geo-lookup failure
        </label>
      </div>
    </div>
  );
}

function FieldRow({ label, value, onChange, mono, placeholder }: {
  label: React.ReactNode; value: string; onChange: (v: string) => void; mono?: boolean; placeholder?: string;
}) {
  return (
    <div>
      <label className="text-[10px] text-waf-muted mb-0.5 block">{label}</label>
      <input type="text" value={value} placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1 text-[11px] text-waf-text focus:outline-none focus:border-waf-orange ${mono ? 'font-mono' : ''}`} />
    </div>
  );
}

function Pill({ children }: { children: React.ReactNode }) {
  return <span className="px-1.5 py-0.5 rounded-md text-[9px] bg-waf-elevated text-waf-muted border border-waf-border">{children}</span>;
}

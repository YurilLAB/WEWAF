import { useState } from 'react';
import { motion } from 'framer-motion';
import { Timer, Plus, Trash2, Edit3, Check, X, ToggleLeft, ToggleRight } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { RateLimit } from '../../store/wafStore';

export default function RateLimitingPage() {
  const { state, dispatch } = useWAF();
  const { rateLimits } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({ name: '', requests: 100, window: 60, action: 'throttle' as 'block' | 'challenge' | 'throttle', matchPath: '' });
  const [editForm, setEditForm] = useState({ name: '', requests: 100, window: 60, action: 'throttle' as 'block' | 'challenge' | 'throttle', matchPath: '' });

  const handleAdd = () => {
    if (!form.name.trim() || !form.matchPath.trim()) return;
    const rl: RateLimit = {
      id: Date.now().toString(),
      name: form.name.trim(),
      requests: form.requests,
      window: form.window,
      action: form.action,
      enabled: true,
      matchPath: form.matchPath.trim(),
    };
    dispatch({ type: 'SET_RATE_LIMITS', payload: [...rateLimits, rl] });
    setForm({ name: '', requests: 100, window: 60, action: 'throttle', matchPath: '' });
    setShowAdd(false);
  };

  const toggleRateLimit = (rl: RateLimit) => {
    dispatch({ type: 'UPDATE_RATE_LIMIT', payload: { ...rl, enabled: !rl.enabled } });
  };

  const deleteRateLimit = (id: string) => {
    dispatch({ type: 'SET_RATE_LIMITS', payload: rateLimits.filter((r) => r.id !== id) });
  };

  const startEdit = (rl: RateLimit) => {
    setEditId(rl.id);
    setEditForm({ name: rl.name, requests: rl.requests, window: rl.window, action: rl.action, matchPath: rl.matchPath });
  };

  const saveEdit = () => {
    if (!editId) return;
    const existing = rateLimits.find((r) => r.id === editId);
    if (!existing) return;
    dispatch({ type: 'UPDATE_RATE_LIMIT', payload: { ...existing, ...editForm } });
    setEditId(null);
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Configure rate limiting to prevent abuse and brute force attacks.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Rate Limit
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">New Rate Limit</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input type="text" placeholder="Rule name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Path pattern (e.g. /api/*)" value={form.matchPath} onChange={(e) => setForm({ ...form, matchPath: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-waf-dim mb-1 block">Requests</label>
              <input type="number" value={form.requests} onChange={(e) => setForm({ ...form, requests: parseInt(e.target.value) || 0 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
            </div>
            <div>
              <label className="text-xs text-waf-dim mb-1 block">Window (seconds)</label>
              <input type="number" value={form.window} onChange={(e) => setForm({ ...form, window: parseInt(e.target.value) || 0 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
            </div>
            <div>
              <label className="text-xs text-waf-dim mb-1 block">Action</label>
              <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as any })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
                <option value="throttle">Throttle</option>
                <option value="block">Block</option>
                <option value="challenge">Challenge</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Add Rate Limit</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      {rateLimits.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Timer className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No rate limits configured</p>
          <p className="text-waf-dim text-xs mt-1">Add rate limits to protect against abuse and brute force.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {rateLimits.map((rl) => (
            <motion.div key={rl.id} layout className="bg-waf-panel border border-waf-border rounded-xl p-4">
              {editId === rl.id ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                    <input type="text" value={editForm.matchPath} onChange={(e) => setEditForm({ ...editForm, matchPath: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                  </div>
                  <div className="flex gap-2">
                    <button onClick={saveEdit} className="flex items-center gap-1 px-3 py-1.5 bg-waf-success text-white rounded text-sm hover:bg-emerald-600"><Check className="w-3.5 h-3.5" /> Save</button>
                    <button onClick={() => setEditId(null)} className="flex items-center gap-1 px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border"><X className="w-3.5 h-3.5" /> Cancel</button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Timer className="w-4 h-4 text-waf-amber" />
                      <span className="text-waf-text font-medium text-sm">{rl.name}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${rl.enabled ? 'bg-waf-success/10 text-waf-orange' : 'bg-waf-dim/10 text-waf-dim'}`}>{rl.enabled ? 'Active' : 'Disabled'}</span>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1 text-xs text-waf-muted">
                      <span>{rl.requests} requests / {rl.window}s</span>
                      <span>Path: {rl.matchPath}</span>
                      <span className={rl.action === 'block' ? 'text-red-500' : rl.action === 'challenge' ? 'text-waf-amber' : 'text-waf-orange'}>Action: {rl.action}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => toggleRateLimit(rl)} className="text-waf-muted hover:text-waf-text">
                      {rl.enabled ? <ToggleRight className="w-6 h-6 text-waf-orange" /> : <ToggleLeft className="w-6 h-6 text-waf-dim" />}
                    </button>
                    <button onClick={() => startEdit(rl)} className="p-1.5 rounded-md hover:bg-waf-elevated text-waf-muted hover:text-waf-text"><Edit3 className="w-4 h-4" /></button>
                    <button onClick={() => deleteRateLimit(rl.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
                  </div>
                </div>
              )}
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}

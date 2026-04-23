import { useState } from 'react';
import { motion } from 'framer-motion';
import { FileText, Plus, Trash2, Edit3, Check, X, ToggleLeft, ToggleRight } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { WAFRules } from '../../store/wafStore';

const categoryLabels: Record<string, string> = {
  xss: 'XSS', sqli: 'SQL Injection', lfi: 'LFI/RFI', rfi: 'RFI',
  xxe: 'XXE', command_injection: 'Command Injection', custom: 'Custom',
};

const categoryColors: Record<string, string> = {
  xss: 'bg-red-500/10 text-red-500', sqli: 'bg-orange-500/10 text-orange-500', lfi: 'bg-yellow-500/10 text-yellow-500',
  rfi: 'bg-yellow-500/10 text-yellow-500', xxe: 'bg-purple-500/10 text-purple-500',
  command_injection: 'bg-orange-500/10 text-orange-500', custom: 'bg-gray-500/10 text-gray-400',
};

export default function WAFRulesPage() {
  const { state, dispatch } = useWAF();
  const { wafRules } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [newRule, setNewRule] = useState({ name: '', description: '', pattern: '', action: 'block' as 'block' | 'challenge' | 'log', category: 'custom' as WAFRules['category'], priority: 5 });
  const [editForm, setEditForm] = useState({ name: '', description: '', pattern: '', action: 'block' as 'block' | 'challenge' | 'log', priority: 5 });

  const handleAdd = () => {
    if (!newRule.name.trim() || !newRule.pattern.trim()) return;
    const rule: WAFRules = {
      id: Date.now().toString(),
      name: newRule.name.trim(),
      description: newRule.description.trim(),
      pattern: newRule.pattern.trim(),
      action: newRule.action,
      enabled: true,
      priority: newRule.priority,
      category: newRule.category,
      hits: 0,
    };
    dispatch({ type: 'SET_WAF_RULES', payload: [...wafRules, rule] });
    setNewRule({ name: '', description: '', pattern: '', action: 'block', category: 'custom', priority: 5 });
    setShowAdd(false);
  };

  const toggleRule = (rule: WAFRules) => {
    dispatch({ type: 'UPDATE_WAF_RULE', payload: { ...rule, enabled: !rule.enabled } });
  };

  const deleteRule = (id: string) => {
    dispatch({ type: 'SET_WAF_RULES', payload: wafRules.filter((r) => r.id !== id) });
  };

  const startEdit = (rule: WAFRules) => {
    setEditId(rule.id);
    setEditForm({ name: rule.name, description: rule.description, pattern: rule.pattern, action: rule.action, priority: rule.priority });
  };

  const saveEdit = () => {
    if (!editId) return;
    const existing = wafRules.find((r) => r.id === editId);
    if (!existing) return;
    dispatch({ type: 'UPDATE_WAF_RULE', payload: { ...existing, ...editForm } });
    setEditId(null);
  };

  const totalHits = wafRules.reduce((a, r) => a + r.hits, 0);
  const activeRules = wafRules.filter((r) => r.enabled).length;

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Total Rules</p>
          <p className="text-2xl font-bold text-waf-text">{wafRules.length}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Active</p>
          <p className="text-2xl font-bold text-waf-orange">{activeRules}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Total Hits</p>
          <p className="text-2xl font-bold text-waf-orange">{totalHits.toLocaleString()}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Disabled</p>
          <p className="text-2xl font-bold text-waf-dim">{wafRules.length - activeRules}</p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Manage WAF rules for blocking malicious traffic patterns.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Rule
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">New WAF Rule</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input type="text" placeholder="Rule name" value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Description" value={newRule.description} onChange={(e) => setNewRule({ ...newRule, description: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <select value={newRule.category} onChange={(e) => setNewRule({ ...newRule, category: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              {Object.entries(categoryLabels).map(([k, v]) => (<option key={k} value={k}>{v}</option>))}
            </select>
            <select value={newRule.action} onChange={(e) => setNewRule({ ...newRule, action: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="block">Block</option>
              <option value="challenge">Challenge</option>
              <option value="log">Log Only</option>
            </select>
            <input type="number" placeholder="Priority (1-10)" value={newRule.priority} onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) || 5 })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <input type="text" placeholder="Regex pattern (e.g. <script|onerror=)" value={newRule.pattern} onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Add Rule</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      <div className="space-y-3">
        {wafRules.map((rule) => (
          <motion.div key={rule.id} layout className="bg-waf-panel border border-waf-border rounded-xl p-4">
            {editId === rule.id ? (
              <div className="space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                  <input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <input type="text" value={editForm.pattern} onChange={(e) => setEditForm({ ...editForm, pattern: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange font-mono" />
                <div className="flex gap-2">
                  <button onClick={saveEdit} className="flex items-center gap-1 px-3 py-1.5 bg-waf-success text-white rounded text-sm hover:bg-emerald-600"><Check className="w-3.5 h-3.5" /> Save</button>
                  <button onClick={() => setEditId(null)} className="flex items-center gap-1 px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border"><X className="w-3.5 h-3.5" /> Cancel</button>
                </div>
              </div>
            ) : (
              <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <FileText className="w-4 h-4 text-waf-orange shrink-0" />
                    <span className="text-waf-text font-medium text-sm">{rule.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${categoryColors[rule.category]}`}>{categoryLabels[rule.category] || rule.category}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${rule.action === 'block' ? 'bg-red-500/10 text-red-500' : rule.action === 'challenge' ? 'bg-waf-orange/10 text-waf-amber' : 'bg-waf-orange/10 text-waf-orange'}`}>{rule.action}</span>
                  </div>
                  <p className="text-waf-dim text-xs mt-1">{rule.description}</p>
                  <div className="flex items-center gap-3 mt-2">
                    <code className="text-xs text-waf-muted bg-waf-elevated px-2 py-0.5 rounded font-mono truncate max-w-[300px]">{rule.pattern}</code>
                    <span className="text-xs text-waf-dim">Priority: {rule.priority}</span>
                    <span className="text-xs text-waf-orange font-bold">{rule.hits} hits</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => toggleRule(rule)} className="text-waf-muted hover:text-waf-text">
                    {rule.enabled ? <ToggleRight className="w-6 h-6 text-waf-orange" /> : <ToggleLeft className="w-6 h-6 text-waf-dim" />}
                  </button>
                  <button onClick={() => startEdit(rule)} className="p-1.5 rounded-md hover:bg-waf-elevated text-waf-muted hover:text-waf-text"><Edit3 className="w-4 h-4" /></button>
                  <button onClick={() => deleteRule(rule.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
                </div>
              </div>
            )}
          </motion.div>
        ))}
      </div>
    </div>
  );
}

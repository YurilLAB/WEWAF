import { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, Plus, Trash2, Edit3, Check, X, Shield, ExternalLink } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { Domain } from '../../store/wafStore';

export default function DomainsPage() {
  const { state, dispatch } = useWAF();
  const { domains } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState({ name: '', originIP: '' });
  const [editForm, setEditForm] = useState({ name: '', originIP: '' });

  const handleAdd = () => {
    if (!newDomain.name.trim() || !newDomain.originIP.trim()) return;
    const domain: Domain = {
      id: Date.now().toString(),
      name: newDomain.name.trim(),
      status: 'pending',
      ssl: false,
      originIP: newDomain.originIP.trim(),
      createdAt: new Date().toISOString(),
      trafficToday: 0,
      threatsBlocked: 0,
    };
    dispatch({ type: 'ADD_DOMAIN', payload: domain });
    setNewDomain({ name: '', originIP: '' });
    setShowAdd(false);
  };

  const handleDelete = (id: string) => {
    dispatch({ type: 'DELETE_DOMAIN', payload: id });
  };

  const startEdit = (d: Domain) => {
    setEditId(d.id);
    setEditForm({ name: d.name, originIP: d.originIP });
  };

  const saveEdit = () => {
    if (!editId) return;
    const existing = domains.find((d) => d.id === editId);
    if (!existing) return;
    dispatch({
      type: 'UPDATE_DOMAIN',
      payload: { ...existing, name: editForm.name, originIP: editForm.originIP },
    });
    setEditId(null);
  };

  const toggleSSL = (d: Domain) => {
    dispatch({ type: 'UPDATE_DOMAIN', payload: { ...d, ssl: !d.ssl } });
  };

  const toggleStatus = (d: Domain) => {
    const next: Domain['status'] = d.status === 'active' ? 'pending' : 'active';
    dispatch({ type: 'UPDATE_DOMAIN', payload: { ...d, status: next } });
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Manage domains protected by your WAF.</p>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center"
        >
          <Plus className="w-4 h-4" /> Add Domain
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">Add New Domain</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              type="text"
              placeholder="example.com"
              value={newDomain.name}
              onChange={(e) => setNewDomain({ ...newDomain, name: e.target.value })}
              className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange"
            />
            <input
              type="text"
              placeholder="Origin IP (e.g. 192.168.1.1)"
              value={newDomain.originIP}
              onChange={(e) => setNewDomain({ ...newDomain, originIP: e.target.value })}
              className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange"
            />
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600 transition-colors">
              Add Domain
            </button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors">
              Cancel
            </button>
          </div>
        </motion.div>
      )}

      {/* Domain Cards */}
      {domains.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Globe className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No domains configured</p>
          <p className="text-waf-dim text-xs mt-1">Add your first domain to start protecting it.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {domains.map((domain) => (
            <motion.div
              key={domain.id}
              layout
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="bg-waf-panel border border-waf-border rounded-xl p-4"
            >
              {editId === domain.id ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input
                      type="text"
                      value={editForm.name}
                      onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                      className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
                    />
                    <input
                      type="text"
                      value={editForm.originIP}
                      onChange={(e) => setEditForm({ ...editForm, originIP: e.target.value })}
                      className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button onClick={saveEdit} className="flex items-center gap-1 px-3 py-1.5 bg-waf-success text-white rounded text-sm hover:bg-emerald-600">
                      <Check className="w-3.5 h-3.5" /> Save
                    </button>
                    <button onClick={() => setEditId(null)} className="flex items-center gap-1 px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border">
                      <X className="w-3.5 h-3.5" /> Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-waf-orange shrink-0" />
                      <span className="text-waf-text font-medium text-sm truncate">{domain.name}</span>
                      <button
                        onClick={() => toggleStatus(domain)}
                        className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider ${
                          domain.status === 'active'
                            ? 'bg-waf-success/10 text-waf-orange'
                            : domain.status === 'error'
                            ? 'bg-red-500/10 text-red-500'
                            : 'bg-waf-orange/10 text-waf-amber'
                        }`}
                      >
                        {domain.status}
                      </button>
                    </div>
                    <div className="flex items-center gap-3 mt-1.5 text-xs text-waf-dim">
                      <span className="flex items-center gap-1">
                        <ExternalLink className="w-3 h-3" /> Origin: {domain.originIP}
                      </span>
                      <span>Traffic: {domain.trafficToday.toLocaleString()}</span>
                      <span className="flex items-center gap-1 text-red-500">
                        <Shield className="w-3 h-3" /> Blocked: {domain.threatsBlocked}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleSSL(domain)}
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        domain.ssl ? 'bg-waf-success/10 text-waf-orange' : 'bg-waf-elevated text-waf-dim'
                      }`}
                    >
                      {domain.ssl ? 'SSL On' : 'SSL Off'}
                    </button>
                    <button onClick={() => startEdit(domain)} className="p-1.5 rounded-md hover:bg-waf-elevated text-waf-muted hover:text-waf-text transition-colors">
                      <Edit3 className="w-4 h-4" />
                    </button>
                    <button onClick={() => handleDelete(domain.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500 transition-colors">
                      <Trash2 className="w-4 h-4" />
                    </button>
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

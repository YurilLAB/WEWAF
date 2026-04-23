import { useState } from 'react';
import { motion } from 'framer-motion';
import { Server, Plus, Trash2, Shield, AlertTriangle } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { DNSRecord } from '../../store/wafStore';

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'] as const;

export default function DNSPage() {
  const { state, dispatch } = useWAF();
  const { dnsRecords, domains } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [newRecord, setNewRecord] = useState<Partial<DNSRecord>>({
    type: 'A',
    name: '',
    value: '',
    ttl: 300,
    proxied: true,
  });
  const [selectedDomain, setSelectedDomain] = useState(domains[0]?.id || '');

  const handleAdd = () => {
    if (!newRecord.name?.trim() || !newRecord.value?.trim()) return;
    const record: DNSRecord = {
      id: Date.now().toString(),
      domainId: selectedDomain || 'default',
      type: newRecord.type || 'A',
      name: newRecord.name.trim(),
      value: newRecord.value.trim(),
      ttl: newRecord.ttl || 300,
      proxied: newRecord.proxied ?? true,
    };
    dispatch({ type: 'ADD_DNS_RECORD', payload: record });
    setNewRecord({ type: 'A', name: '', value: '', ttl: 300, proxied: true });
    setShowAdd(false);
  };

  const handleDelete = (id: string) => {
    dispatch({ type: 'DELETE_DNS_RECORD', payload: id });
  };

  const toggleProxied = (record: DNSRecord) => {
    dispatch({ type: 'SET_DNS_RECORDS', payload: dnsRecords.map((r) => (r.id === record.id ? { ...r, proxied: !r.proxied } : r)) });
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Manage DNS records for your protected domains.</p>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-violet-600 transition-colors w-full sm:w-auto justify-center"
        >
          <Plus className="w-4 h-4" /> Add Record
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">Add DNS Record</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {domains.length > 0 && (
              <select
                value={selectedDomain}
                onChange={(e) => setSelectedDomain(e.target.value)}
                className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
              >
                {domains.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            )}
            <select
              value={newRecord.type}
              onChange={(e) => setNewRecord({ ...newRecord, type: e.target.value as any })}
              className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
            >
              {recordTypes.map((t) => (<option key={t} value={t}>{t}</option>))}
            </select>
            <input type="text" placeholder="Name (e.g. www)" value={newRecord.name} onChange={(e) => setNewRecord({ ...newRecord, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Value" value={newRecord.value} onChange={(e) => setNewRecord({ ...newRecord, value: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex items-center gap-3">
            <input type="number" placeholder="TTL" value={newRecord.ttl} onChange={(e) => setNewRecord({ ...newRecord, ttl: parseInt(e.target.value) })} className="w-28 bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={newRecord.proxied} onChange={(e) => setNewRecord({ ...newRecord, proxied: e.target.checked })} className="rounded border-waf-border" />
              Proxied through WAF
            </label>
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Add Record</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      {dnsRecords.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Server className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No DNS records configured</p>
          <p className="text-waf-dim text-xs mt-1">Add DNS records to manage how traffic reaches your domains.</p>
        </div>
      ) : (
        <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3 hidden sm:table-cell">Value</th>
                  <th className="px-4 py-3">TTL</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {dnsRecords.map((record) => (
                  <tr key={record.id} className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors">
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 bg-waf-orange/10 text-waf-amber text-xs font-medium rounded">{record.type}</span>
                    </td>
                    <td className="px-4 py-3 text-waf-text text-sm">{record.name}</td>
                    <td className="px-4 py-3 text-waf-muted text-sm hidden sm:table-cell truncate max-w-[200px]">{record.value}</td>
                    <td className="px-4 py-3 text-waf-dim text-sm">{record.ttl}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleProxied(record)}
                        className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                          record.proxied ? 'bg-waf-success/10 text-waf-orange' : 'bg-waf-orange/10 text-waf-amber'
                        }`}
                      >
                        {record.proxied ? <Shield className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                        {record.proxied ? 'Proxied' : 'DNS Only'}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => handleDelete(record.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500 transition-colors">
                        <Trash2 className="w-4 h-4" />
                      </button>
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

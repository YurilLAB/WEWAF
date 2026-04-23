import { useState } from 'react';
import { motion } from 'framer-motion';
import { Network, Plus, Trash2, ArrowLeftRight } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { Tunnel } from '../../store/wafStore';

export default function TunnelPage() {
  const { state, dispatch } = useWAF();
  const { tunnels } = state;
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: '', protocol: 'wireguard' as 'wireguard' | 'ipsec' | 'openvpn', localEndpoint: '', remoteEndpoint: '', port: 51820 });

  const handleAdd = () => {
    if (!form.name.trim() || !form.localEndpoint.trim() || !form.remoteEndpoint.trim()) return;
    const tunnel: Tunnel = {
      id: Date.now().toString(),
      name: form.name.trim(),
      status: 'inactive',
      protocol: form.protocol,
      localEndpoint: form.localEndpoint.trim(),
      remoteEndpoint: form.remoteEndpoint.trim(),
      port: form.port,
      uptime: 0,
      bytesTransferred: 0,
    };
    dispatch({ type: 'SET_TUNNELS', payload: [...tunnels, tunnel] });
    setForm({ name: '', protocol: 'wireguard', localEndpoint: '', remoteEndpoint: '', port: 51820 });
    setShowAdd(false);
  };

  const toggleStatus = (t: Tunnel) => {
    const next: Tunnel['status'] = t.status === 'active' ? 'inactive' : 'active';
    dispatch({ type: 'SET_TUNNELS', payload: tunnels.map((tu) => (tu.id === t.id ? { ...tu, status: next } : tu)) });
  };

  const deleteTunnel = (id: string) => {
    dispatch({ type: 'SET_TUNNELS', payload: tunnels.filter((t) => t.id !== id) });
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-waf-dim text-xs lg:text-sm">Manage secure tunnels for Zero Trust network access.</p>
        <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors w-full sm:w-auto justify-center">
          <Plus className="w-4 h-4" /> Add Tunnel
        </button>
      </div>

      {showAdd && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3">
          <h3 className="text-waf-text font-medium text-sm">New Tunnel</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input type="text" placeholder="Tunnel name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as any })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="wireguard">WireGuard</option>
              <option value="ipsec">IPsec</option>
              <option value="openvpn">OpenVPN</option>
            </select>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input type="text" placeholder="Local endpoint" value={form.localEndpoint} onChange={(e) => setForm({ ...form, localEndpoint: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="text" placeholder="Remote endpoint" value={form.remoteEndpoint} onChange={(e) => setForm({ ...form, remoteEndpoint: e.target.value })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
            <input type="number" placeholder="Port" value={form.port} onChange={(e) => setForm({ ...form, port: parseInt(e.target.value) })} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex gap-2">
            <button onClick={handleAdd} className="px-4 py-2 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600">Create Tunnel</button>
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border">Cancel</button>
          </div>
        </motion.div>
      )}

      {tunnels.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Network className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No tunnels configured</p>
          <p className="text-waf-dim text-xs mt-1">Add secure tunnels to connect remote networks.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {tunnels.map((tunnel) => (
            <motion.div key={tunnel.id} layout className="bg-waf-panel border border-waf-border rounded-xl p-4">
              <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <ArrowLeftRight className="w-4 h-4 text-waf-orange" />
                    <span className="text-waf-text font-medium text-sm">{tunnel.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${
                      tunnel.status === 'active' ? 'bg-waf-success/10 text-waf-orange' : tunnel.status === 'error' ? 'bg-red-500/10 text-red-500' : 'bg-waf-dim/10 text-waf-dim'
                    }`}>{tunnel.status}</span>
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-waf-muted">
                    <span>Protocol: {tunnel.protocol.toUpperCase()}</span>
                    <span>Local: {tunnel.localEndpoint}:{tunnel.port}</span>
                    <span>Remote: {tunnel.remoteEndpoint}</span>
                    {tunnel.status === 'active' && <span className="text-waf-orange">Uptime: {tunnel.uptime}s</span>}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => toggleStatus(tunnel)} className="px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-sm hover:bg-waf-border">{tunnel.status === 'active' ? 'Disconnect' : 'Connect'}</button>
                  <button onClick={() => deleteTunnel(tunnel.id)} className="p-1.5 rounded-md hover:bg-red-500/10 text-waf-muted hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}

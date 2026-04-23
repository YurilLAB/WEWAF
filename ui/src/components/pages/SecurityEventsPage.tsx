import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Ban, Zap, Search, Bug, Clock, Crosshair } from 'lucide-react';
import { useWAF } from '../../store/wafStore';

const eventIcons: Record<string, any> = {
  xss: Bug, sql_injection: Crosshair, brute_force: Ban, ddos: Zap, bot: Bug, rate_limit: Clock, ip_reputation: AlertTriangle,
};

const severityColors: Record<string, string> = {
  low: 'bg-waf-success/10 text-waf-orange', medium: 'bg-waf-orange/10 text-waf-amber', high: 'bg-orange-500/10 text-orange-500', critical: 'bg-red-500/10 text-red-500',
};

const typeColors: Record<string, string> = {
  xss: 'text-red-500', sql_injection: 'text-waf-amber', brute_force: 'text-orange-500', ddos: 'text-waf-amber', bot: 'text-waf-orange', rate_limit: 'text-waf-muted', ip_reputation: 'text-waf-orange',
};

export default function SecurityEventsPage() {
  const { state } = useWAF();
  const { securityEvents } = state;
  const [filter, setFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = useMemo(() => {
    return securityEvents.filter((e) => {
      if (filter !== 'all' && e.type !== filter) return false;
      if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
      if (searchQuery && !e.sourceIP.includes(searchQuery) && !e.url.includes(searchQuery) && !e.country.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    });
  }, [securityEvents, filter, severityFilter, searchQuery]);

  const stats = useMemo(() => ({
    total: securityEvents.length,
    critical: securityEvents.filter((e) => e.severity === 'critical').length,
    blocked: securityEvents.filter((e) => e.action === 'blocked').length,
    high: securityEvents.filter((e) => e.severity === 'high').length,
  }), [securityEvents]);

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">Review and analyze security events detected by your WAF.</p>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={Shield} label="Total Events" value={stats.total} color="text-waf-orange" />
        <StatCard icon={AlertTriangle} label="Critical" value={stats.critical} color="text-red-500" />
        <StatCard icon={Ban} label="Blocked" value={stats.blocked} color="text-waf-orange" />
        <StatCard icon={Zap} label="High Severity" value={stats.high} color="text-waf-amber" />
      </div>

      {/* Filters */}
      <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
            <input type="text" placeholder="Search by IP, URL, country..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full bg-waf-elevated border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
          </div>
          <div className="flex gap-2">
            <select value={filter} onChange={(e) => setFilter(e.target.value)} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="all">All Types</option>
              <option value="xss">XSS</option>
              <option value="sql_injection">SQLi</option>
              <option value="brute_force">Brute Force</option>
              <option value="ddos">DDoS</option>
              <option value="bot">Bot</option>
              <option value="rate_limit">Rate Limit</option>
            </select>
            <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Events List */}
      {filtered.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Shield className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No security events</p>
          <p className="text-waf-dim text-xs mt-1">Events will appear when your WAF detects threats.</p>
        </div>
      ) : (
        <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3 hidden sm:table-cell">Source</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Country</th>
                  <th className="px-4 py-3 hidden xl:table-cell">URL</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3 hidden md:table-cell">Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => {
                  const Icon = eventIcons[event.type] || Shield;
                  return (
                    <motion.tr key={event.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-4 h-4 ${typeColors[event.type] || 'text-waf-muted'}`} />
                          <span className="text-sm text-waf-text capitalize">{event.type.replace(/_/g, ' ')}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${severityColors[event.severity]}`}>{event.severity}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden sm:table-cell font-mono">{event.sourceIP}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden lg:table-cell">{event.country}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden xl:table-cell truncate max-w-[200px]">{event.url}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${event.action === 'blocked' ? 'bg-red-500/10 text-red-500' : event.action === 'challenged' ? 'bg-waf-orange/10 text-waf-amber' : 'bg-waf-orange/10 text-waf-orange'}`}>{event.action}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-waf-dim hidden md:table-cell">{new Date(event.timestamp).toLocaleTimeString()}</td>
                    </motion.tr>
                  );
                })}
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
      <p className={`text-xl font-bold tabular-nums ${color}`}>{value.toLocaleString()}</p>
    </motion.div>
  );
}

import { useState, useMemo, useEffect } from 'react';
import { Logs, Search, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import { api } from '../../services/api';

export default function RequestLogsPage() {
  const { state, dispatch } = useWAF();
  const { requestLogs } = state;

  useEffect(() => {
    api.getRequests().then((data) => {
      if (data?.requests) {
        const logs = data.requests.map((r, i) => ({
          id: `req-${i}-${Date.now()}`,
          timestamp: r.ts,
          method: r.method,
          url: r.path,
          sourceIP: r.ip,
          country: 'Unknown',
          userAgent: '',
          status: 'blocked' as const,
          responseTime: 0,
          ruleTriggered: r.rule_id,
        }));
        dispatch({ type: 'SET_REQUEST_LOGS', payload: logs });
      }
    });
  }, [dispatch]);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return requestLogs.filter((l) => {
      if (statusFilter !== 'all' && l.status !== statusFilter) return false;
      if (search && !l.sourceIP.includes(search) && !l.url.includes(search) && !l.userAgent.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [requestLogs, statusFilter, search]);

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">Browse detailed request logs passing through your WAF.</p>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
          <input type="text" placeholder="Search by IP, URL, user agent..." value={search} onChange={(e) => setSearch(e.target.value)} className="w-full bg-waf-panel border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
        </div>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="bg-waf-panel border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
          <option value="all">All Status</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
          <option value="challenged">Challenged</option>
        </select>
      </div>

      {filtered.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Logs className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No request logs yet</p>
          <p className="text-waf-dim text-xs mt-1">Logs will appear when traffic flows through your WAF.</p>
        </div>
      ) : (
        <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Method</th>
                  <th className="px-4 py-3">URL</th>
                  <th className="px-4 py-3 hidden sm:table-cell">IP</th>
                  <th className="px-4 py-3 hidden md:table-cell">Country</th>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Response</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => (
                  <>
                    <tr key={log.id} onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)} className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors cursor-pointer">
                      <td className="px-4 py-3">
                        <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                          log.status === 'allowed' ? 'bg-waf-success/10 text-waf-orange' : log.status === 'blocked' ? 'bg-red-500/10 text-red-500' : 'bg-waf-orange/10 text-waf-amber'
                        }`}>
                          {log.status === 'allowed' ? <CheckCircle className="w-3 h-3" /> : log.status === 'blocked' ? <XCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                          {log.status}
                        </span>
                      </td>
                      <td className="px-4 py-3"><span className="px-1.5 py-0.5 bg-waf-elevated text-waf-orange text-xs font-medium rounded">{log.method}</span></td>
                      <td className="px-4 py-3 text-sm text-waf-text truncate max-w-[150px]">{log.url}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden sm:table-cell font-mono">{log.sourceIP}</td>
                      <td className="px-4 py-3 text-sm text-waf-muted hidden md:table-cell">{log.country}</td>
                      <td className="px-4 py-3 text-xs text-waf-dim">{log.responseTime}ms</td>
                      <td className="px-4 py-3 text-xs text-waf-dim hidden lg:table-cell">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="px-4 py-3">{expandedRow === log.id ? <ChevronUp className="w-4 h-4 text-waf-dim" /> : <ChevronDown className="w-4 h-4 text-waf-dim" />}</td>
                    </tr>
                    {expandedRow === log.id && (
                      <tr className="bg-waf-elevated/20">
                        <td colSpan={8} className="px-4 py-3">
                          <div className="text-xs text-waf-dim space-y-1">
                            <p><span className="text-waf-muted">User Agent:</span> {log.userAgent}</p>
                            {log.ruleTriggered && <p><span className="text-waf-muted">Rule Triggered:</span> {log.ruleTriggered}</p>}
                            <p><span className="text-waf-muted">Full URL:</span> {log.url}</p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

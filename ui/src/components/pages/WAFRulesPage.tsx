import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Search, FileText } from 'lucide-react';
import { api } from '../../services/api';
import type { CompiledRule } from '../../services/api';

const CATEGORIES = ['All', 'XSS', 'SQLi', 'Bot', 'Egress', 'Injection', 'Protocol', 'Cloud', 'Other'] as const;
type Category = (typeof CATEGORIES)[number];

function inferCategory(rule: CompiledRule): Category {
  const id = rule.id?.toUpperCase?.() ?? '';
  if (id.startsWith('XSS')) return 'XSS';
  if (id.startsWith('SQLI') || id.startsWith('NOSQL')) return 'SQLi';
  if (id.startsWith('BOT') || id.startsWith('SCAN')) return 'Bot';
  if (id.startsWith('EGRESS')) return 'Egress';
  if (id.startsWith('CLOUD') || id.startsWith('K8S') || id.startsWith('DOCKER')) return 'Cloud';
  if (
    id.startsWith('RCE') || id.startsWith('TRAV') || id.startsWith('LDAP') ||
    id.startsWith('CRLF') || id.startsWith('XXE') || id.startsWith('XPATH') ||
    id.startsWith('SSI') || id.startsWith('SHELL') || id.startsWith('SSTI') ||
    id.startsWith('DESER') || id.startsWith('JSON') || id.startsWith('XMLRPC') ||
    id.startsWith('JNDI') || id.startsWith('PHP') || id.startsWith('SPRING') ||
    id.startsWith('UPLOAD') || id.startsWith('HEADER') || id.startsWith('HPP') ||
    id.startsWith('B64') || id.startsWith('CORS') || id.startsWith('CT') ||
    id.startsWith('MASS') || id.startsWith('LOG') || id.startsWith('CRYPTO') ||
    id.startsWith('STUFF') || id.startsWith('BL') || id.startsWith('IDOR') ||
    id.startsWith('CLICK') || id.startsWith('METHOD') || id.startsWith('CACHE') ||
    id.startsWith('HOST') || id.startsWith('GRAPHQL') || id.startsWith('OAUTH') ||
    id.startsWith('JWT') || id.startsWith('REDIR') || id.startsWith('SSRF') ||
    id.startsWith('SMUG') || id.startsWith('PROTO') || id.startsWith('DNS')
  ) {
    return 'Injection';
  }
  if (
    id.startsWith('SSRF') || id.startsWith('SMUG') || id.startsWith('HOST') ||
    id.startsWith('HEADER') || id.startsWith('METHOD') || id.startsWith('REDIR') ||
    id.startsWith('CRLF') || id.startsWith('PROTO') || id.startsWith('DNS') ||
    id.startsWith('CACHE') || id.startsWith('HPP') || id.startsWith('B64') ||
    id.startsWith('CORS') || id.startsWith('CT') || id.startsWith('MASS') ||
    id.startsWith('LOG') || id.startsWith('CRYPTO') || id.startsWith('STUFF') ||
    id.startsWith('BL') || id.startsWith('IDOR') || id.startsWith('CLICK') ||
    id.startsWith('GRAPHQL') || id.startsWith('OAUTH') || id.startsWith('JWT')
  ) {
    return 'Protocol';
  }
  return 'Other';
}

function actionColor(action: string): string {
  const a = action?.toLowerCase?.() ?? '';
  if (a === 'block') return 'bg-red-500/10 text-red-500';
  if (a === 'log') return 'bg-blue-500/10 text-blue-500';
  if (a === 'drop') return 'bg-orange-500/10 text-orange-500';
  if (a === 'pass') return 'bg-waf-success/10 text-waf-success';
  return 'bg-waf-orange/10 text-waf-orange';
}

function phaseLabel(phase: string | number): string {
  const p = String(phase).toLowerCase();
  if (p === '0' || p === 'request_headers') return 'Request Headers';
  if (p === '1' || p === 'request_body') return 'Request Body';
  if (p === '2' || p === 'response_headers') return 'Response Headers';
  if (p === '3' || p === 'response_body') return 'Response Body';
  if (p === '4' || p === 'logging') return 'Logging';
  if (p === '5' || p === 'egress_request') return 'Egress';
  return String(phase);
}

export default function WAFRulesPage() {
  const [rules, setRules] = useState<CompiledRule[]>([]);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<Category>('All');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.getRules().then((data) => {
      if (data?.rules) {
        setRules(data.rules);
      } else {
        setRules([]);
      }
      setLoading(false);
    });
  }, []);

  const filtered = useMemo(() => {
    return rules.filter((rule) => {
      const cat = inferCategory(rule);
      if (categoryFilter !== 'All' && cat !== categoryFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        const idMatch = rule.id?.toLowerCase().includes(s);
        const nameMatch = rule.name?.toLowerCase().includes(s);
        const descMatch = rule.description?.toLowerCase().includes(s);
        if (!idMatch && !nameMatch && !descMatch) return false;
      }
      return true;
    });
  }, [rules, categoryFilter, search]);

  const stats = useMemo(() => {
    const total = rules.length;
    const block = rules.filter((r) => r.action?.toLowerCase?.() === 'block').length;
    const log = rules.filter((r) => r.action?.toLowerCase?.() === 'log').length;
    const drop = rules.filter((r) => r.action?.toLowerCase?.() === 'drop').length;
    return { total, block, log, drop };
  }, [rules]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { All: rules.length };
    for (const rule of rules) {
      const cat = inferCategory(rule);
      counts[cat] = (counts[cat] ?? 0) + 1;
    }
    return counts;
  }, [rules]);

  return (
    <div className="space-y-4 lg:space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Total Rules</p>
          <p className="text-2xl font-bold text-waf-text">{stats.total}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Block</p>
          <p className="text-2xl font-bold text-red-500">{stats.block}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Log</p>
          <p className="text-2xl font-bold text-blue-500">{stats.log}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Drop</p>
          <p className="text-2xl font-bold text-orange-500">{stats.drop}</p>
        </div>
      </div>

      <p className="text-waf-dim text-xs lg:text-sm">Browse and filter WAF detection rules served by the backend.</p>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
          <input
            type="text"
            placeholder="Search by ID, name, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-waf-panel border border-waf-border rounded-lg pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange"
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              categoryFilter === cat
                ? 'bg-waf-orange text-white'
                : 'bg-waf-panel border border-waf-border text-waf-muted hover:text-waf-text hover:bg-waf-elevated'
            }`}
          >
            {cat}
            <span className="ml-1.5 opacity-70">({categoryCounts[cat] ?? 0})</span>
          </button>
        ))}
      </div>

      {loading ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <p className="text-waf-muted font-medium">Loading rules...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
          <Shield className="w-10 h-10 text-waf-dim mx-auto mb-3" />
          <p className="text-waf-muted font-medium">No rules found</p>
          <p className="text-waf-dim text-xs mt-1">
            {rules.length === 0 ? 'The backend returned zero rules.' : 'Try adjusting your search or category filter.'}
          </p>
        </div>
      ) : (
        <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-waf-border text-xs text-waf-muted uppercase">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3 hidden md:table-cell">Phase</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3 hidden sm:table-cell">Score</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Description</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => (
                  <motion.tr
                    key={rule.id}
                    layout
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="border-b border-waf-border/50 hover:bg-waf-elevated/30 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-waf-orange shrink-0" />
                        <span className="text-xs text-waf-muted font-mono">{rule.id}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-waf-text font-medium">{rule.name}</td>
                    <td className="px-4 py-3 text-xs text-waf-dim hidden md:table-cell">{phaseLabel(rule.phase)}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${actionColor(String(rule.action))}`}>
                        {rule.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-waf-dim hidden sm:table-cell">{rule.score}</td>
                    <td className="px-4 py-3 text-xs text-waf-dim hidden lg:table-cell max-w-xs truncate">{rule.description}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

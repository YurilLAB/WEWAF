import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Database, Save, TrendingUp } from 'lucide-react';
import { api } from '../../services/api';
import type { GraphQLStatsResponse, GraphQLSample } from '../../services/api';

type Form = {
  graphql_enabled: boolean;
  graphql_block_on_error: boolean;
  graphql_max_depth: number;
  graphql_max_aliases: number;
  graphql_max_fields: number;
  graphql_role_header: string;
};

export default function GraphQLPage() {
  const [stats, setStats] = useState<GraphQLStatsResponse | null>(null);
  const [recent, setRecent] = useState<GraphQLSample[]>([]);
  const [form, setForm] = useState<Form>({
    graphql_enabled: false,
    graphql_block_on_error: false,
    graphql_max_depth: 7,
    graphql_max_aliases: 10,
    graphql_max_fields: 200,
    graphql_role_header: 'X-User-Role',
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.getGraphQLStats().then((resp) => {
        if (cancelled || !resp) return;
        setStats(resp);
        // Mirror form state from stats so form stays in sync with the
        // backend across hot-reload / external config pushes.
        setForm((prev) => ({
          graphql_enabled: !!resp.enabled,
          graphql_block_on_error: !!resp.block,
          graphql_max_depth: resp.max_depth ?? prev.graphql_max_depth,
          graphql_max_aliases: resp.max_aliases ?? prev.graphql_max_aliases,
          graphql_max_fields: resp.max_fields ?? prev.graphql_max_fields,
          graphql_role_header: resp.role_header || prev.graphql_role_header,
        }));
      }).catch(() => {
        if (!cancelled) setError('Failed to fetch GraphQL stats.');
      });
      api.getGraphQLRecent().then((resp) => {
        if (cancelled || !resp) return;
        setRecent(resp.recent || []);
      }).catch(() => {});
    };
    load();
    const interval = window.setInterval(load, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setSaving(true);
    setError(null);
    if (form.graphql_max_depth < 1 || form.graphql_max_depth > 50) {
      setError('Max depth must be between 1 and 50.');
      setSaving(false);
      return;
    }
    try {
      const res = await api.updateConfig({
        graphql_enabled: form.graphql_enabled,
        graphql_block_on_error: form.graphql_block_on_error,
        graphql_max_depth: form.graphql_max_depth,
        graphql_max_aliases: form.graphql_max_aliases,
        graphql_max_fields: form.graphql_max_fields,
        graphql_role_header: form.graphql_role_header,
      });
      if (!res) setError('Save failed.');
      else {
        setSaved(true);
        setTimeout(() => setSaved(false), 1500);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  const s = stats?.stats;

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">
        Schema-aware GraphQL validation. Parses every incoming query, enforces
        depth / alias / field limits against DoS amplification, and — with an
        optional SDL file — enforces <code>@requires(role: "…")</code>
        field-level authorisation. Blocking is opt-in; observe-only by default.
      </p>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <Database className="w-4 h-4 text-waf-orange" /> Configuration
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input type="checkbox" checked={form.graphql_enabled}
              onChange={(e) => setForm((f) => ({ ...f, graphql_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange" />
            <div>
              <div className="text-sm text-waf-text font-medium">GraphQL validation enabled</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Auto-detects <code>/graphql</code>, <code>/query</code>, and sub-paths.
              </p>
            </div>
          </label>
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input type="checkbox" checked={form.graphql_block_on_error}
              disabled={!form.graphql_enabled}
              onChange={(e) => setForm((f) => ({ ...f, graphql_block_on_error: e.target.checked }))}
              className="mt-0.5 accent-waf-orange" />
            <div>
              <div className="text-sm text-waf-text font-medium">Block on violation</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                If off (default), violations are counted but the request still proxies.
              </p>
            </div>
          </label>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Max depth</label>
            <input type="number" min={1} max={50} value={form.graphql_max_depth}
              onChange={(e) => setForm((f) => ({ ...f, graphql_max_depth: Math.max(1, Math.min(50, Number(e.target.value) || 7)) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Max aliases</label>
            <input type="number" min={1} value={form.graphql_max_aliases}
              onChange={(e) => setForm((f) => ({ ...f, graphql_max_aliases: Math.max(1, Number(e.target.value) || 10) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Max fields</label>
            <input type="number" min={1} value={form.graphql_max_fields}
              onChange={(e) => setForm((f) => ({ ...f, graphql_max_fields: Math.max(1, Number(e.target.value) || 200) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Role header</label>
            <input type="text" value={form.graphql_role_header}
              onChange={(e) => setForm((f) => ({ ...f, graphql_role_header: e.target.value }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
        </div>

        {error && <div className="mt-3 p-2.5 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">{error}</div>}

        <div className="mt-4 flex items-center gap-3">
          <button onClick={save} disabled={saving}
            className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
            <Save className="w-4 h-4" /> {saved ? 'Saved' : 'Save'}
          </button>
          <p className="text-[10px] text-waf-dim">
            Schema file path is set in <code>config.json</code> → <code>graphql_schema_file</code>.
          </p>
        </div>
      </motion.div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          { label: 'Requests', v: s?.requests ?? 0 },
          { label: 'Blocked', v: s?.blocked ?? 0, color: 'text-red-500' },
          { label: 'Depth fails', v: s?.depth_fails ?? 0 },
          { label: 'Alias fails', v: s?.alias_fails ?? 0 },
          { label: 'Field fails', v: s?.field_fails ?? 0 },
          { label: 'Auth fails', v: s?.auth_fails ?? 0 },
          { label: 'Parse fails', v: s?.parse_fails ?? 0 },
        ].map((c) => (
          <div key={c.label} className="bg-waf-panel border border-waf-border rounded-xl p-3">
            <p className="text-waf-muted text-xs mb-1">{c.label}</p>
            <p className={`text-xl font-bold tabular-nums ${c.color ?? 'text-waf-text'}`}>
              {c.v.toLocaleString()}
            </p>
          </div>
        ))}
      </div>

      <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-waf-border">
          <h3 className="text-sm font-semibold text-waf-text flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-waf-orange" /> Recent operations
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-waf-muted uppercase text-[10px]">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Operation</th>
                <th className="px-4 py-3">Depth</th>
                <th className="px-4 py-3">Aliases</th>
                <th className="px-4 py-3">Fields</th>
                <th className="px-4 py-3">Blocked</th>
                <th className="px-4 py-3">Reason</th>
              </tr>
            </thead>
            <tbody>
              {recent.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-6 text-center text-waf-dim">No GraphQL operations inspected yet.</td></tr>
              ) : recent.map((r, i) => (
                <tr key={i} className="border-t border-waf-border/50">
                  <td className="px-4 py-2.5 text-[10px] text-waf-dim">{new Date(r.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-2.5 truncate max-w-[200px]">{r.operation || '(anonymous)'}</td>
                  <td className="px-4 py-2.5 tabular-nums">{r.depth}</td>
                  <td className="px-4 py-2.5 tabular-nums">{r.aliases}</td>
                  <td className="px-4 py-2.5 tabular-nums">{r.fields}</td>
                  <td className={`px-4 py-2.5 ${r.blocked ? 'text-red-500 font-semibold' : 'text-waf-dim'}`}>{r.blocked ? 'yes' : 'no'}</td>
                  <td className="px-4 py-2.5 text-[10px] text-waf-muted truncate max-w-[300px]">{r.reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

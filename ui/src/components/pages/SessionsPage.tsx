import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Users, ShieldCheck, AlertTriangle, Save } from 'lucide-react';
import { api } from '../../services/api';
import type { SessionView } from '../../services/api';

type ToggleForm = {
  session_tracking_enabled: boolean;
  browser_challenge_enabled: boolean;
  browser_challenge_block: boolean;
  session_block_threshold: number;
  session_request_rate_ceiling: number;
  session_path_count_ceiling: number;
};

function formatDuration(ms: number): string {
  if (ms <= 0) return '0s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function riskColor(score: number): string {
  if (score >= 60) return 'text-red-500 font-semibold';
  if (score >= 30) return 'text-orange-400';
  if (score > 0) return 'text-waf-orange';
  return 'text-waf-dim';
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [enabled, setEnabled] = useState(false);
  const [count, setCount] = useState(0);
  const [selected, setSelected] = useState<SessionView | null>(null);
  const [form, setForm] = useState<ToggleForm>({
    session_tracking_enabled: false,
    browser_challenge_enabled: false,
    browser_challenge_block: false,
    session_block_threshold: 0,
    session_request_rate_ceiling: 600,
    session_path_count_ceiling: 40,
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.getSessions(200).then((resp) => {
        if (cancelled || !resp) return;
        setSessions(resp.sessions || []);
        setEnabled(!!resp.enabled);
        setCount(resp.count || 0);
      }).catch(() => {
        if (!cancelled) setError('Failed to fetch sessions.');
      });
    };
    load();
    const interval = window.setInterval(load, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    api.getConfig().then((cfg) => {
      if (!cfg) return;
      const c = cfg as Record<string, unknown>;
      setForm((prev) => ({
        session_tracking_enabled: typeof c.session_tracking_enabled === 'boolean' ? c.session_tracking_enabled : prev.session_tracking_enabled,
        browser_challenge_enabled: typeof c.browser_challenge_enabled === 'boolean' ? c.browser_challenge_enabled : prev.browser_challenge_enabled,
        browser_challenge_block: typeof c.browser_challenge_block === 'boolean' ? c.browser_challenge_block : prev.browser_challenge_block,
        session_block_threshold: typeof c.session_block_threshold === 'number' ? c.session_block_threshold : prev.session_block_threshold,
        session_request_rate_ceiling: typeof c.session_request_rate_ceiling === 'number' && c.session_request_rate_ceiling > 0 ? c.session_request_rate_ceiling : prev.session_request_rate_ceiling,
        session_path_count_ceiling: typeof c.session_path_count_ceiling === 'number' && c.session_path_count_ceiling > 0 ? c.session_path_count_ceiling : prev.session_path_count_ceiling,
      }));
    });
  }, []);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await api.updateConfig({
        session_tracking_enabled: form.session_tracking_enabled,
        browser_challenge_enabled: form.browser_challenge_enabled,
        browser_challenge_block: form.browser_challenge_block,
        session_block_threshold: form.session_block_threshold,
        session_request_rate_ceiling: form.session_request_rate_ceiling,
        session_path_count_ceiling: form.session_path_count_ceiling,
      });
      if (!res) {
        setError('Save failed — check /api/errors.');
      } else {
        setSaved(true);
        setTimeout(() => setSaved(false), 1500);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">
        Per-session behavioural tracking + browser-integrity challenge.
        Enable tracking first; then enable the challenge to fingerprint headless automation.
        Risk scores are observe-only until you set Block Threshold &gt; 0.
      </p>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-waf-orange" /> Controls
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input type="checkbox" checked={form.session_tracking_enabled}
              onChange={(e) => setForm((f) => ({ ...f, session_tracking_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange" />
            <div>
              <div className="text-sm text-waf-text font-medium">Session tracking</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Issue <code>__wewaf_sid</code> cookie, accumulate per-session signals.
              </p>
            </div>
          </label>
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input type="checkbox" checked={form.browser_challenge_enabled}
              onChange={(e) => setForm((f) => ({ ...f, browser_challenge_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange" />
            <div>
              <div className="text-sm text-waf-text font-medium">Browser integrity challenge</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Serve <code>/api/browser-challenge.js</code>; failed probes raise session risk.
              </p>
            </div>
          </label>
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input type="checkbox" checked={form.browser_challenge_block}
              disabled={!form.browser_challenge_enabled}
              onChange={(e) => setForm((f) => ({ ...f, browser_challenge_block: e.target.checked }))}
              className="mt-0.5 accent-waf-orange" />
            <div>
              <div className="text-sm text-waf-text font-medium">Block on challenge fail</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                If off (default), failures only add to the risk score.
              </p>
            </div>
          </label>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Block threshold (0 = observe)</label>
            <input type="number" min={0} max={100} value={form.session_block_threshold}
              onChange={(e) => setForm((f) => ({ ...f, session_block_threshold: Math.max(0, Math.min(100, Number(e.target.value) || 0)) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Request-rate ceiling (req/min)</label>
            <input type="number" min={1} value={form.session_request_rate_ceiling}
              onChange={(e) => setForm((f) => ({ ...f, session_request_rate_ceiling: Math.max(1, Number(e.target.value) || 600) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Distinct-path ceiling</label>
            <input type="number" min={1} value={form.session_path_count_ceiling}
              onChange={(e) => setForm((f) => ({ ...f, session_path_count_ceiling: Math.max(1, Number(e.target.value) || 40) }))}
              className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
        </div>

        {error && <div className="mt-3 p-2.5 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">{error}</div>}

        <div className="mt-4">
          <button onClick={save} disabled={saving}
            className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
            <Save className="w-4 h-4" /> {saved ? 'Saved' : 'Save'}
          </button>
          <p className="text-[10px] text-waf-dim mt-2">
            Inline the challenge on protected pages via: <code>&lt;script src="/api/browser-challenge.js" async&gt;&lt;/script&gt;</code>{' '}
            and the beacon via: <code>&lt;script src="/api/browser-beacon.js" async&gt;&lt;/script&gt;</code>.
          </p>
        </div>
      </motion.div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Active sessions</p>
          <p className="text-2xl font-bold text-waf-text">{count}</p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Tracking</p>
          <p className={`text-2xl font-bold ${enabled ? 'text-waf-success' : 'text-waf-dim'}`}>
            {enabled ? 'On' : 'Off'}
          </p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">Challenge-passed</p>
          <p className="text-2xl font-bold text-waf-text">
            {sessions.filter((s) => s.challenge_passed).length}
          </p>
        </div>
        <div className="bg-waf-panel border border-waf-border rounded-xl p-3 lg:p-4">
          <p className="text-waf-muted text-xs mb-1">High risk (&ge;60)</p>
          <p className="text-2xl font-bold text-red-500">
            {sessions.filter((s) => s.risk_score >= 60).length}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-waf-panel border border-waf-border rounded-xl overflow-hidden">
          <div className="p-4 border-b border-waf-border">
            <h3 className="text-sm font-semibold text-waf-text flex items-center gap-2">
              <Users className="w-4 h-4 text-waf-orange" /> Live sessions
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-waf-muted uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Reqs</th>
                  <th className="px-4 py-3">Blocks</th>
                  <th className="px-4 py-3 hidden md:table-cell">Paths</th>
                  <th className="px-4 py-3 hidden md:table-cell">UAs</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Beacon</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Challenge</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-6 text-center text-waf-dim">
                    {enabled ? 'No sessions yet. Generate some traffic.' : 'Enable session tracking to populate this table.'}
                  </td></tr>
                ) : (
                  sessions.map((s) => (
                    <tr key={s.id} onClick={() => setSelected(s)}
                      className="border-t border-waf-border/50 hover:bg-waf-elevated/40 cursor-pointer">
                      <td className="px-4 py-2.5 font-mono text-[10px] text-waf-muted truncate max-w-[140px]">{s.id}</td>
                      <td className={`px-4 py-2.5 ${riskColor(s.risk_score)}`}>{s.risk_score}</td>
                      <td className="px-4 py-2.5">{s.request_count}</td>
                      <td className="px-4 py-2.5">{s.block_count}</td>
                      <td className="px-4 py-2.5 hidden md:table-cell">{s.paths.length}</td>
                      <td className="px-4 py-2.5 hidden md:table-cell">{s.user_agents.length}</td>
                      <td className="px-4 py-2.5 hidden lg:table-cell">{s.beacon_count}</td>
                      <td className="px-4 py-2.5 hidden lg:table-cell">
                        {s.challenge_passed
                          ? <span className="text-waf-success">passed</span>
                          : <span className="text-waf-dim">—</span>}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-waf-panel border border-waf-border rounded-xl p-4">
          <h3 className="text-sm font-semibold text-waf-text flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-waf-orange" /> Session detail
          </h3>
          {!selected ? (
            <p className="text-waf-dim text-xs">Select a session row to see details.</p>
          ) : (
            <div className="space-y-2 text-xs">
              <div><span className="text-waf-dim">ID:</span> <span className="font-mono text-[10px]">{selected.id}</span></div>
              <div><span className="text-waf-dim">Risk:</span> <span className={riskColor(selected.risk_score)}>{selected.risk_score}</span></div>
              <div><span className="text-waf-dim">Requests:</span> {selected.request_count} ({selected.block_count} blocked)</div>
              <div><span className="text-waf-dim">Mouse / Key events:</span> {selected.mouse_events} / {selected.key_events}</div>
              <div><span className="text-waf-dim">Time on page:</span> {formatDuration(selected.time_on_page_ms)}</div>
              <div><span className="text-waf-dim">Beacons received:</span> {selected.beacon_count}</div>
              <div><span className="text-waf-dim">Challenge:</span> {selected.challenge_passed ? 'passed' : 'not yet'}</div>
              <div><span className="text-waf-dim">IPs seen:</span> {selected.ips.join(', ') || '—'}</div>
              <div><span className="text-waf-dim">User-Agents:</span></div>
              <ul className="text-[10px] text-waf-muted ml-2 space-y-0.5 max-h-40 overflow-y-auto">
                {selected.user_agents.map((ua) => <li key={ua} className="truncate">{ua}</li>)}
              </ul>
              <div><span className="text-waf-dim">Paths:</span> {selected.paths.length}</div>
              <ul className="text-[10px] text-waf-muted ml-2 space-y-0.5 max-h-40 overflow-y-auto">
                {selected.paths.slice(0, 20).map((p) => <li key={p} className="truncate">{p}</li>)}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

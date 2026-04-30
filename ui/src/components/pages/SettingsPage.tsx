import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Cpu, HardDrive, Bell, Shield, Save, RotateCcw, Database, ArrowLeftRight, Network, Lock, Gauge, AlertTriangle, FileLock2, RefreshCw } from 'lucide-react';
import { useWAF, type WAFSettings } from '../../store/wafStore';
import { api } from '../../services/api';

// AuditChainCard surfaces the tamper-evident HMAC chain so operators can
// confirm log integrity and inspect recent ban / config / zero-trust
// mutations without dropping to the shell. Network failures degrade to
// a quiet "—" rather than throwing, so this card never breaks the page.
function AuditChainCard() {
  const [verify, setVerify] = useState<{ enabled: boolean; ok?: boolean; bad_seq?: number; total?: number; appends?: number; verify_fails?: number } | null>(null);
  const [tail, setTail] = useState<Array<{ seq: number; timestamp: string; kind: string; actor?: string; message: string }>>([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const [v, t] = await Promise.all([
        api.getAuditVerify(),
        api.getAuditTail(50),
      ]);
      if (v) setVerify(v);
      if (t && Array.isArray(t.entries)) {
        // Newest first — the API returns ascending; we reverse for the UI.
        setTail([...t.entries].reverse().slice(0, 50));
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); /* one-shot on mount */ }, []);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-waf-text font-medium text-sm flex items-center gap-2">
          <FileLock2 className="w-4 h-4 text-waf-orange" /> Tamper-Evident Audit Chain
        </h3>
        <button
          onClick={refresh}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-waf-elevated text-waf-muted rounded text-xs hover:bg-waf-border transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Verifying' : 'Verify + Refresh'}
        </button>
      </div>
      {!verify || !verify.enabled ? (
        <p className="text-xs text-waf-dim">
          Audit chain is disabled. Enable <code>audit_enabled</code> in <code>config.json</code> to record a tamper-evident HMAC chain of every block, ban, and config write.
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
            <div className="bg-waf-elevated rounded p-2">
              <p className="text-[10px] text-waf-dim uppercase">Integrity</p>
              <p className={`text-sm font-medium ${verify.ok ? 'text-waf-success' : 'text-waf-danger'}`}>
                {verify.ok ? '✓ valid' : `✗ broken @ ${verify.bad_seq ?? '?'}`}
              </p>
            </div>
            <div className="bg-waf-elevated rounded p-2">
              <p className="text-[10px] text-waf-dim uppercase">Entries</p>
              <p className="text-sm text-waf-text font-medium">{verify.total ?? 0}</p>
            </div>
            <div className="bg-waf-elevated rounded p-2">
              <p className="text-[10px] text-waf-dim uppercase">Appends</p>
              <p className="text-sm text-waf-text font-medium">{verify.appends ?? 0}</p>
            </div>
            <div className="bg-waf-elevated rounded p-2">
              <p className="text-[10px] text-waf-dim uppercase">Verify fails</p>
              <p className={`text-sm font-medium ${(verify.verify_fails ?? 0) > 0 ? 'text-waf-warning' : 'text-waf-text'}`}>
                {verify.verify_fails ?? 0}
              </p>
            </div>
          </div>
          <div className="border border-waf-border rounded overflow-hidden">
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-[11px]">
                <thead className="bg-waf-elevated text-waf-dim uppercase text-[10px]">
                  <tr>
                    <th className="text-left px-2 py-1.5">Seq</th>
                    <th className="text-left px-2 py-1.5">Time</th>
                    <th className="text-left px-2 py-1.5">Kind</th>
                    <th className="text-left px-2 py-1.5">Actor</th>
                    <th className="text-left px-2 py-1.5">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {tail.length === 0 ? (
                    <tr><td colSpan={5} className="text-center text-waf-dim py-3">No entries yet.</td></tr>
                  ) : (
                    tail.map((e) => (
                      <tr key={e.seq} className="border-t border-waf-border">
                        <td className="px-2 py-1 text-waf-dim font-mono">{e.seq}</td>
                        <td className="px-2 py-1 text-waf-muted">{new Date(e.timestamp).toLocaleString()}</td>
                        <td className="px-2 py-1 text-waf-text">{e.kind}</td>
                        <td className="px-2 py-1 text-waf-muted font-mono">{e.actor || '—'}</td>
                        <td className="px-2 py-1 text-waf-muted truncate max-w-md" title={e.message}>{e.message}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </motion.div>
  );
}

export default function SettingsPage() {
  const { state, dispatch } = useWAF();
  const { settings } = state;
  const [form, setForm] = useState({ ...settings });
  const [saved, setSaved] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [meshTestStatus, setMeshTestStatus] = useState<{ text: string; ok: boolean | null }>({ text: '', ok: null });
  const [egressStats, setEgressStats] = useState({ blocked: 0, allowed: 0 });

  // Rule-engine + safety knobs surfaced from /api/config. These aren't
  // part of the WAFSettings store because they're purely backend concerns
  // — we read and write them directly through the admin API.
  const [engineForm, setEngineForm] = useState({
    paranoia_level: 1,
    crs_enabled: true,
    failsafe_mode: 'closed' as 'closed' | 'open',
    shaper_enabled: false,
    shaper_max_rps: 2000,
    shaper_burst: 4000,
  });
  const [engineSaved, setEngineSaved] = useState(false);
  const [engineSaving, setEngineSaving] = useState(false);

  // Advanced hardening controls introduced alongside transport timeouts,
  // expo-ban, decompression, and per-rule counters. Each one is read from
  // /api/config at mount and round-trips through the same POST /api/config.
  const [advForm, setAdvForm] = useState({
    decompress_inspect: true,
    decompress_ratio_cap: 100,
    ban_backoff_enabled: true,
    ban_backoff_multiplier: 2,
    ban_backoff_window_sec: 86400,
    max_ban_duration_sec: 7 * 24 * 3600,
    per_rule_counters: true,
    block_threshold: 100,
    rate_limit_rps: 100,
    rate_limit_burst: 150,
  });
  const [advSaved, setAdvSaved] = useState(false);
  const [advSaving, setAdvSaving] = useState(false);
  const [advError, setAdvError] = useState<string | null>(null);

  useEffect(() => {
    api.getConfig().then((cfg) => {
      if (!cfg) return;
      // Seed the rule-engine/safety form from the live config.
      const pl = (cfg as Record<string, unknown>).paranoia_level;
      const crs = (cfg as Record<string, unknown>).crs_enabled;
      const fsm = (cfg as Record<string, unknown>).failsafe_mode;
      const se = (cfg as Record<string, unknown>).shaper_enabled;
      const smr = (cfg as Record<string, unknown>).shaper_max_rps;
      const sb = (cfg as Record<string, unknown>).shaper_burst;
      setEngineForm((prev) => ({
        paranoia_level: typeof pl === 'number' ? pl : prev.paranoia_level,
        crs_enabled: typeof crs === 'boolean' ? crs : prev.crs_enabled,
        failsafe_mode: fsm === 'open' || fsm === 'closed' ? fsm : prev.failsafe_mode,
        shaper_enabled: typeof se === 'boolean' ? se : prev.shaper_enabled,
        shaper_max_rps: typeof smr === 'number' && smr > 0 ? smr : prev.shaper_max_rps,
        shaper_burst: typeof sb === 'number' && sb > 0 ? sb : prev.shaper_burst,
      }));

      // Seed the advanced-hardening form from the same config response.
      const c = cfg as Record<string, unknown>;
      const readBool = (k: string, fallback: boolean) =>
        typeof c[k] === 'boolean' ? (c[k] as boolean) : fallback;
      const readNum = (k: string, fallback: number) =>
        typeof c[k] === 'number' && (c[k] as number) > 0 ? (c[k] as number) : fallback;
      setAdvForm((prev) => ({
        decompress_inspect: readBool('decompress_inspect', prev.decompress_inspect),
        decompress_ratio_cap: readNum('decompress_ratio_cap', prev.decompress_ratio_cap),
        ban_backoff_enabled: readBool('ban_backoff_enabled', prev.ban_backoff_enabled),
        ban_backoff_multiplier: readNum('ban_backoff_multiplier', prev.ban_backoff_multiplier),
        ban_backoff_window_sec: readNum('ban_backoff_window_sec', prev.ban_backoff_window_sec),
        max_ban_duration_sec: readNum('max_ban_duration_sec', prev.max_ban_duration_sec),
        per_rule_counters: readBool('per_rule_counters', prev.per_rule_counters),
        block_threshold: readNum('block_threshold', prev.block_threshold),
        rate_limit_rps: readNum('rate_limit_rps', prev.rate_limit_rps),
        rate_limit_burst: readNum('rate_limit_burst', prev.rate_limit_burst),
      }));
      const updates: Partial<WAFSettings> = {};
      if (cfg.history_rotate_hours) updates.historyRotateHours = cfg.history_rotate_hours;
      if (typeof cfg.egress_enabled === 'boolean') updates.egressEnabled = cfg.egress_enabled;
      if (typeof cfg.egress_addr === 'string') updates.egressAddr = cfg.egress_addr;
      if (Array.isArray(cfg.egress_allowlist)) updates.egressAllowlist = cfg.egress_allowlist.join(', ');
      if (typeof cfg.egress_block_private_ips === 'boolean') updates.egressBlockPrivateIPs = cfg.egress_block_private_ips;
      if (typeof cfg.egress_exfil_inspect === 'boolean') updates.egressExfilInspect = cfg.egress_exfil_inspect;
      if (typeof cfg.egress_exfil_block === 'boolean') updates.egressExfilBlock = cfg.egress_exfil_block;
      if (typeof cfg.mesh_enabled === 'boolean') updates.meshEnabled = cfg.mesh_enabled;
      if (Array.isArray(cfg.mesh_peers)) updates.meshPeers = cfg.mesh_peers.join(', ');
      if (typeof cfg.mesh_gossip_interval_sec === 'number') updates.meshGossipIntervalSec = cfg.mesh_gossip_interval_sec;
      if (typeof cfg.mesh_sync_timeout_sec === 'number') updates.meshSyncTimeoutSec = cfg.mesh_sync_timeout_sec;
      if (typeof cfg.mesh_api_key === 'string') updates.meshAPIKey = cfg.mesh_api_key;
      if (typeof cfg.security_headers_enabled === 'boolean') updates.securityHeadersEnabled = cfg.security_headers_enabled;
      if (typeof cfg.trust_xff === 'boolean') updates.trustXFF = cfg.trust_xff;
      if (Array.isArray(cfg.trusted_proxies)) updates.trustedProxies = (cfg.trusted_proxies as string[]).join(', ');
      if (typeof cfg.hsts_enabled === 'boolean') updates.hstsEnabled = cfg.hsts_enabled;
      if (typeof cfg.hsts_max_age_sec === 'number') updates.hstsMaxAgeSec = cfg.hsts_max_age_sec;
      if (typeof cfg.hsts_include_subdomains === 'boolean') updates.hstsIncludeSubdomains = cfg.hsts_include_subdomains;
      if (typeof cfg.hsts_preload === 'boolean') updates.hstsPreload = cfg.hsts_preload;
      if (typeof cfg.ja3_enabled === 'boolean') updates.ja3Enabled = cfg.ja3_enabled;
      if (typeof cfg.ja3_hard_block === 'boolean') updates.ja3HardBlock = cfg.ja3_hard_block;
      if (typeof cfg.ja3_header === 'string') updates.ja3Header = cfg.ja3_header;
      if (Array.isArray(cfg.ja3_trusted_sources)) updates.ja3TrustedSources = cfg.ja3_trusted_sources.join(', ');
      if (typeof cfg.pow_enabled === 'boolean') updates.powEnabled = cfg.pow_enabled;
      if (typeof cfg.pow_trigger_score === 'number') updates.powTriggerScore = cfg.pow_trigger_score;
      if (typeof cfg.pow_min_difficulty === 'number') updates.powMinDifficulty = cfg.pow_min_difficulty;
      if (typeof cfg.pow_max_difficulty === 'number') updates.powMaxDifficulty = cfg.pow_max_difficulty;
      if (typeof cfg.pow_token_ttl_sec === 'number') updates.powTokenTTLSec = cfg.pow_token_ttl_sec;
      if (typeof cfg.pow_cookie_ttl_sec === 'number') updates.powCookieTTLSec = cfg.pow_cookie_ttl_sec;
      if (typeof cfg.pow_adaptive_enabled === 'boolean') updates.powAdaptiveEnabled = cfg.pow_adaptive_enabled;
      if (typeof cfg.pow_adaptive_tier2_failures === 'number') updates.powAdaptiveTier2Failures = cfg.pow_adaptive_tier2_failures;
      if (typeof cfg.pow_adaptive_tier2_penalty_bits === 'number') updates.powAdaptiveTier2PenaltyBits = cfg.pow_adaptive_tier2_penalty_bits;
      if (typeof cfg.multi_limit_enabled === 'boolean') updates.multiLimitEnabled = cfg.multi_limit_enabled;
      if (typeof cfg.multi_limit_window_sec === 'number') updates.multiLimitWindowSec = cfg.multi_limit_window_sec;
      if (typeof cfg.multi_limit_ip_rpm === 'number') updates.multiLimitIPRPM = cfg.multi_limit_ip_rpm;
      if (typeof cfg.multi_limit_ja4_rpm === 'number') updates.multiLimitJA4RPM = cfg.multi_limit_ja4_rpm;
      if (typeof cfg.multi_limit_cookie_rpm === 'number') updates.multiLimitCookieRPM = cfg.multi_limit_cookie_rpm;
      if (typeof cfg.multi_limit_cookie_name === 'string') updates.multiLimitCookieName = cfg.multi_limit_cookie_name;
      if (typeof cfg.multi_limit_query_rpm === 'number') updates.multiLimitQueryRPM = cfg.multi_limit_query_rpm;
      if (typeof cfg.multi_limit_max_entries === 'number') updates.multiLimitMaxEntries = cfg.multi_limit_max_entries;
      if (typeof cfg.grpc_inspect === 'boolean') updates.grpcInspect = cfg.grpc_inspect;
      if (typeof cfg.grpc_block_on_error === 'boolean') updates.grpcBlockOnError = cfg.grpc_block_on_error;
      if (typeof cfg.grpc_block_compressed === 'boolean') updates.grpcBlockCompressed = cfg.grpc_block_compressed;
      if (typeof cfg.grpc_max_frames === 'number') updates.grpcMaxFrames = cfg.grpc_max_frames;
      if (typeof cfg.grpc_max_frame_bytes === 'number') updates.grpcMaxFrameBytes = cfg.grpc_max_frame_bytes;
      if (typeof cfg.websocket_inspect === 'boolean') updates.websocketInspect = cfg.websocket_inspect;
      if (typeof cfg.websocket_require_subprotocol === 'boolean') updates.websocketRequireSubprotocol = cfg.websocket_require_subprotocol;
      if (Array.isArray(cfg.websocket_origin_allowlist)) updates.websocketOriginAllowlist = (cfg.websocket_origin_allowlist as string[]).join(', ');
      if (Array.isArray(cfg.websocket_subprotocol_allowlist)) updates.websocketSubprotocolAllowlist = (cfg.websocket_subprotocol_allowlist as string[]).join(', ');
      if (Object.keys(updates).length > 0) {
        setForm((prev) => ({ ...prev, ...updates }));
        dispatch({ type: 'UPDATE_SETTINGS', payload: updates });
      }
    });
  }, [dispatch]);

  useEffect(() => {
    api.getMeshStatus().then((status) => {
      if (status) {
        dispatch({
          type: 'SET_MESH_STATUS',
          payload: {
            enabled: status.enabled,
            peers: status.peers || [],
            lastSync: status.last_sync || '',
            peerCount: status.peer_count || 0,
          },
        });
      }
    });
  }, [dispatch]);

  useEffect(() => {
    const poll = async () => {
      const metrics = await api.getMetrics();
      if (metrics) {
        setEgressStats({
          blocked: metrics.egress_blocked ?? 0,
          allowed: metrics.egress_allowed ?? 0,
        });
      }
    };
    poll();
    const id = setInterval(poll, 10000);
    return () => clearInterval(id);
  }, []);

  const handleSave = async () => {
    setBackendError(null);
    // Update local store
    dispatch({ type: 'SET_SETTINGS', payload: { ...form } });
    // Sync history rotation to backend
    try {
      const res = await api.updateConfig({
        history_rotate_hours: form.historyRotateHours,
        egress_enabled: form.egressEnabled,
        egress_addr: form.egressAddr,
        egress_allowlist: form.egressAllowlist.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        egress_block_private_ips: form.egressBlockPrivateIPs,
        egress_exfil_inspect: form.egressExfilInspect,
        egress_exfil_block: form.egressExfilBlock,
        mesh_enabled: form.meshEnabled,
        mesh_peers: form.meshPeers.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        mesh_gossip_interval_sec: form.meshGossipIntervalSec,
        mesh_sync_timeout_sec: form.meshSyncTimeoutSec,
        mesh_api_key: form.meshAPIKey,
        security_headers_enabled: form.securityHeadersEnabled,
        trust_xff: form.trustXFF,
        trusted_proxies: form.trustedProxies.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        hsts_enabled: form.hstsEnabled,
        hsts_max_age_sec: form.hstsMaxAgeSec,
        hsts_include_subdomains: form.hstsIncludeSubdomains,
        hsts_preload: form.hstsPreload,
        ja3_enabled: form.ja3Enabled,
        ja3_hard_block: form.ja3HardBlock,
        ja3_header: form.ja3Header,
        ja3_trusted_sources: form.ja3TrustedSources.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        pow_enabled: form.powEnabled,
        pow_trigger_score: form.powTriggerScore,
        pow_min_difficulty: form.powMinDifficulty,
        pow_max_difficulty: form.powMaxDifficulty,
        pow_token_ttl_sec: form.powTokenTTLSec,
        pow_cookie_ttl_sec: form.powCookieTTLSec,
        pow_adaptive_enabled: form.powAdaptiveEnabled,
        pow_adaptive_tier2_failures: form.powAdaptiveTier2Failures,
        pow_adaptive_tier2_penalty_bits: form.powAdaptiveTier2PenaltyBits,
        multi_limit_enabled: form.multiLimitEnabled,
        multi_limit_window_sec: form.multiLimitWindowSec,
        multi_limit_ip_rpm: form.multiLimitIPRPM,
        multi_limit_ja4_rpm: form.multiLimitJA4RPM,
        multi_limit_cookie_rpm: form.multiLimitCookieRPM,
        multi_limit_cookie_name: form.multiLimitCookieName,
        multi_limit_query_rpm: form.multiLimitQueryRPM,
        multi_limit_max_entries: form.multiLimitMaxEntries,
        grpc_inspect: form.grpcInspect,
        grpc_block_on_error: form.grpcBlockOnError,
        grpc_block_compressed: form.grpcBlockCompressed,
        grpc_max_frames: form.grpcMaxFrames,
        grpc_max_frame_bytes: form.grpcMaxFrameBytes,
        websocket_inspect: form.websocketInspect,
        websocket_require_subprotocol: form.websocketRequireSubprotocol,
        websocket_origin_allowlist: form.websocketOriginAllowlist.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
        websocket_subprotocol_allowlist: form.websocketSubprotocolAllowlist.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
      });
      if (res) {
        dispatch({ type: 'UPDATE_SETTINGS', payload: { ...form } });
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setBackendError('Failed to sync settings to backend.');
    }
  };

  const handleReset = () => {
    setForm({ ...settings });
    setBackendError(null);
    setMeshTestStatus({ text: '', ok: null });
  };

  const saveEngine = async () => {
    setEngineSaving(true);
    try {
      const res = await api.updateConfig({
        // These pass through the admin /api/config POST accept list.
        paranoia_level: engineForm.paranoia_level,
        crs_enabled: engineForm.crs_enabled,
        failsafe_mode: engineForm.failsafe_mode,
        shaper_enabled: engineForm.shaper_enabled,
        shaper_max_rps: engineForm.shaper_max_rps,
        shaper_burst: engineForm.shaper_burst,
      } as Parameters<typeof api.updateConfig>[0]);
      if (res) {
        setEngineSaved(true);
        setTimeout(() => setEngineSaved(false), 1500);
      }
    } finally {
      setEngineSaving(false);
    }
  };

  const saveAdvanced = async () => {
    setAdvSaving(true);
    setAdvError(null);
    // Client-side sanity before hitting the backend — the backend clamps
    // again defensively, but surfacing an obvious nonsense value here is
    // faster than a round-trip.
    if (advForm.decompress_ratio_cap < 10 || advForm.decompress_ratio_cap > 10000) {
      setAdvError('Decompression ratio cap must be between 10 and 10000.');
      setAdvSaving(false);
      return;
    }
    if (advForm.ban_backoff_multiplier < 1 || advForm.ban_backoff_multiplier > 16) {
      setAdvError('Ban backoff multiplier must be between 1 and 16.');
      setAdvSaving(false);
      return;
    }
    try {
      const res = await api.updateConfig({
        decompress_inspect: advForm.decompress_inspect,
        decompress_ratio_cap: advForm.decompress_ratio_cap,
        ban_backoff_enabled: advForm.ban_backoff_enabled,
        ban_backoff_multiplier: advForm.ban_backoff_multiplier,
        ban_backoff_window_sec: advForm.ban_backoff_window_sec,
        max_ban_duration_sec: advForm.max_ban_duration_sec,
        per_rule_counters: advForm.per_rule_counters,
        block_threshold: advForm.block_threshold,
        rate_limit_rps: advForm.rate_limit_rps,
        rate_limit_burst: advForm.rate_limit_burst,
      } as Parameters<typeof api.updateConfig>[0]);
      if (res) {
        setAdvSaved(true);
        setTimeout(() => setAdvSaved(false), 1500);
      } else {
        setAdvError('Save failed — check /api/errors or the daemon log.');
      }
    } catch (err) {
      setAdvError(err instanceof Error ? err.message : 'Save failed.');
    } finally {
      setAdvSaving(false);
    }
  };

  const handleTestPeer = async () => {
    const peers = form.meshPeers.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    if (peers.length === 0) {
      setMeshTestStatus({ text: 'No peers configured.', ok: false });
      return;
    }
    setMeshTestStatus({ text: 'Testing...', ok: null });
    const res = await api.syncMeshPeer(peers[0], form.meshAPIKey);
    if (res) {
      setMeshTestStatus({ text: 'Connection successful!', ok: true });
    } else {
      setMeshTestStatus({ text: 'Connection failed.', ok: false });
    }
  };

  return (
    <div className="space-y-4 lg:space-y-6 max-w-4xl">
      <p className="text-waf-dim text-xs lg:text-sm">Configure WAF settings including resource limits, logging, and alerting.</p>

      {/* Rule engine + safety */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <Gauge className="w-4 h-4 text-waf-orange" /> Rule Engine &amp; Safety
        </h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Paranoia Level</label>
            <div className="flex gap-2">
              {[1, 2, 3, 4].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setEngineForm((f) => ({ ...f, paranoia_level: lvl }))}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    engineForm.paranoia_level === lvl
                      ? 'bg-waf-orange text-white'
                      : 'bg-waf-elevated text-waf-muted hover:text-waf-text border border-waf-border'
                  }`}
                >
                  PL{lvl}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-waf-dim mt-1">
              PL1 is the base rule set (lowest false-positive risk). Each level adds more
              aggressive rules. Start at PL1 and ratchet up after running in detection mode.
            </p>
          </div>

          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input
              type="checkbox" checked={engineForm.crs_enabled}
              onChange={(e) => setEngineForm((f) => ({ ...f, crs_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange"
            />
            <div>
              <div className="text-xs text-waf-text font-medium">OWASP Core Rule Set</div>
              <p className="text-[10px] text-waf-dim">
                Load the full CRS pack alongside the native WEWAF signatures. Disable to run with
                native rules only.
              </p>
            </div>
          </label>

          <div>
            <label className="text-xs text-waf-muted mb-2 block flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Failsafe mode on engine panic
            </label>
            <div className="flex gap-2">
              {(['closed', 'open'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setEngineForm((f) => ({ ...f, failsafe_mode: m }))}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    engineForm.failsafe_mode === m
                      ? (m === 'closed' ? 'bg-emerald-500 text-white' : 'bg-amber-500 text-white')
                      : 'bg-waf-elevated text-waf-muted hover:text-waf-text border border-waf-border'
                  }`}
                >
                  {m === 'closed' ? 'Fail closed (503)' : 'Fail open (pass)'}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-waf-dim mt-1">
              Controls what happens if the engine panics: fail-closed returns 503 so the client
              retries; fail-open forwards the request unfiltered with an <span className="font-mono">X-WAF-Failsafe</span> response header.
            </p>
          </div>

          <div className="pt-3 border-t border-waf-border/50 space-y-3">
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox" checked={engineForm.shaper_enabled}
                onChange={(e) => setEngineForm((f) => ({ ...f, shaper_enabled: e.target.checked }))}
                className="mt-0.5 accent-waf-orange"
              />
              <div>
                <div className="text-xs text-waf-text font-medium">Pre-WAF traffic shaper</div>
                <p className="text-[10px] text-waf-dim">
                  Admission-control token bucket running before rule evaluation. When enabled,
                  the shaper auto-tightens to 20% of its base rate while the DDoS detector
                  reports under-attack, protecting the WAF's own resources under load.
                </p>
              </div>
            </label>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-waf-muted mb-1 block">Max RPS</label>
                <input
                  type="number" min={10} max={100000}
                  disabled={!engineForm.shaper_enabled}
                  value={engineForm.shaper_max_rps}
                  onChange={(e) => setEngineForm((f) => ({ ...f, shaper_max_rps: parseInt(e.target.value) || 2000 }))}
                  className="w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1.5 text-xs text-waf-text font-mono focus:outline-none focus:border-waf-orange disabled:opacity-40"
                />
              </div>
              <div>
                <label className="text-[10px] text-waf-muted mb-1 block">Burst</label>
                <input
                  type="number" min={10} max={200000}
                  disabled={!engineForm.shaper_enabled}
                  value={engineForm.shaper_burst}
                  onChange={(e) => setEngineForm((f) => ({ ...f, shaper_burst: parseInt(e.target.value) || 4000 }))}
                  className="w-full bg-waf-elevated border border-waf-border rounded-md px-2 py-1.5 text-xs text-waf-text font-mono focus:outline-none focus:border-waf-orange disabled:opacity-40"
                />
              </div>
            </div>
            <p className="text-[10px] text-waf-dim">
              Set Max RPS above your traffic's realistic peak — the shaper's job is to cap
              catastrophic floods, not to enforce QoS. Typical starting point: 2× observed
              peak during the last seven days.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={saveEngine} disabled={engineSaving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
              <Save className="w-4 h-4" /> {engineSaved ? 'Saved' : 'Save engine settings'}
            </button>
          </div>
        </div>
      </motion.div>

      {/* Advanced hardening: decompression, expo-ban, per-rule counters, thresholds. */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2">
          <Gauge className="w-4 h-4 text-waf-orange" /> Advanced Hardening
        </h3>
        <div className="space-y-4">
          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input
              type="checkbox"
              checked={advForm.decompress_inspect}
              onChange={(e) => setAdvForm((f) => ({ ...f, decompress_inspect: e.target.checked }))}
              className="mt-0.5 accent-waf-orange"
            />
            <div>
              <div className="text-sm text-waf-text font-medium">Decompression inspection</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Decompress gzip / brotli request bodies into a ratio-capped buffer so a
                zip bomb can't sail past <code>max_body_bytes</code>. Rejects payloads
                whose decompressed size exceeds the ratio cap.
              </p>
            </div>
          </label>

          <div>
            <label className="text-xs text-waf-muted mb-1 block">
              Decompression ratio cap — decompressed ÷ compressed
            </label>
            <input
              type="number"
              min={10}
              max={10000}
              value={advForm.decompress_ratio_cap}
              disabled={!advForm.decompress_inspect}
              onChange={(e) => setAdvForm((f) => ({ ...f, decompress_ratio_cap: Math.max(10, Math.min(10000, Number(e.target.value) || 100)) }))}
              className="w-32 bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange disabled:opacity-50"
            />
            <p className="text-[10px] text-waf-dim mt-1">
              100 is the safe default — real traffic tops out around 10-20×. Lower for stricter,
              higher only if you have legitimate highly-compressible payloads.
            </p>
          </div>

          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input
              type="checkbox"
              checked={advForm.ban_backoff_enabled}
              onChange={(e) => setAdvForm((f) => ({ ...f, ban_backoff_enabled: e.target.checked }))}
              className="mt-0.5 accent-waf-orange"
            />
            <div>
              <div className="text-sm text-waf-text font-medium">Exponential-backoff bans</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Repeat offenders inside the backoff window get longer bans (multiplied each time).
                Capped at Max ban duration so it can't run away.
              </p>
            </div>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Multiplier</label>
              <input
                type="number" min={1} max={16}
                value={advForm.ban_backoff_multiplier}
                disabled={!advForm.ban_backoff_enabled}
                onChange={(e) => setAdvForm((f) => ({ ...f, ban_backoff_multiplier: Math.max(1, Math.min(16, Number(e.target.value) || 2)) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange disabled:opacity-50"
              />
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Window (seconds)</label>
              <input
                type="number" min={60}
                value={advForm.ban_backoff_window_sec}
                disabled={!advForm.ban_backoff_enabled}
                onChange={(e) => setAdvForm((f) => ({ ...f, ban_backoff_window_sec: Math.max(60, Number(e.target.value) || 86400) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange disabled:opacity-50"
              />
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Max ban (seconds)</label>
              <input
                type="number" min={60}
                value={advForm.max_ban_duration_sec}
                disabled={!advForm.ban_backoff_enabled}
                onChange={(e) => setAdvForm((f) => ({ ...f, max_ban_duration_sec: Math.max(60, Number(e.target.value) || 604800) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange disabled:opacity-50"
              />
            </div>
          </div>

          <label className="flex items-start gap-2 cursor-pointer p-3 rounded-lg bg-waf-elevated border border-waf-border">
            <input
              type="checkbox"
              checked={advForm.per_rule_counters}
              onChange={(e) => setAdvForm((f) => ({ ...f, per_rule_counters: e.target.checked }))}
              className="mt-0.5 accent-waf-orange"
            />
            <div>
              <div className="text-sm text-waf-text font-medium">Per-rule match counters</div>
              <p className="text-[11px] text-waf-dim mt-0.5">
                Count matches per rule ID. Visible under /api/rules/counters, in the Rules page's
                "Noisiest rules" widget, and in Prometheus as <code>wewaf_rule_matches_total</code>.
              </p>
            </div>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Block threshold (score)</label>
              <input
                type="number" min={10} max={1000}
                value={advForm.block_threshold}
                onChange={(e) => setAdvForm((f) => ({ ...f, block_threshold: Math.max(10, Math.min(1000, Number(e.target.value) || 100)) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange"
              />
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Rate limit RPS</label>
              <input
                type="number" min={1}
                value={advForm.rate_limit_rps}
                onChange={(e) => setAdvForm((f) => ({ ...f, rate_limit_rps: Math.max(1, Number(e.target.value) || 100) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange"
              />
            </div>
            <div>
              <label className="text-xs text-waf-muted mb-1 block">Rate limit burst</label>
              <input
                type="number" min={1}
                value={advForm.rate_limit_burst}
                onChange={(e) => setAdvForm((f) => ({ ...f, rate_limit_burst: Math.max(1, Number(e.target.value) || 150) }))}
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange"
              />
            </div>
          </div>

          {advError && (
            <div className="p-2.5 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">{advError}</div>
          )}

          <div className="flex items-center gap-3">
            <button onClick={saveAdvanced} disabled={advSaving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-waf-orange text-white text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
              <Save className="w-4 h-4" /> {advSaved ? 'Saved' : 'Save advanced settings'}
            </button>
            <p className="text-[10px] text-waf-dim">
              Prometheus scrape target: <code>http://&lt;admin&gt;/metrics</code>
            </p>
          </div>
        </div>
      </motion.div>

      {/* Resource Management */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Cpu className="w-4 h-4 text-waf-orange" /> Resource Management</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Resource Mode</label>
            <div className="flex gap-2">
              {(['auto', 'manual'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setForm({ ...form, resourceMode: mode })}
                  className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
                    form.resourceMode === mode ? 'bg-waf-orange text-white' : 'bg-waf-elevated text-waf-muted hover:bg-waf-border'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
            <p className="text-waf-dim text-xs mt-2">
              {form.resourceMode === 'auto'
                ? 'WAF will automatically use all available system resources.'
                : 'Manually configure the resource limits for the WAF.'}
            </p>
          </div>

          {form.resourceMode === 'manual' && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">CPU Limit (%)</label>
                  <input
                    type="range" min={10} max={100} value={form.cpuLimit}
                    onChange={(e) => setForm({ ...form, cpuLimit: parseInt(e.target.value) })}
                    className="w-full accent-waf-orange"
                  />
                  <div className="flex justify-between text-xs text-waf-dim mt-1">
                    <span>10%</span>
                    <span className="text-waf-orange font-bold">{form.cpuLimit}%</span>
                    <span>100%</span>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Memory Limit (%)</label>
                  <input
                    type="range" min={10} max={100} value={form.memoryLimit}
                    onChange={(e) => setForm({ ...form, memoryLimit: parseInt(e.target.value) })}
                    className="w-full accent-waf-orange"
                  />
                  <div className="flex justify-between text-xs text-waf-dim mt-1">
                    <span>10%</span>
                    <span className="text-waf-orange font-bold">{form.memoryLimit}%</span>
                    <span>100%</span>
                  </div>
                </div>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Worker Threads</label>
                <input
                  type="number" min={1} max={64} value={form.workerThreads}
                  onChange={(e) => setForm({ ...form, workerThreads: parseInt(e.target.value) || 4 })}
                  className="w-32 bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange"
                />
                <p className="text-waf-dim text-xs mt-1">Number of worker threads processing incoming requests.</p>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Block Mode */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-waf-orange" /> Security Mode</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-2 block">Block Mode</label>
            <div className="flex flex-wrap gap-2">
              {([
                { value: 'aggressive', label: 'Aggressive', desc: 'Block all suspicious traffic' },
                { value: 'standard', label: 'Standard', desc: 'Balanced protection' },
                { value: 'passive', label: 'Passive', desc: 'Log only, no blocking' },
              ] as const).map((mode) => (
                <button
                  key={mode.value}
                  onClick={() => setForm({ ...form, blockMode: mode.value })}
                  className={`flex flex-col items-start px-4 py-3 rounded-lg text-left transition-colors min-w-[120px] ${
                    form.blockMode === mode.value ? 'bg-waf-orange/10 border border-waf-orange/30' : 'bg-waf-elevated border border-waf-border hover:bg-waf-border'
                  }`}
                >
                  <span className={`text-sm font-medium ${form.blockMode === mode.value ? 'text-waf-orange' : 'text-waf-text'}`}>{mode.label}</span>
                  <span className="text-[10px] text-waf-dim mt-0.5">{mode.desc}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.challengeSuspicious} onChange={(e) => setForm({ ...form, challengeSuspicious: e.target.checked })} className="rounded border-waf-border" />
              Challenge suspicious requests
            </label>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.autoUpdateRules} onChange={(e) => setForm({ ...form, autoUpdateRules: e.target.checked })} className="rounded border-waf-border" />
              Auto-update WAF rules
            </label>
          </div>
        </div>
      </motion.div>

      {/* Logging */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><HardDrive className="w-4 h-4 text-waf-amber" /> Logging</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Log Level</label>
            <select value={form.logLevel} onChange={(e) => setForm({ ...form, logLevel: e.target.value as any })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange">
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Log Retention (days)</label>
            <input type="number" min={1} max={365} value={form.logRetention} onChange={(e) => setForm({ ...form, logRetention: parseInt(e.target.value) || 30 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
          </div>
        </div>
      </motion.div>

      {/* History & Database */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Database className="w-4 h-4 text-waf-orange" /> History &amp; Database</h3>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Database Rotation (hours)</label>
            <input
              type="range"
              min={1}
              max={720}
              step={1}
              value={form.historyRotateHours}
              onChange={(e) => setForm({ ...form, historyRotateHours: parseInt(e.target.value) || 168 })}
              className="w-full accent-waf-orange"
            />
            <div className="flex justify-between text-xs text-waf-dim mt-1">
              <span>1h</span>
              <span className="text-waf-orange font-bold">{form.historyRotateHours}h ({(form.historyRotateHours / 24).toFixed(0)} days)</span>
              <span>720h (30d)</span>
            </div>
            <p className="text-waf-dim text-[10px] mt-1">
              How often the SQLite history database rotates to a new file. Default is 168 hours (1 week).
            </p>
          </div>
        </div>
      </motion.div>

      {/* Egress Proxy */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.28 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><ArrowLeftRight className="w-4 h-4 text-waf-orange" /> Egress Proxy</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.egressEnabled} onChange={(e) => setForm({ ...form, egressEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable egress proxy (inspect outbound traffic from backend)
          </label>
          {form.egressEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Listen Address</label>
                <input type="text" value={form.egressAddr} onChange={(e) => setForm({ ...form, egressAddr: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder=":8081" />
                <p className="text-waf-dim text-[10px] mt-1">Backend app should route outbound HTTP through this address.</p>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Allowlist (comma or newline separated)</label>
                <textarea value={form.egressAllowlist} onChange={(e) => setForm({ ...form, egressAllowlist: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="api.stripe.com, api.sendgrid.com" />
                <p className="text-waf-dim text-[10px] mt-1">If non-empty, only these destinations are allowed. All others are blocked.</p>
              </div>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                <input type="checkbox" checked={form.egressBlockPrivateIPs} onChange={(e) => setForm({ ...form, egressBlockPrivateIPs: e.target.checked })} className="rounded border-waf-border" />
                Block requests to private IPs / localhost (SSRF protection)
              </label>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                <input type="checkbox" checked={form.egressExfilInspect} onChange={(e) => setForm({ ...form, egressExfilInspect: e.target.checked })} className="rounded border-waf-border" />
                Inspect outbound response bodies for credit-card numbers and cloud-provider secrets (first 256 KiB)
              </label>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer pl-6">
                <input type="checkbox" disabled={!form.egressExfilInspect} checked={form.egressExfilBlock} onChange={(e) => setForm({ ...form, egressExfilBlock: e.target.checked })} className="rounded border-waf-border" />
                Block the response (default: observe-only — count + log)
              </label>
              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="bg-waf-elevated border border-waf-border rounded-lg p-3">
                  <div className="text-[10px] text-waf-dim uppercase tracking-wider">Blocked</div>
                  <div className="text-lg font-semibold text-waf-text">{egressStats.blocked}</div>
                </div>
                <div className="bg-waf-elevated border border-waf-border rounded-lg p-3">
                  <div className="text-[10px] text-waf-dim uppercase tracking-wider">Allowed</div>
                  <div className="text-lg font-semibold text-waf-text">{egressStats.allowed}</div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Threat Mesh */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.29 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Network className="w-4 h-4 text-waf-orange" /> Threat Mesh</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.meshEnabled} onChange={(e) => setForm({ ...form, meshEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable distributed threat mesh (share bans with peer WAF nodes)
          </label>
          {form.meshEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-4 pt-2">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Peer URLs (comma or newline separated)</label>
                <textarea value={form.meshPeers} onChange={(e) => setForm({ ...form, meshPeers: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="http://waf-node-2:8443, http://waf-node-3:8443" />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Gossip Interval (sec)</label>
                  <input type="number" min={10} max={3600} value={form.meshGossipIntervalSec} onChange={(e) => setForm({ ...form, meshGossipIntervalSec: parseInt(e.target.value) || 60 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Sync Timeout (sec)</label>
                  <input type="number" min={1} max={60} value={form.meshSyncTimeoutSec || 10} onChange={(e) => setForm({ ...form, meshSyncTimeoutSec: parseInt(e.target.value) || 10 })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
              </div>
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Mesh API Key</label>
                <input type="password" value={form.meshAPIKey} onChange={(e) => setForm({ ...form, meshAPIKey: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="shared secret between peers" />
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleTestPeer}
                  className="px-3 py-1.5 bg-waf-elevated border border-waf-border rounded-lg text-xs text-waf-text hover:bg-waf-border transition-colors"
                >
                  Test Peer Connection
                </button>
                {meshTestStatus.text && (
                  <span className={`text-xs ${meshTestStatus.ok === true ? 'text-emerald-400' : meshTestStatus.ok === false ? 'text-red-400' : 'text-waf-dim'}`}>
                    {meshTestStatus.text}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-waf-dim">
                <Network className="w-3 h-3" />
                <span>Peers: {state.meshStatus.peerCount} | Last sync: {state.meshStatus.lastSync ? new Date(state.meshStatus.lastSync).toLocaleString() : 'Never'}</span>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Response Hardening */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.295 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Lock className="w-4 h-4 text-waf-orange" /> Response Hardening</h3>
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.securityHeadersEnabled} onChange={(e) => setForm({ ...form, securityHeadersEnabled: e.target.checked })} className="rounded border-waf-border" />
            Inject security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) and strip Server/X-Powered-By
          </label>
          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.cspEnabled} onChange={(e) => setForm({ ...form, cspEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable Content-Security-Policy header
          </label>
          {form.cspEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}>
              <label className="text-xs text-waf-muted mb-1 block">CSP Policy</label>
              <textarea value={form.cspPolicy} onChange={(e) => setForm({ ...form, cspPolicy: e.target.value })} rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange" placeholder="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" />
            </motion.div>
          )}

          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.hstsEnabled} onChange={(e) => setForm({ ...form, hstsEnabled: e.target.checked })} className="rounded border-waf-border" />
            Enable HSTS (Strict-Transport-Security) — only emitted when backend is HTTPS
          </label>
          {form.hstsEnabled && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="grid grid-cols-1 md:grid-cols-3 gap-3 pl-6">
              <div>
                <label className="text-xs text-waf-muted mb-1 block">Max-age (seconds)</label>
                <input type="number" min={0} max={315360000} value={form.hstsMaxAgeSec}
                  onChange={(e) => setForm({ ...form, hstsMaxAgeSec: Math.max(0, Number(e.target.value) || 0) })}
                  className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                <p className="text-[10px] text-waf-dim mt-1">15552000 = 180 days (safe starting value).</p>
              </div>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer mt-4">
                <input type="checkbox" checked={form.hstsIncludeSubdomains} onChange={(e) => setForm({ ...form, hstsIncludeSubdomains: e.target.checked })} className="rounded border-waf-border" />
                includeSubDomains
              </label>
              <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer mt-4">
                <input type="checkbox" checked={form.hstsPreload} onChange={(e) => setForm({ ...form, hstsPreload: e.target.checked })} className="rounded border-waf-border" />
                preload (only tick once ready to submit to hstspreload.org)
              </label>
            </motion.div>
          )}

          <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
            <input type="checkbox" checked={form.trustXFF} onChange={(e) => setForm({ ...form, trustXFF: e.target.checked })} className="rounded border-waf-border" />
            Trust X-Forwarded-For / X-Real-Ip (only enable when the WAF sits behind a trusted reverse proxy)
          </label>
          {form.trustXFF && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="pl-6">
              <label className="text-xs text-waf-muted mb-1 block">
                Trusted proxy CIDRs (comma or newline separated) — required so an attacker bypassing your CDN cannot spoof the source IP. Bare IPs are accepted (auto-promoted to <code>/32</code> or <code>/128</code>).
              </label>
              <textarea
                value={form.trustedProxies}
                onChange={(e) => setForm({ ...form, trustedProxies: e.target.value })}
                rows={2}
                placeholder="173.245.48.0/20, 103.21.244.0/22, 2400:cb00::/32"
                className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange"
              />
              {form.trustedProxies.trim() === '' && (
                <p className="text-[10px] text-waf-warning mt-1">
                  ⚠ Empty list = legacy behaviour: every client can spoof X-Forwarded-For. Populate this in production.
                </p>
              )}
            </motion.div>
          )}

          {/* JA3 TLS fingerprinting */}
          <div className="border-t border-waf-border pt-3 mt-3">
            <p className="text-xs text-waf-text font-medium mb-2">JA3 TLS Fingerprinting</p>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.ja3Enabled} onChange={(e) => setForm({ ...form, ja3Enabled: e.target.checked })} className="rounded border-waf-border" />
              Enable JA3 fingerprinting (catches headless automation that passes the browser challenge)
            </label>
            {form.ja3Enabled && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-2 pl-6 mt-2">
                <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                  <input type="checkbox" checked={form.ja3HardBlock} onChange={(e) => setForm({ ...form, ja3HardBlock: e.target.checked })} className="rounded border-waf-border" />
                  Hard-block on known-bad fingerprints (default = score-only)
                </label>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Edge JA3 header (e.g. <code>Cf-Ja3-Hash</code>) — leave blank for native TLS only</label>
                  <input type="text" value={form.ja3Header} onChange={(e) => setForm({ ...form, ja3Header: e.target.value })} placeholder="Cf-Ja3-Hash" className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Trusted source CIDRs (comma or newline separated) — only sources in this list may set the JA3 header</label>
                  <textarea value={form.ja3TrustedSources} onChange={(e) => setForm({ ...form, ja3TrustedSources: e.target.value })} rows={2} placeholder="173.245.48.0/20, 103.21.244.0/22" className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
              </motion.div>
            )}
          </div>

          {/* Proof-of-work */}
          <div className="border-t border-waf-border pt-3 mt-3">
            <p className="text-xs text-waf-text font-medium mb-2">Proof-of-Work Challenge</p>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.powEnabled} onChange={(e) => setForm({ ...form, powEnabled: e.target.checked })} className="rounded border-waf-border" />
              Enable PoW challenge for high-risk sessions (no CAPTCHA — browser solves a small math problem)
            </label>
            {form.powEnabled && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="grid grid-cols-2 md:grid-cols-3 gap-3 pl-6 mt-2">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Trigger Score (0–100)</label>
                  <input type="number" min={1} max={100} value={form.powTriggerScore} onChange={(e) => setForm({ ...form, powTriggerScore: Math.max(1, Math.min(100, Number(e.target.value) || 60)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Min Difficulty (bits)</label>
                  <input type="number" min={8} max={32} value={form.powMinDifficulty} onChange={(e) => setForm({ ...form, powMinDifficulty: Math.max(8, Math.min(32, Number(e.target.value) || 18)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Max Difficulty (bits)</label>
                  <input type="number" min={8} max={32} value={form.powMaxDifficulty} onChange={(e) => setForm({ ...form, powMaxDifficulty: Math.max(8, Math.min(32, Number(e.target.value) || 24)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Challenge TTL (s)</label>
                  <input type="number" min={30} max={600} value={form.powTokenTTLSec} onChange={(e) => setForm({ ...form, powTokenTTLSec: Math.max(30, Math.min(600, Number(e.target.value) || 120)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Pass Cookie TTL (s)</label>
                  <input type="number" min={60} max={86400} value={form.powCookieTTLSec} onChange={(e) => setForm({ ...form, powCookieTTLSec: Math.max(60, Math.min(86400, Number(e.target.value) || 3600)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <p className="text-[10px] text-waf-dim col-span-full">18 bits ≈ 1s on a phone, 24 bits ≈ 5–15s. Difficulty scales linearly with score above the trigger.</p>
              </motion.div>
            )}

            {/* Adaptive PoW Tier-2 — bumps difficulty for repeat failers. */}
            {form.powEnabled && (
              <div className="pl-6 mt-3">
                <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                  <input type="checkbox" checked={form.powAdaptiveEnabled} onChange={(e) => setForm({ ...form, powAdaptiveEnabled: e.target.checked })} className="rounded border-waf-border" />
                  Enable Tier-2 adaptive escalation (raises difficulty for IPs that repeatedly fail)
                </label>
                {form.powAdaptiveEnabled && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="grid grid-cols-2 gap-3 pl-6 mt-2">
                    <div>
                      <label className="text-xs text-waf-muted mb-1 block">Failures before Tier-2 (1–20)</label>
                      <input type="number" min={1} max={20} value={form.powAdaptiveTier2Failures} onChange={(e) => setForm({ ...form, powAdaptiveTier2Failures: Math.max(1, Math.min(20, Number(e.target.value) || 5)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                    </div>
                    <div>
                      <label className="text-xs text-waf-muted mb-1 block">Penalty (extra bits, 1–10)</label>
                      <input type="number" min={1} max={10} value={form.powAdaptiveTier2PenaltyBits} onChange={(e) => setForm({ ...form, powAdaptiveTier2PenaltyBits: Math.max(1, Math.min(10, Number(e.target.value) || 3)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                    </div>
                    <p className="text-[10px] text-waf-dim col-span-full">Each failed solve past the threshold adds the penalty bits to the next challenge. Capped to maximum difficulty.</p>
                  </motion.div>
                )}
              </div>
            )}
          </div>

          {/* Multi-dimensional rate limiter */}
          <div className="border-t border-waf-border pt-3 mt-3">
            <p className="text-xs text-waf-text font-medium mb-2">Multi-Dimensional Rate Limiter</p>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.multiLimitEnabled} onChange={(e) => setForm({ ...form, multiLimitEnabled: e.target.checked })} className="rounded border-waf-border" />
              Enforce per-IP / per-JA4 / per-cookie / per-query-key budgets in parallel (defeats IP-rotating bots that keep stable client fingerprints)
            </label>
            {form.multiLimitEnabled && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="grid grid-cols-2 md:grid-cols-3 gap-3 pl-6 mt-2">
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Window (seconds)</label>
                  <input type="number" min={10} max={3600} value={form.multiLimitWindowSec} onChange={(e) => setForm({ ...form, multiLimitWindowSec: Math.max(10, Math.min(3600, Number(e.target.value) || 60)) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">IP budget (req/window)</label>
                  <input type="number" min={1} value={form.multiLimitIPRPM} onChange={(e) => setForm({ ...form, multiLimitIPRPM: Math.max(1, Number(e.target.value) || 600) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">JA4 budget (req/window)</label>
                  <input type="number" min={0} value={form.multiLimitJA4RPM} onChange={(e) => setForm({ ...form, multiLimitJA4RPM: Math.max(0, Number(e.target.value) || 1200) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Cookie budget (req/window)</label>
                  <input type="number" min={0} value={form.multiLimitCookieRPM} onChange={(e) => setForm({ ...form, multiLimitCookieRPM: Math.max(0, Number(e.target.value) || 600) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Cookie name</label>
                  <input type="text" value={form.multiLimitCookieName} onChange={(e) => setForm({ ...form, multiLimitCookieName: e.target.value })} placeholder="session" className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Query-keys budget</label>
                  <input type="number" min={0} value={form.multiLimitQueryRPM} onChange={(e) => setForm({ ...form, multiLimitQueryRPM: Math.max(0, Number(e.target.value) || 600) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Max tracked entries</label>
                  <input type="number" min={1000} value={form.multiLimitMaxEntries} onChange={(e) => setForm({ ...form, multiLimitMaxEntries: Math.max(1000, Number(e.target.value) || 200000) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <p className="text-[10px] text-waf-dim col-span-full">Set 0 to disable a dimension. Each request is rejected if any enabled budget overflows.</p>
              </motion.div>
            )}
          </div>

          {/* Deep packet inspection — gRPC + WebSocket */}
          <div className="border-t border-waf-border pt-3 mt-3">
            <p className="text-xs text-waf-text font-medium mb-2">Deep Packet Inspection</p>
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
              <input type="checkbox" checked={form.grpcInspect} onChange={(e) => setForm({ ...form, grpcInspect: e.target.checked })} className="rounded border-waf-border" />
              Inspect gRPC frames (parses length-prefixed Protobuf, extracts UTF-8 strings for rule matching)
            </label>
            {form.grpcInspect && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="grid grid-cols-2 md:grid-cols-3 gap-3 pl-6 mt-2">
                <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer col-span-full">
                  <input type="checkbox" checked={form.grpcBlockOnError} onChange={(e) => setForm({ ...form, grpcBlockOnError: e.target.checked })} className="rounded border-waf-border" />
                  Block when frame caps are exceeded (default = observe + score)
                </label>
                <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer col-span-full">
                  <input type="checkbox" checked={form.grpcBlockCompressed} onChange={(e) => setForm({ ...form, grpcBlockCompressed: e.target.checked })} className="rounded border-waf-border" />
                  Block compressed frames (closes the rule-engine bypass where attackers hide payloads behind any compression codec — turn on once you've confirmed your services don't legitimately use gRPC compression)
                </label>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Max frames per body</label>
                  <input type="number" min={1} value={form.grpcMaxFrames} onChange={(e) => setForm({ ...form, grpcMaxFrames: Math.max(1, Number(e.target.value) || 1024) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Max frame size (bytes)</label>
                  <input type="number" min={1024} value={form.grpcMaxFrameBytes} onChange={(e) => setForm({ ...form, grpcMaxFrameBytes: Math.max(1024, Number(e.target.value) || 1048576) })} className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
              </motion.div>
            )}
            <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer mt-3">
              <input type="checkbox" checked={form.websocketInspect} onChange={(e) => setForm({ ...form, websocketInspect: e.target.checked })} className="rounded border-waf-border" />
              Inspect WebSocket upgrades (rejects off-policy Origin / subprotocol before the handshake completes)
            </label>
            {form.websocketInspect && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-2 pl-6 mt-2">
                <label className="flex items-center gap-2 text-sm text-waf-muted cursor-pointer">
                  <input type="checkbox" checked={form.websocketRequireSubprotocol} onChange={(e) => setForm({ ...form, websocketRequireSubprotocol: e.target.checked })} className="rounded border-waf-border" />
                  Require Sec-WebSocket-Protocol header (rejects upgrades that don't advertise one)
                </label>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Origin allowlist (comma or newline separated; <code>*.example.com</code> wildcards supported)</label>
                  <textarea value={form.websocketOriginAllowlist} onChange={(e) => setForm({ ...form, websocketOriginAllowlist: e.target.value })} rows={2} placeholder="https://app.example.com, https://*.example.com" className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Subprotocol allowlist (case-insensitive)</label>
                  <textarea value={form.websocketSubprotocolAllowlist} onChange={(e) => setForm({ ...form, websocketSubprotocolAllowlist: e.target.value })} rows={2} placeholder="graphql-ws, mqtt" className="w-full bg-waf-elevated border border-waf-border rounded px-3 py-1.5 text-xs text-waf-text focus:outline-none focus:border-waf-orange" />
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Audit chain — tamper-evident operator activity log */}
      <AuditChainCard />

      {/* Alerts */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <h3 className="text-waf-text font-medium text-sm mb-4 flex items-center gap-2"><Bell className="w-4 h-4 text-waf-amber" /> Alerts</h3>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Alert Email</label>
            <input type="email" placeholder="alerts@example.com" value={form.alertEmail} onChange={(e) => setForm({ ...form, alertEmail: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-warning" />
          </div>
          <div>
            <label className="text-xs text-waf-muted mb-1 block">Webhook URL</label>
            <input type="url" placeholder="https://hooks.example.com/waf" value={form.alertWebhook} onChange={(e) => setForm({ ...form, alertWebhook: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-warning" />
          </div>
        </div>
      </motion.div>

      {/* Save Buttons */}
      <div className="space-y-3">
        {backendError && (
          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 text-xs text-red-500">
            {backendError}
          </div>
        )}
        <div className="flex gap-3">
          <button onClick={handleSave} className="flex items-center gap-2 px-6 py-2.5 bg-waf-success text-white rounded-lg text-sm font-medium hover:bg-emerald-600 transition-colors">
            <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save Settings'}
          </button>
          <button onClick={handleReset} className="flex items-center gap-2 px-6 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors">
            <RotateCcw className="w-4 h-4" /> Reset
          </button>
        </div>
      </div>
    </div>
  );
}

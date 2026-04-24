import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle, CheckCircle, HeartPulse, ShieldAlert, Zap, Gauge,
} from 'lucide-react';
import { api, startPolling } from '../services/api';
import type { HealthDetail, ErrorEvent, DDoSStats, ShaperStats } from '../services/api';

// Compact operational panel: watchdog subsystems, DDoS posture, shaper
// posture, recent engine errors. Everything refreshed every 8s so operators
// see the WAF's state without tailing logs.
export default function EngineStatusPanel() {
  const [health, setHealth] = useState<HealthDetail | null>(null);
  const [errors, setErrors] = useState<ErrorEvent[]>([]);
  const [ddos, setDdos] = useState<DDoSStats | null>(null);
  const [shaper, setShaper] = useState<ShaperStats | null>(null);

  useEffect(() => {
    let cancelled = false;
    const pull = async () => {
      const [h, e, d, s] = await Promise.all([
        api.getHealthDetail(),
        api.getErrors(),
        api.getDDoSStats(),
        api.getShaperStats(),
      ]);
      if (cancelled) return;
      if (h) setHealth(h);
      if (e?.errors) setErrors(e.errors.slice(-20).reverse());
      if (d) setDdos(d);
      if (s) setShaper(s);
    };
    pull();
    const stop = startPolling(pull, 8000);
    return () => { cancelled = true; stop(); };
  }, []);

  const overall = health?.overall ?? 'unknown';
  const overallColour =
    overall === 'ok' ? 'text-emerald-400' :
    overall === 'degraded' ? 'text-amber-400' :
    overall === 'fail' ? 'text-red-400' : 'text-waf-dim';

  const underAttack = !!ddos?.under_attack;
  const shaperPressure = !!shaper?.under_pressure;

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <HeartPulse className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Engine Status
        </h2>
        <span className={`text-[10px] uppercase tracking-wider ${overallColour}`}>{overall}</span>
      </div>

      {/* Alert row — only renders when there's something to flag */}
      {(underAttack || shaperPressure) && (
        <div className="mb-2 p-2 rounded-md bg-red-500/5 border border-red-500/20 flex items-center gap-2 text-[11px]">
          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
          <div className="text-red-400">
            {underAttack && <span>DDoS mitigation active</span>}
            {underAttack && shaperPressure && <span> · </span>}
            {shaperPressure && <span>Shaper tightened to {shaper?.current_rps?.toFixed(0)} rps</span>}
          </div>
        </div>
      )}

      {/* DDoS + Shaper posture */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        <PostureTile
          label="DDoS"
          icon={Zap}
          ok={!underAttack}
          primary={underAttack ? 'UNDER ATTACK' : 'normal'}
          secondary={ddos ? `baseline ~${Math.round(ddos.adaptive_baseline || 0)} rps · streak ${ddos.spike_streak ?? 0}/${ddos.spike_windows_req ?? 3}` : undefined}
        />
        <PostureTile
          label="Shaper"
          icon={Gauge}
          ok={!shaperPressure}
          primary={shaper?.enabled ? (shaperPressure ? 'tightened' : 'nominal') : 'disabled'}
          secondary={shaper?.enabled ? `${shaper.admitted?.toLocaleString() ?? 0} admit / ${shaper.rejected?.toLocaleString() ?? 0} drop` : undefined}
        />
      </div>

      {/* Counter row for DDoS triggers */}
      {ddos && (
        <div className="grid grid-cols-4 gap-1.5 mb-3 text-center">
          <MiniStat label="volum" value={ddos.flagged_volumetric ?? 0} />
          <MiniStat label="conn" value={ddos.flagged_conn_rate ?? 0} />
          <MiniStat label="slow" value={ddos.flagged_slow_read ?? 0} />
          <MiniStat label="botnet" value={ddos.flagged_botnet ?? 0} highlight={(ddos.flagged_botnet ?? 0) > 0} />
        </div>
      )}

      {/* Subsystem grid */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        {(health?.subsystems ?? []).map((s) => {
          const colour =
            s.status === 'ok' ? 'text-emerald-400' :
            s.status === 'degraded' ? 'text-amber-400' : 'text-red-400';
          const Icon = s.status === 'ok' ? CheckCircle :
            s.status === 'degraded' ? Activity : AlertTriangle;
          return (
            <motion.div key={s.subsystem} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="p-2 rounded-md bg-waf-elevated/50 border border-waf-border/50">
              <div className="flex items-center gap-1.5">
                <Icon className={`w-3.5 h-3.5 ${colour}`} />
                <span className="text-[11px] font-semibold text-waf-text capitalize">{s.subsystem}</span>
              </div>
              <div className={`text-[10px] ${colour}`}>{s.status}</div>
              {s.message && <div className="text-[10px] text-waf-dim truncate">{s.message}</div>}
            </motion.div>
          );
        })}
        {(!health || (health.subsystems ?? []).length === 0) && (
          <div className="col-span-2 text-center py-4 text-waf-dim text-xs">
            Watchdog hasn't produced any samples yet.
          </div>
        )}
      </div>

      {/* Errors */}
      <div className="flex items-center gap-1.5 mb-2 pt-2 border-t border-waf-border/40">
        <ShieldAlert className="w-3.5 h-3.5 text-waf-orange" />
        <span className="text-[10px] uppercase tracking-wider text-waf-muted">
          Recent Errors {errors.length > 0 && `(${errors.length})`}
        </span>
      </div>
      <div className="flex-1 overflow-y-auto pr-1 space-y-1">
        {errors.length === 0 ? (
          <div className="text-[11px] text-waf-dim py-2">No errors recorded.</div>
        ) : errors.map((e, i) => (
          <div key={i} className="p-1.5 rounded-md bg-red-500/5 border border-red-500/20">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-red-400 font-semibold">{e.source}</span>
              {e.request_id && <span className="text-[9px] text-waf-dim font-mono">{e.request_id}</span>}
              <span className="text-[9px] text-waf-dim ml-auto">
                {new Date(e.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div className="text-[10px] text-waf-muted truncate">{e.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PostureTile({ label, icon: Icon, ok, primary, secondary }: {
  label: string;
  icon: React.ElementType;
  ok: boolean;
  primary: string;
  secondary?: string;
}) {
  return (
    <div className={`p-2 rounded-md border ${ok ? 'bg-waf-elevated/50 border-waf-border/50' : 'bg-red-500/5 border-red-500/30'}`}>
      <div className="flex items-center gap-1.5">
        <Icon className={`w-3.5 h-3.5 ${ok ? 'text-waf-orange' : 'text-red-400'}`} />
        <span className="text-[11px] font-semibold text-waf-text">{label}</span>
      </div>
      <div className={`text-[10px] uppercase tracking-wider ${ok ? 'text-waf-muted' : 'text-red-400'}`}>{primary}</div>
      {secondary && <div className="text-[10px] text-waf-dim truncate">{secondary}</div>}
    </div>
  );
}

function MiniStat({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className={`p-1.5 rounded-md ${highlight ? 'bg-red-500/10 border border-red-500/30' : 'bg-waf-elevated/40 border border-waf-border/30'}`}>
      <div className={`text-[10px] tabular-nums font-bold ${highlight ? 'text-red-400' : 'text-waf-text'}`}>
        {value.toLocaleString()}
      </div>
      <div className="text-[9px] text-waf-dim uppercase">{label}</div>
    </div>
  );
}

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { ArrowDown, Shield, AlertTriangle, CheckCircle, Server, Ban, Activity } from 'lucide-react';
import { useWAF } from '../store/wafStore';
import ConnectionBadge from './ConnectionBadge';

export default function TrafficPanel() {
  const { state } = useWAF();
  const { trafficStats, securityEvents, settings, connectionState } = state;

  // Derive category hits from actual recent blocks so the panel reflects live
  // attack mix rather than mock counters on wafRules.
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const ev of securityEvents) {
      const t = (ev.type || 'other').toLowerCase();
      counts[t] = (counts[t] || 0) + 1;
    }
    return counts;
  }, [securityEvents]);

  const threatTypes = [
    { label: 'XSS Attempts', count: categoryCounts['xss'] || 0, icon: AlertTriangle },
    { label: 'SQL Injection', count: categoryCounts['sql_injection'] || categoryCounts['sqli'] || 0, icon: Shield },
    { label: 'Brute Force', count: categoryCounts['brute_force'] || 0, icon: Ban },
    { label: 'Rate Limit', count: categoryCounts['rate_limit'] || 0, icon: Activity },
  ];

  const modeLabel = settings.mode === 'active' ? 'Active' : settings.mode === 'detection' ? 'Detection' : 'Learning';
  const endpointOk = connectionState === 'online';

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5 h-full">
      <div className="flex items-center justify-between mb-3 sm:mb-4 lg:mb-6">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <ArrowDown className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Incoming Traffic
        </h2>
        <ConnectionBadge variant="dot" />
      </div>

      <div className="bg-waf-elevated rounded-lg p-2.5 sm:p-3 lg:p-4 mb-3 sm:mb-4 lg:mb-5 border border-waf-border">
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="w-7 h-7 sm:w-8 sm:h-8 lg:w-10 lg:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center shrink-0">
            <Server className="w-3.5 h-3.5 sm:w-4 sm:h-4 lg:w-5 lg:h-5 text-waf-orange" />
          </div>
          <div className="min-w-0">
            <p className="text-waf-text text-[11px] sm:text-sm font-medium">Endpoint Status</p>
            <p className="text-waf-dim text-[9px] sm:text-xs">
              {endpointOk ? 'Backend reachable' : 'Backend unreachable'}
            </p>
          </div>
          <CheckCircle
            className={`w-3.5 h-3.5 sm:w-4 sm:h-4 lg:w-5 lg:h-5 ml-auto shrink-0 ${
              endpointOk ? 'text-waf-orange' : 'text-waf-dim'
            }`}
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1.5 sm:gap-2 lg:gap-3 mb-3 sm:mb-4 lg:mb-5">
        <StatCard label="Total Requests" value={trafficStats.totalRequests} delay={0.1} />
        <StatCard label="Blocked" value={trafficStats.blockedRequests} color="text-red-500" delay={0.2} />
        <StatCard label="Allowed" value={trafficStats.allowedRequests} color="text-green-500" delay={0.3} />
        <StatCard label="Unique IPs" value={trafficStats.uniqueIPs} color="text-waf-orange" delay={0.4} />
      </div>

      <div className="mb-3 sm:mb-4">
        <p className="text-waf-muted text-[9px] sm:text-[10px] lg:text-xs uppercase tracking-wider mb-1.5 sm:mb-2 lg:mb-3 font-medium">Known Blocks</p>
        <div className="space-y-1 sm:space-y-1.5 lg:space-y-2">
          {threatTypes.map((threat, index) => {
            const Icon = threat.icon;
            return (
              <motion.div
                key={threat.label}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.5 + index * 0.1 }}
                className="flex items-center gap-1.5 sm:gap-2 lg:gap-3 p-1.5 sm:p-2 lg:p-2.5 rounded-md bg-waf-elevated/50 border border-waf-border/50"
              >
                <Icon className="w-3 h-3 sm:w-3.5 sm:h-3.5 lg:w-4 lg:h-4 text-waf-orange shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-waf-muted text-[10px] sm:text-xs lg:text-sm truncate">{threat.label}</p>
                </div>
                <span className="text-waf-orange font-bold text-[10px] sm:text-xs lg:text-sm tabular-nums">{threat.count}</span>
              </motion.div>
            );
          })}
        </div>
      </div>

      <div className="bg-waf-elevated/50 rounded-lg p-2 sm:p-3 border border-waf-border/50">
        <p className="text-waf-dim text-[9px] sm:text-xs mb-1 sm:mb-2">WAF Actions</p>
        <div className="flex items-center justify-between text-[10px] sm:text-xs lg:text-sm">
          <span className="text-waf-muted">Mode</span>
          <span className="text-waf-orange font-medium">{modeLabel}</span>
        </div>
        <div className="flex items-center justify-between text-[10px] sm:text-xs lg:text-sm mt-0.5 sm:mt-1">
          <span className="text-waf-muted">Pass Through</span>
          <span className={`font-medium ${endpointOk ? 'text-waf-orange' : 'text-waf-dim'}`}>
            {endpointOk ? 'Enabled' : 'Offline'}
          </span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color = 'text-waf-text', delay }: { label: string; value: number; color?: string; delay: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay }}
      className="bg-waf-elevated rounded-lg p-2 sm:p-2.5 lg:p-3 border border-waf-border"
    >
      <p className="text-waf-dim text-[8px] sm:text-[9px] lg:text-xs uppercase tracking-wider mb-0.5 lg:mb-1">{label}</p>
      <p className={`text-base sm:text-xl lg:text-2xl font-bold tabular-nums ${color}`}>{value.toLocaleString()}</p>
    </motion.div>
  );
}

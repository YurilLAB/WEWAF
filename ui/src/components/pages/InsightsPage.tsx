import { useMemo, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, CheckCircle, TrendingUp, Lock, Globe,
  Zap, Eye, Clock, ChevronRight, X, ArrowUpRight, ArrowDownRight,
  Activity, Server, Users, FileWarning, RotateCcw, Sparkles,
  Ban, Fingerprint, Wifi,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';

interface Recommendation {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  action: string;
  icon: React.ElementType;
  resolved: boolean;
}

interface TrendMetric {
  label: string;
  value: number;
  change: number;
  trend: 'up' | 'down' | 'stable';
}

export default function InsightsPage() {
  const { state } = useWAF();
  const { securityEvents, trafficStats, wafRules, settings, rateLimits, ipReputation, sslConfig, domains, nextSteps } = state;
  const [dismissedRecs, setDismissedRecs] = useState<Set<string>>(new Set());
  const [activeDetail, setActiveDetail] = useState<string | null>(null);

  // ---- SECURITY SCORE CALCULATION ----
  const securityScore = useMemo(() => {
    let score = 100;
    const penalties: { reason: string; penalty: number }[] = [];

    // Deduct for disabled rules
    const disabledRules = wafRules.filter((r) => !r.enabled).length;
    if (disabledRules > 0) {
      const p = Math.min(disabledRules * 5, 30);
      score -= p;
      penalties.push({ reason: `${disabledRules} WAF rules disabled`, penalty: p });
    }

    // Deduct for no rate limiting configured
    if (rateLimits.length === 0) {
      score -= 15;
      penalties.push({ reason: 'No rate limiting configured', penalty: 15 });
    }

    // Deduct for detection mode
    if (settings.mode === 'detection') {
      score -= 20;
      penalties.push({ reason: 'WAF in detection mode (not blocking)', penalty: 20 });
    } else if (settings.mode === 'learning') {
      score -= 10;
      penalties.push({ reason: 'WAF in learning mode', penalty: 10 });
    }

    // Deduct for no SSL
    if (!sslConfig.enabled) {
      score -= 10;
      penalties.push({ reason: 'SSL/TLS not enabled', penalty: 10 });
    }

    // Deduct for high recent threats
    if (securityEvents.length > 50) {
      score -= 5;
      penalties.push({ reason: 'High volume of recent threats', penalty: 5 });
    }

    // Deduct for no domains configured
    if (domains.length === 0) {
      score -= 10;
      penalties.push({ reason: 'No domains configured', penalty: 10 });
    }

    // Deduct for uncompleted setup steps
    const incompleteSteps = nextSteps.filter((s) => !s.completed).length;
    if (incompleteSteps > 0) {
      const p = Math.min(incompleteSteps * 3, 15);
      score -= p;
      penalties.push({ reason: `${incompleteSteps} setup steps incomplete`, penalty: p });
    }

    // Deduct for empty IP reputation (no custom blocks)
    if (ipReputation.length === 0) {
      score -= 5;
      penalties.push({ reason: 'No IP reputation rules configured', penalty: 5 });
    }

    return { score: Math.max(0, score), penalties };
  }, [wafRules, rateLimits, settings.mode, sslConfig.enabled, securityEvents.length, domains.length, nextSteps, ipReputation.length]);

  // ---- TREND METRICS ----
  const trendMetrics: TrendMetric[] = useMemo(() => {
    const blockRate = trafficStats.totalRequests > 0 ? (trafficStats.blockedRequests / trafficStats.totalRequests) * 100 : 0;
    return [
      { label: 'Block Rate', value: Math.round(blockRate), change: Math.round(blockRate * 0.1), trend: blockRate > 5 ? 'up' : 'stable' },
      { label: 'Active Rules', value: wafRules.filter((r) => r.enabled).length, change: 0, trend: 'stable' },
      { label: 'Threat Events', value: securityEvents.length, change: Math.max(0, securityEvents.length - 10), trend: securityEvents.length > 20 ? 'up' : 'stable' },
      { label: 'Protected Domains', value: domains.length, change: 0, trend: domains.length > 0 ? 'stable' : 'down' },
    ];
  }, [trafficStats, wafRules, securityEvents.length, domains.length]);

  // ---- THREAT INTELLIGENCE ----
  const threatIntel = useMemo(() => {
    const typeCounts: Record<string, number> = {};
    const countryCounts: Record<string, number> = {};
    const ipCounts: Record<string, number> = {};

    securityEvents.forEach((e) => {
      typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
      countryCounts[e.country] = (countryCounts[e.country] || 0) + 1;
      ipCounts[e.sourceIP] = (ipCounts[e.sourceIP] || 0) + 1;
    });

    const topThreats = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topCountries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    return { topThreats, topCountries, topIPs, totalEvents: securityEvents.length };
  }, [securityEvents]);

  // ---- ACTIONABLE RECOMMENDATIONS ----
  const recommendations = useMemo<Recommendation[]>(() => {
    const recs: Recommendation[] = [];

    if (settings.mode === 'detection') {
      recs.push({
        id: 'mode-active',
        severity: 'critical',
        title: 'WAF Not Blocking Threats',
        description: 'Your WAF is running in detection mode. Malicious requests are logged but NOT blocked. Switch to active mode for production.',
        action: 'Go to Settings > Security Mode',
        icon: Shield,
        resolved: false,
      });
    }

    if (settings.mode === 'learning') {
      recs.push({
        id: 'mode-learning',
        severity: 'warning',
        title: 'WAF Still Learning',
        description: 'Learning mode builds a baseline but does not enforce rules. Switch to active mode once baseline is established.',
        action: 'Go to Settings > Security Mode',
        icon: Sparkles,
        resolved: false,
      });
    }

    const disabledRules = wafRules.filter((r) => !r.enabled);
    if (disabledRules.length > 0) {
      recs.push({
        id: 'disabled-rules',
        severity: 'critical',
        title: `${disabledRules.length} WAF Rule${disabledRules.length > 1 ? 's' : ''} Disabled`,
        description: `Rules covering ${disabledRules.map((r) => r.category).join(', ')} are not active. These protections are currently bypassed.`,
        action: 'Go to Security > WAF Rules',
        icon: Ban,
        resolved: false,
      });
    }

    if (rateLimits.length === 0) {
      recs.push({
        id: 'no-rate-limit',
        severity: 'critical',
        title: 'No Rate Limiting Configured',
        description: 'Without rate limiting, your endpoints are vulnerable to brute force, DDoS, and scraping attacks.',
        action: 'Go to Security > Rate Limiting',
        icon: Zap,
        resolved: false,
      });
    }

    if (!sslConfig.enabled) {
      recs.push({
        id: 'no-ssl',
        severity: 'warning',
        title: 'SSL/TLS Disabled',
        description: 'Traffic is not encrypted. Credentials, tokens, and user data are transmitted in plaintext.',
        action: 'Go to SSL / TLS > Settings',
        icon: Lock,
        resolved: false,
      });
    }

    if (domains.length === 0) {
      recs.push({
        id: 'no-domains',
        severity: 'warning',
        title: 'No Domains Protected',
        description: 'Add at least one domain to start monitoring and protecting traffic.',
        action: 'Go to Domains',
        icon: Globe,
        resolved: false,
      });
    }

    const incompleteSteps = nextSteps.filter((s) => !s.completed);
    if (incompleteSteps.length > 0) {
      recs.push({
        id: 'incomplete-setup',
        severity: 'info',
        title: `${incompleteSteps.length} Setup Step${incompleteSteps.length > 1 ? 's' : ''} Incomplete`,
        description: `Complete: ${incompleteSteps.map((s) => s.label).join(', ')}`,
        action: 'Check Next Steps on Dashboard',
        icon: CheckCircle,
        resolved: false,
      });
    }

    if (securityEvents.length > 20 && ipReputation.filter((ip) => ip.action === 'block').length === 0) {
      recs.push({
        id: 'reputation-empty',
        severity: 'warning',
        title: 'No IP Reputation Rules',
        description: `${securityEvents.length} threats detected but no IP reputation rules exist. Recurring attackers are not being blocked.`,
        action: 'Go to Security > IP Reputation',
        icon: Fingerprint,
        resolved: false,
      });
    }

    if (ipReputation.filter((ip) => ip.action === 'block').length > 10) {
      recs.push({
        id: 'reputation-cleanup',
        severity: 'info',
        title: 'Review Blocked IPs',
        description: `${ipReputation.length} IPs are blocked. Review if any should be unblocked to avoid false positives.`,
        action: 'Go to Security > IP Reputation',
        icon: Users,
        resolved: false,
      });
    }

    if (securityEvents.length === 0 && wafRules.every((r) => r.enabled)) {
      recs.push({
        id: 'healthy',
        severity: 'info',
        title: 'All Systems Secure',
        description: 'No threats detected. All rules active. WAF is configured correctly.',
        action: 'Monitor dashboard for changes',
        icon: CheckCircle,
        resolved: true,
      });
    }

    return recs;
  }, [settings.mode, wafRules, rateLimits, sslConfig.enabled, domains.length, nextSteps, securityEvents.length, ipReputation]);

  const dismissRec = useCallback((id: string) => {
    setDismissedRecs((prev) => new Set([...prev, id]));
  }, []);

  const visibleRecs = recommendations.filter((r) => !dismissedRecs.has(r.id));
  const criticalCount = visibleRecs.filter((r) => r.severity === 'critical').length;
  const warningCount = visibleRecs.filter((r) => r.severity === 'warning').length;
  const infoCount = visibleRecs.filter((r) => r.severity === 'info').length;
  const resolvedCount = visibleRecs.filter((r) => r.resolved).length;

  const scoreColor = securityScore.score >= 80 ? 'text-emerald-500' : securityScore.score >= 60 ? 'text-waf-amber' : 'text-red-500';
  const scoreBg = securityScore.score >= 80 ? 'bg-emerald-500/10' : securityScore.score >= 60 ? 'bg-waf-amber/10' : 'bg-red-500/10';
  const scoreRing = securityScore.score >= 80 ? 'ring-emerald-500/30' : securityScore.score >= 60 ? 'ring-waf-amber/30' : 'ring-red-500/30';
  const scoreLabel = securityScore.score >= 90 ? 'Excellent' : securityScore.score >= 80 ? 'Good' : securityScore.score >= 60 ? 'Fair' : 'At Risk';

  return (
    <div className="space-y-4 lg:space-y-6">
      <p className="text-waf-dim text-xs lg:text-sm">Zero Trust security intelligence with actionable insights, risk scoring, and prioritized remediation.</p>

      {/* Security Score Hero */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Score Circle */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className={`bg-waf-panel border border-waf-border rounded-xl p-5 lg:p-6 flex flex-col items-center justify-center ${scoreBg} ${scoreRing} ring-1`}
        >
          <div className="relative w-28 h-28 sm:w-32 sm:h-32">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#1a1a1a" strokeWidth="8" />
              <circle
                cx="50" cy="50" r="42" fill="none"
                stroke={securityScore.score >= 80 ? '#10b981' : securityScore.score >= 60 ? '#f97316' : '#ef4444'}
                strokeWidth="8" strokeLinecap="round"
                strokeDasharray={2 * Math.PI * 42}
                strokeDashoffset={2 * Math.PI * 42 - (securityScore.score / 100) * 2 * Math.PI * 42}
                style={{ transition: 'stroke-dashoffset 1.5s cubic-bezier(0.22, 1, 0.36, 1)' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-3xl sm:text-4xl font-bold ${scoreColor}`}>{securityScore.score}</span>
              <span className="text-[10px] text-waf-muted uppercase tracking-wider">{scoreLabel}</span>
            </div>
          </div>
          <p className="text-waf-muted text-xs mt-3 text-center">
            {securityScore.penalties.length > 0
              ? `${securityScore.penalties.length} issue${securityScore.penalties.length > 1 ? 's' : ''} affecting score`
              : 'No issues detected'}
          </p>
        </motion.div>

        {/* Quick Stats */}
        <div className="lg:col-span-2 grid grid-cols-2 gap-3">
          {trendMetrics.map((metric, i) => (
            <motion.div
              key={metric.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="bg-waf-panel border border-waf-border rounded-xl p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-waf-muted text-xs">{metric.label}</span>
                {metric.trend === 'up' && <ArrowUpRight className="w-3.5 h-3.5 text-red-500" />}
                {metric.trend === 'down' && <ArrowDownRight className="w-3.5 h-3.5 text-emerald-500" />}
                {metric.trend === 'stable' && <span className="w-3.5 h-3.5 rounded-full bg-waf-dim/30" />}
              </div>
              <p className="text-waf-text text-xl font-bold">{metric.value.toLocaleString()}</p>
              {metric.change > 0 && (
                <p className="text-[10px] text-waf-dim mt-1">
                  {metric.trend === 'up' ? '+' : '-'}{metric.change} from baseline
                </p>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* Actionable Recommendations */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-waf-text text-sm font-medium flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-waf-orange" /> Actionable Recommendations
          </h3>
          <div className="flex items-center gap-2">
            {criticalCount > 0 && <span className="px-2 py-0.5 bg-red-500/10 text-red-500 rounded text-[10px] font-medium">{criticalCount} Critical</span>}
            {warningCount > 0 && <span className="px-2 py-0.5 bg-waf-amber/10 text-waf-amber rounded text-[10px] font-medium">{warningCount} Warning</span>}
            {resolvedCount > 0 && <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-500 rounded text-[10px] font-medium">{resolvedCount} OK</span>}
          </div>
        </div>

        {visibleRecs.length === 0 ? (
          <div className="text-center py-6">
            <CheckCircle className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
            <p className="text-waf-muted text-sm">All recommendations addressed. Great work!</p>
          </div>
        ) : (
          <div className="space-y-2">
            {visibleRecs.map((rec, i) => {
              const Icon = rec.icon;
              const isOpen = activeDetail === rec.id;
              const severityColor = rec.severity === 'critical' ? 'border-red-500/20 bg-red-500/5' : rec.severity === 'warning' ? 'border-waf-amber/20 bg-waf-amber/5' : rec.resolved ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-waf-border/50 bg-waf-elevated/50';
              const severityText = rec.severity === 'critical' ? 'text-red-500' : rec.severity === 'warning' ? 'text-waf-amber' : rec.resolved ? 'text-emerald-500' : 'text-waf-muted';
              const severityDot = rec.severity === 'critical' ? 'bg-red-500' : rec.severity === 'warning' ? 'bg-waf-amber' : rec.resolved ? 'bg-emerald-500' : 'bg-waf-dim';

              return (
                <motion.div
                  key={rec.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className={`rounded-lg border p-3 ${severityColor} transition-all cursor-pointer`}
                  onClick={() => setActiveDetail(isOpen ? null : rec.id)}
                >
                  <div className="flex items-start gap-3">
                    <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${severityDot}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-3.5 h-3.5 ${severityText} shrink-0`} />
                          <span className={`text-sm font-medium ${rec.resolved ? 'text-emerald-500' : 'text-waf-text'}`}>{rec.title}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[10px] uppercase tracking-wider font-medium ${severityText}`}>{rec.severity}</span>
                          <ChevronRight className={`w-3.5 h-3.5 text-waf-dim transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                        </div>
                      </div>
                      <AnimatePresence>
                        {isOpen && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="overflow-hidden"
                          >
                            <p className="text-waf-dim text-xs mt-2 mb-2">{rec.description}</p>
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-waf-muted">{rec.action}</span>
                              {!rec.resolved && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); dismissRec(rec.id); }}
                                  className="flex items-center gap-1 text-[10px] text-waf-dim hover:text-waf-text transition-colors"
                                >
                                  <X className="w-3 h-3" /> Dismiss
                                </button>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.div>

      {/* Threat Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Threat Types */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-waf-orange" /> Threat Breakdown
          </h3>
          {threatIntel.topThreats.length === 0 ? (
            <div className="text-center py-6">
              <Shield className="w-6 h-6 text-waf-dim mx-auto mb-2 opacity-40" />
              <p className="text-waf-dim text-xs">No threat data collected yet</p>
            </div>
          ) : (
            <div className="space-y-3">
              {threatIntel.topThreats.map(([type, count], i) => {
                const max = threatIntel.topThreats[0][1];
                const pct = max > 0 ? (count / max) * 100 : 0;
                return (
                  <div key={type} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-waf-muted capitalize">{type.replace(/_/g, ' ')}</span>
                      <span className="text-waf-text font-medium">{count}</span>
                    </div>
                    <div className="h-1.5 bg-waf-elevated rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.max(5, pct)}%` }}
                        transition={{ duration: 0.8, delay: i * 0.05 }}
                        className="h-full bg-red-500 rounded-full"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>

        {/* Top Source Countries */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-waf-orange" /> Top Source Countries
          </h3>
          {threatIntel.topCountries.length === 0 ? (
            <div className="text-center py-6">
              <Globe className="w-6 h-6 text-waf-dim mx-auto mb-2 opacity-40" />
              <p className="text-waf-dim text-xs">No geographic data available</p>
            </div>
          ) : (
            <div className="space-y-2">
              {threatIntel.topCountries.map(([country, count], i) => (
                <div key={country} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-waf-elevated flex items-center justify-center text-[10px] text-waf-muted">{i + 1}</span>
                    <span className="text-sm text-waf-text">{country}</span>
                  </div>
                  <span className="text-sm font-bold text-red-500">{count}</span>
                </div>
              ))}
            </div>
          )}
        </motion.div>

        {/* Top Attacker IPs */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-waf-orange" /> Top Attacker IPs
          </h3>
          {threatIntel.topIPs.length === 0 ? (
            <div className="text-center py-6">
              <Wifi className="w-6 h-6 text-waf-dim mx-auto mb-2 opacity-40" />
              <p className="text-waf-dim text-xs">No IP reputation data yet</p>
            </div>
          ) : (
            <div className="space-y-2">
              {threatIntel.topIPs.map(([ip, count], i) => (
                <div key={ip} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-waf-elevated flex items-center justify-center text-[10px] text-waf-muted">{i + 1}</span>
                    <span className="text-sm text-waf-text font-mono">{ip}</span>
                  </div>
                  <span className="text-sm font-bold text-waf-orange">{count}</span>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Score Breakdown */}
      {securityScore.penalties.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
          <h3 className="text-waf-text text-sm font-medium mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-waf-orange" /> Score Breakdown
          </h3>
          <div className="space-y-2">
            {securityScore.penalties.map((p, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-waf-border/30 last:border-0 text-sm">
                <span className="text-waf-muted">{p.reason}</span>
                <span className="text-red-500 font-medium">-{p.penalty} pts</span>
              </div>
            ))}
            <div className="flex items-center justify-between py-2 text-sm font-medium">
              <span className="text-waf-text">Final Score</span>
              <span className={scoreColor}>{securityScore.score}/100</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Reset dismissed */}
      {dismissedRecs.size > 0 && (
        <div className="flex justify-end">
          <button
            onClick={() => setDismissedRecs(new Set())}
            className="flex items-center gap-1.5 text-xs text-waf-muted hover:text-waf-text transition-colors"
          >
            <RotateCcw className="w-3 h-3" /> Restore dismissed recommendations
          </button>
        </div>
      )}
    </div>
  );
}

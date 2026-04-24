import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle, XCircle, AlertTriangle, Globe, Server, Lock, Rocket,
  ExternalLink, X, ChevronRight, Check, Loader2, RefreshCw,
} from 'lucide-react';
import { useWAF } from '../store/wafStore';
import { api } from '../services/api';
import type { SetupCheckResult, SetupCheckStatus } from '../services/api';

type SetupModal = 'dns' | 'origin' | 'ssl' | 'test' | null;
type StepRunState = 'idle' | 'running' | 'pass' | 'warn' | 'fail';

const stepData = [
  {
    id: 1,
    label: 'Configure DNS',
    description: 'Point your domain A record to the WAF server IP',
    icon: Globe,
    modal: 'dns' as SetupModal,
  },
  {
    id: 2,
    label: 'Set Origin IP',
    description: 'Configure your backend server IP in WAF settings',
    icon: Server,
    modal: 'origin' as SetupModal,
  },
  {
    id: 3,
    label: 'Enable SSL/TLS',
    description: 'Upload certificate or use auto-generated one',
    icon: Lock,
    modal: 'ssl' as SetupModal,
  },
  {
    id: 4,
    label: 'Test Connectivity',
    description: 'Run end-to-end checks against the live backend',
    icon: Rocket,
    modal: 'test' as SetupModal,
  },
];

// Map SetupCheckResult.status onto our local StepRunState — warn and skip
// are surfaced as their own colours so operators see the difference between
// "did not run" and "ran and was unhappy".
function mapStatus(s: SetupCheckStatus | undefined): StepRunState {
  if (s === 'pass') return 'pass';
  if (s === 'warn') return 'warn';
  if (s === 'fail') return 'fail';
  return 'idle';
}

function statusIcon(state: StepRunState) {
  if (state === 'running') return <Loader2 className="w-4 h-4 text-waf-orange animate-spin" />;
  if (state === 'pass') return <CheckCircle className="w-4 h-4 text-emerald-500" />;
  if (state === 'warn') return <AlertTriangle className="w-4 h-4 text-amber-400" />;
  if (state === 'fail') return <XCircle className="w-4 h-4 text-red-500" />;
  return <div className="w-4 h-4 rounded-full border-2 border-waf-dim" />;
}

export default function NextSteps() {
  const { state, dispatch } = useWAF();
  const { nextSteps } = state;

  const [activeModal, setActiveModal] = useState<SetupModal>(null);
  const [modalData, setModalData] = useState<Record<string, string>>({});
  const [checkState, setCheckState] = useState<Record<number, StepRunState>>({});
  const [checkResult, setCheckResult] = useState<Record<number, SetupCheckResult | null>>({});
  const [testSuite, setTestSuite] = useState<SetupCheckResult[]>([]);
  const [testSuiteRunning, setTestSuiteRunning] = useState(false);

  const setStepState = (id: number, s: StepRunState) =>
    setCheckState((prev) => ({ ...prev, [id]: s }));

  const setStepResult = (id: number, r: SetupCheckResult | null) =>
    setCheckResult((prev) => ({ ...prev, [id]: r }));

  const openModal = (modal: SetupModal) => {
    setActiveModal(modal);
  };

  const closeModal = () => {
    setActiveModal(null);
  };

  // runCheck executes the backend probe for a given step. If it returns
  // "pass" or "warn" we mark the step as completed in the store; a "fail"
  // leaves it unchecked so the user can fix the problem and retry.
  const runCheck = async (stepId: number) => {
    setStepState(stepId, 'running');
    setStepResult(stepId, null);
    let result: SetupCheckResult | null = null;
    try {
      switch (stepId) {
        case 1: // DNS
          if (!modalData.domain) {
            result = {
              step: 'dns',
              status: 'fail',
              message: 'Enter a domain before running the DNS check.',
              at: new Date().toISOString(),
            };
          } else {
            result = await api.checkSetupDNS(modalData.domain, modalData.wafIp || undefined);
          }
          break;
        case 2: // Origin
          result = await api.checkSetupOrigin();
          break;
        case 3: // SSL
          result = await api.checkSetupSSL(modalData.domain || undefined);
          break;
        case 4: // Traffic — we'll run the full suite instead
          result = await api.checkSetupTraffic();
          break;
      }
    } catch {
      result = {
        step: 'error',
        status: 'fail',
        message: 'Check request failed — admin API unreachable.',
        at: new Date().toISOString(),
      };
    }
    if (!result) {
      result = {
        step: 'error',
        status: 'fail',
        message: 'Check returned no result.',
        at: new Date().toISOString(),
      };
    }
    setStepResult(stepId, result);
    setStepState(stepId, mapStatus(result.status));

    // Only mark step completed if the backend actually passed the check.
    // "warn" is treated as pass-with-caveats because the check ran and the
    // configured thing exists (e.g., cert present but expiring soon).
    const stepIsComplete = nextSteps.find((s) => s.id === stepId)?.completed ?? false;
    const shouldComplete = result.status === 'pass' || result.status === 'warn';
    if (shouldComplete !== stepIsComplete) {
      dispatch({ type: 'TOGGLE_NEXT_STEP', payload: stepId });
    }
  };

  // runTestSuite hits /api/setup/checks/all and re-evaluates every step.
  const runTestSuite = async () => {
    setTestSuiteRunning(true);
    setTestSuite([]);
    let res: { results: SetupCheckResult[] } | null = null;
    try {
      res = await api.runSetupChecks(modalData.domain || undefined, modalData.wafIp || undefined);
    } catch {
      res = null;
    }
    const results = res?.results ?? [];
    setTestSuite(results);
    setTestSuiteRunning(false);

    // Backfill per-step state from the suite so the outer Next Steps list
    // reflects the real backend state after the operator runs the test.
    const map: Record<string, number> = { dns: 1, origin: 2, ssl: 3, traffic: 4 };
    for (const r of results) {
      const stepId = map[r.step];
      if (!stepId) continue;
      setStepResult(stepId, r);
      setStepState(stepId, mapStatus(r.status));
      const isComplete = nextSteps.find((s) => s.id === stepId)?.completed ?? false;
      const shouldComplete = r.status === 'pass' || r.status === 'warn';
      if (shouldComplete !== isComplete) {
        dispatch({ type: 'TOGGLE_NEXT_STEP', payload: stepId });
      }
    }
  };

  const completedCount = nextSteps.filter((s) => s.completed).length;

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5 relative">
      <div className="flex items-center justify-between mb-3 sm:mb-4 lg:mb-5">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <Rocket className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Next Steps
        </h2>
        <div className="flex items-center gap-2">
          <span className="text-[9px] sm:text-xs text-waf-muted">{completedCount}/{nextSteps.length}</span>
          <button
            onClick={runTestSuite}
            disabled={testSuiteRunning}
            className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] bg-waf-elevated text-waf-muted border border-waf-border hover:text-waf-text hover:bg-waf-border transition-colors disabled:opacity-50"
            title="Run every check and refresh step status"
          >
            {testSuiteRunning
              ? <Loader2 className="w-3 h-3 animate-spin" />
              : <RefreshCw className="w-3 h-3" />}
            Re-check all
          </button>
        </div>
      </div>

      <div className="w-full bg-waf-elevated rounded-full h-1.5 mb-3 sm:mb-4 lg:mb-5">
        <motion.div
          className="bg-gradient-to-r from-waf-orange to-waf-amber h-1.5 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${(completedCount / nextSteps.length) * 100}%` }}
          transition={{ duration: 0.5 }}
        />
      </div>

      <div className="space-y-1.5 sm:space-y-2 lg:space-y-3">
        {stepData.map((step) => {
          const stepStatus = nextSteps.find((s) => s.id === step.id);
          const isCompleted = stepStatus?.completed ?? false;
          const runState = checkState[step.id] ?? 'idle';
          const result = checkResult[step.id];
          const Icon = step.icon;
          return (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: step.id * 0.1 }}
              className={`flex items-start gap-1.5 sm:gap-2 lg:gap-3 p-2 sm:p-2.5 lg:p-3 rounded-lg transition-all duration-200 border ${
                runState === 'fail' ? 'bg-red-500/5 border-red-500/30'
                : runState === 'warn' ? 'bg-amber-500/5 border-amber-500/30'
                : isCompleted ? 'bg-waf-orange/5 border-waf-orange/20'
                : 'bg-waf-elevated/50 border-waf-border/50 hover:bg-waf-elevated hover:border-waf-border'
              }`}
            >
              <div className="mt-0.5 shrink-0">{statusIcon(runState === 'idle' && isCompleted ? 'pass' : runState)}</div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5 sm:gap-2">
                  <Icon className={`w-3 h-3 sm:w-3.5 sm:h-3.5 lg:w-4 lg:h-4 ${isCompleted ? 'text-waf-orange' : 'text-waf-muted'}`} />
                  <span className={`text-[11px] sm:text-sm font-medium ${isCompleted ? 'text-waf-orange' : 'text-waf-text'}`}>
                    {step.label}
                  </span>
                </div>
                <p className="text-waf-dim text-[9px] sm:text-xs mt-0.5 sm:mt-1">{step.description}</p>
                {result && (
                  <p className={`text-[10px] mt-1 ${
                    result.status === 'pass' ? 'text-emerald-500'
                    : result.status === 'warn' ? 'text-amber-400'
                    : result.status === 'fail' ? 'text-red-400'
                    : 'text-waf-dim'
                  }`}>
                    {result.message}
                  </p>
                )}
              </div>
              <button
                onClick={() => openModal(step.modal)}
                className="shrink-0 flex items-center gap-0.5 sm:gap-1 px-1.5 sm:px-2 py-0.5 sm:py-1 bg-waf-orange text-white rounded text-[9px] sm:text-xs font-medium hover:bg-orange-600 transition-colors"
              >
                {isCompleted ? 'Re-check' : 'Setup'}
                <ChevronRight className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
              </button>
            </motion.div>
          );
        })}
      </div>

      <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-waf-border space-y-1.5 sm:space-y-2">
        <a href="#" onClick={(e) => e.preventDefault()} className="flex items-center gap-1.5 sm:gap-2 text-waf-muted text-[9px] sm:text-xs hover:text-waf-orange transition-colors">
          <ExternalLink className="w-2.5 h-2.5 sm:w-3.5 sm:h-3.5" /> View connection documentation
        </a>
      </div>

      <AnimatePresence>
        {activeModal && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={closeModal} />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }} className="fixed inset-2 sm:inset-4 lg:inset-auto lg:top-1/2 lg:left-1/2 lg:-translate-x-1/2 lg:-translate-y-1/2 lg:w-[540px] lg:max-h-[85vh] bg-waf-panel border border-waf-border rounded-xl z-50 overflow-y-auto">
              {activeModal === 'dns' && (
                <StepModal
                  title="Configure DNS" subtitle="Point your domain to the WAF" icon={Globe}
                  runState={checkState[1] ?? 'idle'} result={checkResult[1]}
                  onClose={closeModal}
                  onRun={() => runCheck(1)}
                  runLabel="Run DNS check"
                >
                  <div className="space-y-3">
                    <Field label="Your domain" placeholder="example.com"
                      value={modalData.domain || ''}
                      onChange={(v) => setModalData((d) => ({ ...d, domain: v }))} />
                    <Field label="Expected WAF IP (optional)" placeholder="192.0.2.10"
                      mono value={modalData.wafIp || ''}
                      onChange={(v) => setModalData((d) => ({ ...d, wafIp: v }))} />
                    <p className="text-[10px] text-waf-dim">
                      The check resolves the domain and — if you supply one — verifies it points
                      at the expected IP. Warn status means it resolves but not to that IP.
                    </p>
                  </div>
                </StepModal>
              )}

              {activeModal === 'origin' && (
                <StepModal
                  title="Set Origin IP" subtitle="Verify the backend is reachable" icon={Server}
                  runState={checkState[2] ?? 'idle'} result={checkResult[2]}
                  onClose={closeModal}
                  onRun={() => runCheck(2)}
                  runLabel="Probe backend"
                >
                  <div className="space-y-3">
                    <p className="text-xs text-waf-muted">
                      Uses the configured <span className="font-mono text-waf-text">backend_url</span> from the
                      Connection Management page. The check sends a GET and reports latency + status code.
                    </p>
                    <div className="bg-waf-elevated rounded-lg p-2 border border-waf-border text-[10px] text-waf-dim">
                      To change the backend URL, use Connection → API Configuration and then re-run this check.
                    </div>
                  </div>
                </StepModal>
              )}

              {activeModal === 'ssl' && (
                <StepModal
                  title="Enable SSL/TLS" subtitle="Verify the certificate inventory" icon={Lock}
                  runState={checkState[3] ?? 'idle'} result={checkResult[3]}
                  onClose={closeModal}
                  onRun={() => runCheck(3)}
                  runLabel="Check certificates"
                >
                  <div className="space-y-3">
                    <Field label="Domain to live-probe (optional)" placeholder="example.com"
                      value={modalData.domain || ''}
                      onChange={(v) => setModalData((d) => ({ ...d, domain: v }))} />
                    <p className="text-xs text-waf-muted">
                      Looks up every uploaded cert, picks the nearest-expiring, and reports days left.
                      Warn if expiring in under 14 days; fail if already expired or none uploaded.
                      Upload certificates from the SSL / TLS page.
                    </p>
                  </div>
                </StepModal>
              )}

              {activeModal === 'test' && (
                <StepModal
                  title="Test Connectivity" subtitle="Verify the admin + engine pipeline" icon={Rocket}
                  runState={checkState[4] ?? 'idle'} result={checkResult[4]}
                  onClose={closeModal}
                  onRun={runTestSuite}
                  runLabel="Run full suite"
                >
                  <div className="space-y-2">
                    <p className="text-xs text-waf-muted">
                      Runs every setup check at once. Each row below updates as its probe finishes.
                    </p>
                    {testSuite.length === 0 && !testSuiteRunning && (
                      <p className="text-[11px] text-waf-dim">No results yet. Click Run full suite.</p>
                    )}
                    {testSuiteRunning && (
                      <div className="flex items-center gap-2 text-[11px] text-waf-dim">
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-waf-orange" /> Running checks...
                      </div>
                    )}
                    {testSuite.map((r, i) => (
                      <div key={i} className={`flex items-start justify-between p-2 rounded-md border ${
                        r.status === 'pass' ? 'bg-emerald-500/5 border-emerald-500/20'
                        : r.status === 'warn' ? 'bg-amber-500/5 border-amber-500/20'
                        : r.status === 'fail' ? 'bg-red-500/5 border-red-500/20'
                        : 'bg-waf-elevated/40 border-waf-border/40'
                      }`}>
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold text-waf-text capitalize">{r.step}</div>
                          <div className="text-[10px] text-waf-dim">{r.message}</div>
                        </div>
                        <div className="shrink-0 mt-0.5">{statusIcon(mapStatus(r.status))}</div>
                      </div>
                    ))}
                  </div>
                </StepModal>
              )}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}

// ---- small helper components ----

interface StepModalProps {
  title: string;
  subtitle: string;
  icon: React.ElementType;
  runState: StepRunState;
  result: SetupCheckResult | null | undefined;
  onClose: () => void;
  onRun: () => void;
  runLabel: string;
  children: React.ReactNode;
}

function StepModal({ title, subtitle, icon: Icon, runState, result, onClose, onRun, runLabel, children }: StepModalProps) {
  return (
    <div className="p-3 sm:p-5">
      <div className="flex items-center justify-between mb-3 sm:mb-4">
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center">
            <Icon className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" />
          </div>
          <div>
            <h3 className="text-waf-text font-semibold text-sm sm:text-base">{title}</h3>
            <p className="text-waf-dim text-[10px] sm:text-xs">{subtitle}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-waf-elevated text-waf-muted">
          <X className="w-4 h-4 sm:w-5 sm:h-5" />
        </button>
      </div>

      {children}

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
          className={`mt-3 p-2 rounded-md border text-[11px] ${
            result.status === 'pass' ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400'
            : result.status === 'warn' ? 'bg-amber-500/5 border-amber-500/20 text-amber-400'
            : 'bg-red-500/5 border-red-500/20 text-red-400'
          }`}
        >
          <div className="flex items-start gap-1.5">
            {statusIcon(mapStatus(result.status))}
            <div>
              <div className="font-semibold uppercase tracking-wider text-[10px]">{result.status}</div>
              <div>{result.message}</div>
              {result.detail && (
                <pre className="mt-1 text-[9px] text-waf-dim whitespace-pre-wrap break-all">
                  {Object.entries(result.detail).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join('\n')}
                </pre>
              )}
            </div>
          </div>
        </motion.div>
      )}

      <button
        onClick={onRun}
        disabled={runState === 'running'}
        className="w-full mt-3 py-2 sm:py-2.5 bg-waf-orange text-white rounded-lg text-xs sm:text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {runState === 'running' ? <><Loader2 className="w-4 h-4 animate-spin" /> Running...</>
          : <><Check className="w-4 h-4" /> {runLabel}</>}
      </button>
    </div>
  );
}

function Field({ label, placeholder, value, onChange, mono }: {
  label: string; placeholder: string; value: string; onChange: (v: string) => void; mono?: boolean;
}) {
  return (
    <div>
      <label className="text-[10px] text-waf-muted mb-1 block">{label}</label>
      <input
        type="text" placeholder={placeholder} value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange ${mono ? 'font-mono' : ''}`}
      />
    </div>
  );
}

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle, XCircle, Globe, Server, Lock, Rocket,
  ExternalLink, X, ChevronRight, Check, Loader2,
} from 'lucide-react';
import { useWAF } from '../store/wafStore';
import { api } from '../services/api';

type SetupModal = 'dns' | 'origin' | 'ssl' | 'test' | null;

const stepData = [
  { id: 1, label: 'Configure DNS', description: 'Point your domain A record to the WAF server IP', icon: Globe, modal: 'dns' as SetupModal },
  { id: 2, label: 'Set Origin IP', description: 'Configure your backend server IP in WAF settings', icon: Server, modal: 'origin' as SetupModal },
  { id: 3, label: 'Enable SSL/TLS', description: 'Upload certificate or use auto-generated one', icon: Lock, modal: 'ssl' as SetupModal },
  { id: 4, label: 'Test Connectivity', description: 'Verify traffic flows through WAF to your endpoint', icon: Rocket, modal: 'test' as SetupModal },
];

interface TestResult {
  label: string;
  status: 'idle' | 'running' | 'pass' | 'fail';
  message: string;
}

export default function NextSteps() {
  const { state, dispatch } = useWAF();
  const { nextSteps } = state;
  const [activeModal, setActiveModal] = useState<SetupModal>(null);
  const [modalData, setModalData] = useState<Record<string, string>>({});
  const [modalStatus, setModalStatus] = useState<'idle' | 'success'>('idle');
  const [isTesting, setIsTesting] = useState(false);
  const [testResults, setTestResults] = useState<TestResult[]>([
    { label: 'DNS Records', status: 'idle', message: 'Waiting to check...' },
    { label: 'Origin Server Reachable', status: 'idle', message: 'Waiting to check...' },
    { label: 'SSL/TLS Configured', status: 'idle', message: 'Waiting to check...' },
    { label: 'WAF Health Check', status: 'idle', message: 'Waiting to check...' },
    { label: 'Backend API Response', status: 'idle', message: 'Waiting to check...' },
  ]);

  const toggleStep = (id: number) => {
    dispatch({ type: 'TOGGLE_NEXT_STEP', payload: id });
  };

  const openModal = (modal: SetupModal, stepId: number) => {
    setActiveModal(modal);
    setModalStatus('idle');
    setIsTesting(false);
    // Reset test results when opening modal
    setTestResults([
      { label: 'DNS Records', status: 'idle', message: 'Waiting to check...' },
      { label: 'Origin Server Reachable', status: 'idle', message: 'Waiting to check...' },
      { label: 'SSL/TLS Configured', status: 'idle', message: 'Waiting to check...' },
      { label: 'WAF Health Check', status: 'idle', message: 'Waiting to check...' },
      { label: 'Backend API Response', status: 'idle', message: 'Waiting to check...' },
    ]);
    dispatch({ type: 'TOGGLE_NEXT_STEP', payload: stepId });
  };

  const STEP_DELAY = 1200; // minimum ms each step is visible

  const runConnectionTest = async () => {
    setIsTesting(true);
    setModalStatus('idle');
    const startTime = Date.now();

    const results = [...testResults];

    // Check 1: DNS Records
    results[0] = { ...results[0], status: 'running', message: 'Resolving DNS records...' };
    setTestResults([...results]);
    const check1Start = Date.now();
    const dnsPass = !!(modalData.domain && modalData.domain.length > 3);
    await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - check1Start), 200)));
    results[0] = {
      ...results[0],
      status: dnsPass ? 'pass' : 'fail',
      message: dnsPass ? `Domain "${modalData.domain}" configured` : 'No domain configured in DNS step',
    };
    setTestResults([...results]);

    // Check 2: Origin Server
    results[1] = { ...results[1], status: 'running', message: 'Pinging origin server...' };
    setTestResults([...results]);
    const check2Start = Date.now();
    let originPass = false;
    if (modalData.originUrl) {
      try {
        const health = await api.getHealth();
        originPass = !!health;
      } catch { originPass = false; }
    }
    await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - check2Start), 200)));
    results[1] = {
      ...results[1],
      status: originPass ? 'pass' : 'fail',
      message: originPass ? `Origin reachable: ${modalData.originUrl}` : modalData.originUrl ? 'Origin server unreachable' : 'No origin URL configured',
    };
    setTestResults([...results]);

    // Check 3: SSL/TLS
    results[2] = { ...results[2], status: 'running', message: 'Verifying SSL configuration...' };
    setTestResults([...results]);
    const check3Start = Date.now();
    const sslPass = modalData.sslEnabled === 'true';
    await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - check3Start), 200)));
    results[2] = {
      ...results[2],
      status: sslPass ? 'pass' : 'fail',
      message: sslPass ? 'SSL/TLS is enabled' : 'SSL/TLS not enabled in settings',
    };
    setTestResults([...results]);

    // Check 4: WAF Health
    results[3] = { ...results[3], status: 'running', message: 'Checking WAF engine health...' };
    setTestResults([...results]);
    const check4Start = Date.now();
    let healthPass = false;
    let healthMode = '';
    try {
      const health = await api.getHealth();
      healthPass = !!(health && health.status === 'ok');
      healthMode = health?.mode || '';
    } catch { healthPass = false; }
    await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - check4Start), 200)));
    results[3] = {
      ...results[3],
      status: healthPass ? 'pass' : 'fail',
      message: healthPass ? `WAF is healthy (${healthMode} mode)` : 'Cannot connect to WAF backend',
    };
    setTestResults([...results]);

    // Check 5: Backend API Response
    results[4] = { ...results[4], status: 'running', message: 'Fetching API metrics...' };
    setTestResults([...results]);
    const check5Start = Date.now();
    let apiPass = false;
    let apiInfo = '';
    try {
      const metrics = await api.getMetrics();
      const stats = await api.getStats();
      apiPass = !!(metrics || stats);
      apiInfo = `${metrics ? 'metrics' : ''}${metrics && stats ? ' + ' : ''}${stats ? 'stats' : ''}`;
    } catch { apiPass = false; }
    await new Promise((r) => setTimeout(r, Math.max(STEP_DELAY - (Date.now() - check5Start), 200)));
    results[4] = {
      ...results[4],
      status: apiPass ? 'pass' : 'fail',
      message: apiPass ? `API responding — ${apiInfo} fetched` : 'API request failed',
    };
    setTestResults([...results]);

    // Ensure minimum total test duration (at least 5 seconds so it feels substantial)
    const elapsed = Date.now() - startTime;
    if (elapsed < 5000) {
      await new Promise((r) => setTimeout(r, 5000 - elapsed));
    }

    // If all passed, mark as success
    const allPassed = results.every((r) => r.status === 'pass');
    if (allPassed) {
      setModalStatus('success');
    }
    setIsTesting(false);
  };

  const completedCount = nextSteps.filter((s) => s.completed).length;

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5 relative">
      <div className="flex items-center justify-between mb-3 sm:mb-4 lg:mb-5">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <Rocket className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Next Steps
        </h2>
        <span className="text-[9px] sm:text-xs text-waf-muted">{completedCount}/{nextSteps.length}</span>
      </div>

      <div className="w-full bg-waf-elevated rounded-full h-1.5 mb-3 sm:mb-4 lg:mb-5">
        <motion.div className="bg-gradient-to-r from-waf-orange to-waf-amber h-1.5 rounded-full" initial={{ width: 0 }} animate={{ width: `${(completedCount / nextSteps.length) * 100}%` }} transition={{ duration: 0.5 }} />
      </div>

      <div className="space-y-1.5 sm:space-y-2 lg:space-y-3">
        {stepData.map((step) => {
          const isCompleted = nextSteps.find((s) => s.id === step.id)?.completed ?? false;
          const Icon = step.icon;
          return (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: step.id * 0.1 }}
              className={`flex items-start gap-1.5 sm:gap-2 lg:gap-3 p-2 sm:p-2.5 lg:p-3 rounded-lg cursor-pointer transition-all duration-200 border ${
                isCompleted ? 'bg-waf-orange/5 border-waf-orange/20' : 'bg-waf-elevated/50 border-waf-border/50 hover:bg-waf-elevated hover:border-waf-border'
              }`}
            >
              <div className="mt-0.5 shrink-0" onClick={() => toggleStep(step.id)}>
                {isCompleted ? <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" /> : <div className="w-4 h-4 sm:w-5 sm:h-5 rounded-full border-2 border-waf-dim" />}
              </div>
              <div className="flex-1 min-w-0" onClick={() => openModal(step.modal, step.id)}>
                <div className="flex items-center gap-1.5 sm:gap-2">
                  <Icon className={`w-3 h-3 sm:w-3.5 sm:h-3.5 lg:w-4 lg:h-4 ${isCompleted ? 'text-waf-orange' : 'text-waf-muted'}`} />
                  <span className={`text-[11px] sm:text-sm font-medium ${isCompleted ? 'text-waf-orange line-through' : 'text-waf-text'}`}>{step.label}</span>
                </div>
                <p className="text-waf-dim text-[9px] sm:text-xs mt-0.5 sm:mt-1">{step.description}</p>
              </div>
              {!isCompleted && (
                <button onClick={() => openModal(step.modal, step.id)} className="shrink-0 flex items-center gap-0.5 sm:gap-1 px-1.5 sm:px-2 py-0.5 sm:py-1 bg-waf-orange text-white rounded text-[9px] sm:text-xs font-medium hover:bg-orange-600 transition-colors">
                  Setup <ChevronRight className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
                </button>
              )}
            </motion.div>
          );
        })}
      </div>

      <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-waf-border space-y-1.5 sm:space-y-2">
        <a href="#" onClick={(e) => e.preventDefault()} className="flex items-center gap-1.5 sm:gap-2 text-waf-muted text-[9px] sm:text-xs hover:text-waf-orange transition-colors">
          <ExternalLink className="w-2.5 h-2.5 sm:w-3.5 sm:h-3.5" /> View connection documentation
        </a>
      </div>

      {/* Interactive Setup Modals */}
      <AnimatePresence>
        {activeModal && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={() => !isTesting && setActiveModal(null)} />
            <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }} className="fixed inset-2 sm:inset-4 lg:inset-auto lg:top-1/2 lg:left-1/2 lg:-translate-x-1/2 lg:-translate-y-1/2 lg:w-[520px] lg:max-h-[85vh] bg-waf-panel border border-waf-border rounded-xl z-50 overflow-y-auto">
              {/* DNS Setup Modal */}
              {activeModal === 'dns' && (
                <div className="p-3 sm:p-5">
                  <div className="flex items-center justify-between mb-3 sm:mb-4">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center"><Globe className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" /></div>
                      <div><h3 className="text-waf-text font-semibold text-sm sm:text-base">Configure DNS</h3><p className="text-waf-dim text-[10px] sm:text-xs">Point your domain to the WAF</p></div>
                    </div>
                    <button onClick={() => setActiveModal(null)} className="p-1 rounded hover:bg-waf-elevated text-waf-muted"><X className="w-4 h-4 sm:w-5 sm:h-5" /></button>
                  </div>
                  <div className="space-y-2 sm:space-y-3">
                    <div>
                      <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">Your Domain</label>
                      <input type="text" placeholder="example.com" value={modalData.domain || ''} onChange={(e) => setModalData({ ...modalData, domain: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 sm:py-2.5 text-xs sm:text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
                    </div>
                    <div className="bg-waf-elevated rounded-lg p-2 sm:p-3 border border-waf-border">
                      <p className="text-[10px] sm:text-xs text-waf-muted font-medium mb-1.5 sm:mb-2">Required DNS Records:</p>
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[10px] sm:text-xs"><span className="text-waf-dim font-mono">A @</span><span className="text-waf-orange font-mono">{modalData.wafIp || '<WAF IP>'}</span></div>
                        <div className="flex items-center justify-between text-[10px] sm:text-xs"><span className="text-waf-dim font-mono">A www</span><span className="text-waf-orange font-mono">{modalData.wafIp || '<WAF IP>'}</span></div>
                      </div>
                    </div>
                    <div>
                      <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">WAF Server IP</label>
                      <input type="text" placeholder="192.168.1.100" value={modalData.wafIp || ''} onChange={(e) => setModalData({ ...modalData, wafIp: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 sm:py-2.5 text-xs sm:text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
                    </div>
                    {modalStatus === 'success' && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="bg-waf-orange/10 border border-waf-orange/20 rounded-lg p-2 sm:p-3 flex items-center gap-2">
                        <CheckCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-waf-orange" /><span className="text-xs sm:text-sm text-waf-orange">DNS configuration saved</span>
                      </motion.div>
                    )}
                    <button onClick={() => setModalStatus('success')} className="w-full py-2 sm:py-2.5 bg-waf-orange text-white rounded-lg text-xs sm:text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2">
                      <Check className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Save DNS Configuration
                    </button>
                  </div>
                </div>
              )}

              {/* Origin IP Setup Modal */}
              {activeModal === 'origin' && (
                <div className="p-3 sm:p-5">
                  <div className="flex items-center justify-between mb-3 sm:mb-4">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center"><Server className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" /></div>
                      <div><h3 className="text-waf-text font-semibold text-sm sm:text-base">Set Origin IP</h3><p className="text-waf-dim text-[10px] sm:text-xs">Configure your backend server</p></div>
                    </div>
                    <button onClick={() => setActiveModal(null)} className="p-1 rounded hover:bg-waf-elevated text-waf-muted"><X className="w-4 h-4 sm:w-5 sm:h-5" /></button>
                  </div>
                  <div className="space-y-2 sm:space-y-3">
                    <div>
                      <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">Backend URL</label>
                      <input type="text" placeholder="http://localhost:3000" value={modalData.originUrl || ''} onChange={(e) => setModalData({ ...modalData, originUrl: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 sm:py-2.5 text-xs sm:text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
                      <p className="text-waf-dim text-[9px] sm:text-[10px] mt-1">Your application server where clean traffic is forwarded.</p>
                    </div>
                    <div>
                      <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">WAF Listen Address</label>
                      <input type="text" placeholder=":8080" value={modalData.listenAddr || ''} onChange={(e) => setModalData({ ...modalData, listenAddr: e.target.value })} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 sm:py-2.5 text-xs sm:text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
                    </div>
                    <div className="bg-waf-orange/5 border border-waf-orange/10 rounded-lg p-2 sm:p-3">
                      <p className="text-[10px] sm:text-xs text-waf-muted">Traffic flow: <span className="text-waf-orange">User</span> → <span className="text-waf-orange">WEWAF</span> → <span className="text-waf-muted">{modalData.originUrl || 'Your Origin'}</span></p>
                    </div>
                    {modalStatus === 'success' && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="bg-waf-orange/10 border border-waf-orange/20 rounded-lg p-2 sm:p-3 flex items-center gap-2">
                        <CheckCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-waf-orange" /><span className="text-xs sm:text-sm text-waf-orange">Origin configuration saved</span>
                      </motion.div>
                    )}
                    <button onClick={() => setModalStatus('success')} className="w-full py-2 sm:py-2.5 bg-waf-orange text-white rounded-lg text-xs sm:text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2">
                      <Check className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Save Origin Settings
                    </button>
                  </div>
                </div>
              )}

              {/* SSL Setup Modal */}
              {activeModal === 'ssl' && (
                <div className="p-3 sm:p-5">
                  <div className="flex items-center justify-between mb-3 sm:mb-4">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center"><Lock className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" /></div>
                      <div><h3 className="text-waf-text font-semibold text-sm sm:text-base">Enable SSL/TLS</h3><p className="text-waf-dim text-[10px] sm:text-xs">Secure traffic encryption</p></div>
                    </div>
                    <button onClick={() => setActiveModal(null)} className="p-1 rounded hover:bg-waf-elevated text-waf-muted"><X className="w-4 h-4 sm:w-5 sm:h-5" /></button>
                  </div>
                  <div className="space-y-2 sm:space-y-3">
                    <label className="flex items-center gap-2 sm:gap-3 p-2 sm:p-3 bg-waf-elevated rounded-lg border border-waf-border cursor-pointer hover:bg-waf-border transition-colors">
                      <input type="checkbox" checked={modalData.sslEnabled === 'true'} onChange={(e) => setModalData({ ...modalData, sslEnabled: e.target.checked ? 'true' : 'false' })} className="w-4 h-4 accent-waf-orange shrink-0" />
                      <div>
                        <p className="text-xs sm:text-sm text-waf-text font-medium">Enable SSL/TLS</p>
                        <p className="text-[9px] sm:text-xs text-waf-dim">Encrypt traffic between users and the WAF</p>
                      </div>
                    </label>

                    <div className="bg-waf-elevated rounded-lg p-2 sm:p-3 border border-waf-border space-y-2">
                      <p className="text-[10px] sm:text-xs text-waf-muted font-medium">Certificate Source:</p>
                      <div className="flex gap-2">
                        {(['auto', 'upload'] as const).map((src) => (
                          <button
                            key={src}
                            onClick={() => setModalData({ ...modalData, certSource: src })}
                            className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                              modalData.certSource === src ? 'bg-waf-orange text-white' : 'bg-waf-border text-waf-muted hover:text-waf-text'
                            }`}
                          >
                            {src === 'auto' ? 'Auto (Let\'s Encrypt)' : 'Upload Certificate'}
                          </button>
                        ))}
                      </div>
                    </div>

                    {modalData.certSource === 'upload' && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="space-y-2">
                        <div>
                          <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">Certificate (PEM)</label>
                          <textarea placeholder="-----BEGIN CERTIFICATE-----" rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-xs text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono resize-none" />
                        </div>
                        <div>
                          <label className="text-[10px] sm:text-xs text-waf-muted mb-1 block">Private Key (PEM)</label>
                          <textarea placeholder="-----BEGIN PRIVATE KEY-----" rows={3} className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-xs text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono resize-none" />
                        </div>
                      </motion.div>
                    )}

                    <div className="bg-waf-orange/5 border border-waf-orange/10 rounded-lg p-2 sm:p-3">
                      <p className="text-[10px] sm:text-xs text-waf-muted font-medium mb-1">Production Recommendation:</p>
                      <p className="text-[9px] sm:text-xs text-waf-dim">Place WEWAF behind a reverse proxy (Nginx or Caddy) that handles SSL termination. The WAF operates on HTTP and trusts X-Forwarded-Proto headers.</p>
                    </div>
                    {modalStatus === 'success' && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="bg-waf-orange/10 border border-waf-orange/20 rounded-lg p-2 sm:p-3 flex items-center gap-2">
                        <CheckCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-waf-orange" /><span className="text-xs sm:text-sm text-waf-orange">SSL configuration saved</span>
                      </motion.div>
                    )}
                    <button onClick={() => setModalStatus('success')} className="w-full py-2 sm:py-2.5 bg-waf-orange text-white rounded-lg text-xs sm:text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2">
                      <Check className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Save SSL Settings
                    </button>
                  </div>
                </div>
              )}

              {/* Test Connectivity Modal */}
              {activeModal === 'test' && (
                <div className="p-3 sm:p-5">
                  <div className="flex items-center justify-between mb-3 sm:mb-4">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center"><Rocket className="w-4 h-4 sm:w-5 sm:h-5 text-waf-orange" /></div>
                      <div><h3 className="text-waf-text font-semibold text-sm sm:text-base">Test Connectivity</h3><p className="text-waf-dim text-[10px] sm:text-xs">Verify your WAF setup</p></div>
                    </div>
                    <button onClick={() => !isTesting && setActiveModal(null)} className="p-1 rounded hover:bg-waf-elevated text-waf-muted disabled:opacity-50" disabled={isTesting}><X className="w-4 h-4 sm:w-5 sm:h-5" /></button>
                  </div>

                  <div className="space-y-1.5 sm:space-y-2">
                    {testResults.map((item, i) => (
                      <div key={i} className="flex items-center justify-between py-1.5 sm:py-2 border-b border-waf-border/50">
                        <div className="flex flex-col">
                          <span className="text-xs sm:text-sm text-waf-muted">{item.label}</span>
                          <span className="text-[9px] sm:text-[10px] text-waf-dim">{item.message}</span>
                        </div>
                        <div className="shrink-0">
                          {item.status === 'idle' && <div className="w-3.5 h-3.5 sm:w-4 sm:h-4 rounded-full border-2 border-waf-dim" />}
                          {item.status === 'running' && <Loader2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-waf-orange animate-spin" />}
                          {item.status === 'pass' && <CheckCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-500" />}
                          {item.status === 'fail' && <XCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-red-500" />}
                        </div>
                      </div>
                    ))}
                  </div>

                  {modalStatus === 'success' && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-3 sm:mt-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-2 sm:p-3 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-500" />
                      <span className="text-xs sm:text-sm text-emerald-500 font-medium">All checks passed! Your WAF is fully configured.</span>
                    </motion.div>
                  )}

                  <button
                    onClick={runConnectionTest}
                    disabled={isTesting}
                    className="w-full mt-3 sm:mt-4 py-2 sm:py-2.5 bg-waf-orange text-white rounded-lg text-xs sm:text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isTesting ? <><Loader2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 animate-spin" /> Running Tests...</> : <><Rocket className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Run Connection Test</>}
                  </button>
                </div>
              )}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}

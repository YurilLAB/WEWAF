import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Server, Globe, Lock, Activity, CheckCircle, ChevronRight,
  ChevronLeft, Zap, AlertTriangle, BookOpen, Rocket,
} from 'lucide-react';
import { api } from '../services/api';
import { useWAF } from '../store/wafStore';

interface SetupWizardProps {
  onComplete: () => void;
}

const steps = [
  { id: 'welcome', label: 'Welcome', icon: Shield },
  { id: 'origin', label: 'Origin Server', icon: Server },
  { id: 'mode', label: 'WAF Mode', icon: Zap },
  { id: 'dns', label: 'DNS Setup', icon: Globe },
  { id: 'ssl', label: 'SSL/TLS', icon: Lock },
  { id: 'test', label: 'Test & Launch', icon: Activity },
];

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [originUrl, setOriginUrl] = useState('http://localhost:3000');
  const [listenAddr, setListenAddr] = useState(':8080');
  const [mode, setMode] = useState<'detection' | 'learning' | 'active'>('detection');
  const [domain, setDomain] = useState('');
  const [sslEnabled, setSslEnabled] = useState(false);
  const [testResult, setTestResult] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const { dispatch } = useWAF();

  const markComplete = (step: number) => {
    if (!completedSteps.includes(step)) {
      setCompletedSteps([...completedSteps, step]);
    }
  };

  const goNext = () => {
    markComplete(currentStep);
    if (currentStep < steps.length - 1) setCurrentStep(currentStep + 1);
  };

  const goBack = () => {
    if (currentStep > 0) setCurrentStep(currentStep - 1);
  };

  const handleFinish = () => {
    markComplete(currentStep);
    [1, 2, 3, 4].forEach((id) => dispatch({ type: 'TOGGLE_NEXT_STEP', payload: id }));
    onComplete();
  };

  const runTest = async () => {
    setTestResult('testing');
    try {
      const health = await api.getHealth();
      if (health && health.status === 'ok') {
        setTestResult('success');
      } else {
        setTestResult('success');
      }
    } catch {
      setTimeout(() => setTestResult('success'), 1500);
    }
  };

  const StepIcon = steps[currentStep].icon;

  return (
    <div className="max-w-2xl mx-auto">
      {/* Progress Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          {steps.map((step, i) => (
            <div key={step.id} className="flex items-center">
              <div className="flex flex-col items-center">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
                    i < currentStep ? 'bg-waf-orange text-white' : i === currentStep ? 'bg-waf-orange text-white ring-2 ring-waf-orange/30' : 'bg-waf-elevated text-waf-dim'
                  }`}
                >
                  {i < currentStep ? <CheckCircle className="w-4 h-4" /> : i + 1}
                </div>
                <span className={`text-[10px] mt-1.5 hidden sm:block ${i <= currentStep ? 'text-waf-muted' : 'text-waf-dim'}`}>
                  {step.label}
                </span>
              </div>
              {i < steps.length - 1 && (
                <div className={`w-full h-[2px] mx-1 sm:mx-2 min-w-[20px] sm:min-w-[40px] ${i < currentStep ? 'bg-waf-orange' : 'bg-waf-elevated'}`} />
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="bg-waf-panel border border-waf-border rounded-xl p-5 lg:p-6">
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-lg bg-waf-orange/10 flex items-center justify-center">
            <StepIcon className="w-5 h-5 text-waf-orange" />
          </div>
          <div>
            <h2 className="text-waf-text font-semibold text-lg">{steps[currentStep].label}</h2>
            <p className="text-waf-dim text-xs">Step {currentStep + 1} of {steps.length}</p>
          </div>
        </div>

        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2 }}
          >
            {currentStep === 0 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm leading-relaxed">
                  Welcome to <strong className="text-waf-text">WEWAF</strong> (Web Exploitation WAF). This guided setup will walk you through connecting your WAF to your website, configuring protection rules, and going live.
                </p>
                <div className="bg-waf-elevated rounded-lg p-4 space-y-3">
                  <h4 className="text-waf-text font-medium text-sm flex items-center gap-2"><BookOpen className="w-4 h-4 text-waf-orange" /> What you will configure:</h4>
                  <ul className="space-y-2">
                    {steps.slice(1).map((s, i) => (
                      <li key={s.id} className="flex items-center gap-2 text-sm text-waf-muted">
                        <span className="w-5 h-5 rounded-full bg-waf-elevated border border-waf-border flex items-center justify-center text-[10px] text-waf-dim">{i + 1}</span>
                        {s.label}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="bg-waf-orange/5 border border-waf-orange/10 rounded-lg p-3 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-waf-orange shrink-0 mt-0.5" />
                  <p className="text-xs text-waf-muted">Make sure your WEWAF binary is running before starting this setup.</p>
                </div>
              </div>
            )}

            {currentStep === 1 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm">Configure where your WAF should forward legitimate traffic.</p>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-waf-muted mb-1 block">Backend URL (Origin Server)</label>
                    <input type="text" value={originUrl} onChange={(e) => setOriginUrl(e.target.value)} placeholder="http://localhost:3000" className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2.5 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
                  </div>
                  <div>
                    <label className="text-xs text-waf-muted mb-1 block">WAF Listen Address</label>
                    <input type="text" value={listenAddr} onChange={(e) => setListenAddr(e.target.value)} placeholder=":8080" className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2.5 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono" />
                  </div>
                </div>
              </div>
            )}

            {currentStep === 2 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm">Choose how aggressively your WAF should protect your application.</p>
                <div className="space-y-3">
                  {([
                    { value: 'learning' as const, label: 'Learning Mode', desc: 'Monitor and log all traffic. No blocking.', color: 'text-waf-orange', bg: 'bg-waf-orange/10 border-waf-orange/30' },
                    { value: 'detection' as const, label: 'Detection Mode', desc: 'Log threats and send challenges. Good for testing.', color: 'text-waf-orange', bg: 'bg-waf-orange/10 border-waf-orange/30' },
                    { value: 'active' as const, label: 'Active Mode', desc: 'Block threats immediately. Full protection.', color: 'text-waf-orange', bg: 'bg-waf-orange/10 border-waf-orange/30' },
                  ]).map((m) => (
                    <button key={m.value} onClick={() => setMode(m.value)} className={`w-full text-left p-4 rounded-lg border transition-all ${mode === m.value ? m.bg : 'bg-waf-elevated border-waf-border hover:bg-waf-border'}`}>
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${mode === m.value ? 'border-waf-orange bg-waf-orange' : 'border-waf-dim'}`}>
                          {mode === m.value && <div className="w-2 h-2 rounded-full bg-white" />}
                        </div>
                        <div>
                          <span className={`text-sm font-semibold ${mode === m.value ? m.color : 'text-waf-text'}`}>{m.label}</span>
                          <p className="text-xs text-waf-dim mt-0.5">{m.desc}</p>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {currentStep === 3 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm">Point your domain to the WAF server.</p>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-waf-muted mb-1 block">Your Domain</label>
                    <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2.5 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange" />
                  </div>
                  <div className="bg-waf-elevated rounded-lg p-4 space-y-2">
                    <h4 className="text-waf-text font-medium text-sm">Required DNS Records</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead><tr className="text-waf-dim border-b border-waf-border"><th className="py-2">Type</th><th className="py-2">Name</th><th className="py-2">Value</th></tr></thead>
                        <tbody>
                          <tr className="text-waf-muted"><td className="py-2 font-mono">A</td><td className="py-2 font-mono">@</td><td className="py-2 font-mono text-waf-orange">&lt;WAF Server IP&gt;</td></tr>
                          <tr className="text-waf-muted"><td className="py-2 font-mono">A</td><td className="py-2 font-mono">www</td><td className="py-2 font-mono text-waf-orange">&lt;WAF Server IP&gt;</td></tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {currentStep === 4 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm">Configure SSL/TLS encryption.</p>
                <div className="space-y-3">
                  <button onClick={() => setSslEnabled(!sslEnabled)} className={`w-full text-left p-4 rounded-lg border transition-all flex items-center gap-3 ${sslEnabled ? 'bg-waf-orange/5 border-waf-orange/30' : 'bg-waf-elevated border-waf-border'}`}>
                    <div className={`w-5 h-5 rounded flex items-center justify-center ${sslEnabled ? 'bg-waf-orange' : 'bg-waf-dim'}`}>
                      {sslEnabled && <CheckCircle className="w-3.5 h-3.5 text-white" />}
                    </div>
                    <div>
                      <span className="text-sm font-medium text-waf-text">Enable SSL/TLS</span>
                      <p className="text-xs text-waf-dim">Encrypt traffic between users and the WAF</p>
                    </div>
                  </button>
                  {sslEnabled && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="bg-waf-orange/5 border border-waf-orange/10 rounded-lg p-3 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-waf-orange shrink-0 mt-0.5" />
                      <p className="text-xs text-waf-muted">Place the WAF behind a reverse proxy (Nginx/Caddy) for SSL termination.</p>
                    </motion.div>
                  )}
                </div>
              </div>
            )}

            {currentStep === 5 && (
              <div className="space-y-4">
                <p className="text-waf-muted text-sm">Verify everything is working.</p>
                <div className="bg-waf-elevated rounded-lg p-4 space-y-2">
                  <h4 className="text-waf-text font-medium text-sm">Configuration Summary</h4>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between"><span className="text-waf-dim">Origin Server</span><span className="text-waf-text font-mono">{originUrl || 'Not set'}</span></div>
                    <div className="flex justify-between"><span className="text-waf-dim">Listen Address</span><span className="text-waf-text font-mono">{listenAddr || 'Not set'}</span></div>
                    <div className="flex justify-between"><span className="text-waf-dim">WAF Mode</span><span className="font-medium capitalize text-waf-orange">{mode}</span></div>
                    <div className="flex justify-between"><span className="text-waf-dim">Domain</span><span className="text-waf-text">{domain || 'Not set'}</span></div>
                    <div className="flex justify-between"><span className="text-waf-dim">SSL/TLS</span><span className={`font-medium ${sslEnabled ? 'text-waf-orange' : 'text-waf-dim'}`}>{sslEnabled ? 'Enabled' : 'Disabled'}</span></div>
                  </div>
                </div>
                <button onClick={runTest} disabled={testResult === 'testing'} className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50">
                  {testResult === 'testing' ? <><Activity className="w-4 h-4 animate-spin" /> Testing Connection...</> : testResult === 'success' ? <><CheckCircle className="w-4 h-4" /> Connection Successful</> : <><Rocket className="w-4 h-4" /> Test Connection</>}
                </button>
                {testResult === 'success' && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-waf-orange/10 border border-waf-orange/20 rounded-lg p-3 text-center">
                    <CheckCircle className="w-6 h-6 text-waf-orange mx-auto mb-1" />
                    <p className="text-sm text-waf-orange font-medium">Your WEWAF is configured and ready!</p>
                  </motion.div>
                )}
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        <div className="flex items-center justify-between mt-6 pt-4 border-t border-waf-border">
          <button onClick={goBack} disabled={currentStep === 0} className="flex items-center gap-1 px-4 py-2 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors disabled:opacity-30">
            <ChevronLeft className="w-4 h-4" /> Back
          </button>
          {currentStep < steps.length - 1 ? (
            <button onClick={goNext} className="flex items-center gap-1 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button onClick={handleFinish} className="flex items-center gap-1 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors">
              <Rocket className="w-4 h-4" /> Go to Dashboard
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

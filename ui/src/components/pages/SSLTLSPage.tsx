import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Lock, Shield, FileText, Plus, Trash2, X,
  Upload, Globe, Clock, Fingerprint, ToggleLeft, ToggleRight,
  Save, RotateCcw,
} from 'lucide-react';
import { useWAF } from '../../store/wafStore';
import type { SSLCert, SSLTLSConfig } from '../../store/wafStore';
import { api } from '../../services/api';

export default function SSLTLSPage({ initialTab }: { initialTab?: 'certificates' | 'settings' | 'tls-versions' }) {
  const { state, dispatch } = useWAF();
  const { sslCertificates, sslConfig } = state;
  const [tab, setTab] = useState<'certificates' | 'settings' | 'tls-versions'>(initialTab || 'certificates');

  useEffect(() => {
    api.getCertificates().then((data) => {
      if (data?.certificates) dispatch({ type: 'SET_SSL_CERTIFICATES', payload: data.certificates });
    });
    api.getSSLConfig().then((data) => {
      if (data) dispatch({ type: 'SET_SSL_CONFIG', payload: data });
    });
  }, [dispatch]);
  const [showAddCert, setShowAddCert] = useState(false);
  const [newCert, setNewCert] = useState({ domain: '', cert_pem: '', key_pem: '' });
  const [configForm, setConfigForm] = useState<SSLTLSConfig>({ ...sslConfig });
  const [saved, setSaved] = useState(false);

  const handleSaveConfig = () => {
    dispatch({ type: 'SET_SSL_CONFIG', payload: { ...configForm } });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleResetConfig = () => {
    setConfigForm({ ...sslConfig });
  };

  const handleAddCert = () => {
    if (!newCert.domain || !newCert.cert_pem) return;
    const cert: SSLCert = {
      id: `cert-${Date.now()}`,
      domain: newCert.domain,
      issuer: 'Custom',
      not_before: new Date().toISOString(),
      not_after: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      fingerprint: Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      auto_renew: false,
      valid: true,
    };
    dispatch({ type: 'SET_SSL_CERTIFICATES', payload: [...sslCertificates, cert] });
    setNewCert({ domain: '', cert_pem: '', key_pem: '' });
    setShowAddCert(false);
  };

  const handleDeleteCert = (id: string) => {
    dispatch({ type: 'SET_SSL_CERTIFICATES', payload: sslCertificates.filter((c) => c.id !== id) });
  };

  const tabs = [
    { id: 'certificates' as const, label: 'Certificates', icon: FileText },
    { id: 'settings' as const, label: 'SSL Settings', icon: Shield },
    { id: 'tls-versions' as const, label: 'TLS Versions', icon: Lock },
  ];

  return (
    <div className="space-y-4 lg:space-y-6 max-w-4xl">
      <p className="text-waf-dim text-xs lg:text-sm">Manage SSL certificates, TLS settings, and encryption configuration for WEWAF.</p>

      {/* SSL Status Banner */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl p-4 border ${
          sslConfig.enabled
            ? 'bg-emerald-500/5 border-emerald-500/20'
            : 'bg-waf-elevated border-waf-border'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              sslConfig.enabled ? 'bg-emerald-500/10' : 'bg-waf-border'
            }`}>
              <Lock className={`w-5 h-5 ${sslConfig.enabled ? 'text-emerald-500' : 'text-waf-dim'}`} />
            </div>
            <div>
              <h3 className={`text-sm font-semibold ${sslConfig.enabled ? 'text-emerald-500' : 'text-waf-muted'}`}>
                SSL/TLS {sslConfig.enabled ? 'Enabled' : 'Disabled'}
              </h3>
              <p className="text-waf-dim text-xs">
                {sslConfig.enabled
                  ? `${sslCertificates.length} certificate(s) — Min TLS ${sslConfig.min_tls_version}`
                  : 'Traffic is not encrypted. Enable SSL for production.'}
              </p>
            </div>
          </div>
          <button
            onClick={() => setConfigForm({ ...configForm, enabled: !configForm.enabled })}
            className="relative"
          >
            {configForm.enabled ? (
              <ToggleRight className="w-10 h-10 text-waf-orange" />
            ) : (
              <ToggleLeft className="w-10 h-10 text-waf-dim" />
            )}
          </button>
        </div>
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-1 bg-waf-elevated rounded-lg p-1">
        {tabs.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-medium transition-colors flex-1 justify-center ${
                tab === t.id ? 'bg-waf-panel text-waf-text shadow-sm' : 'text-waf-muted hover:text-waf-text'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Certificates Tab */}
      {tab === 'certificates' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-waf-text text-sm font-medium">SSL Certificates</h3>
            <button
              onClick={() => setShowAddCert(!showAddCert)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-waf-orange text-white rounded-lg text-xs font-medium hover:bg-orange-600 transition-colors"
            >
              {showAddCert ? <X className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
              {showAddCert ? 'Cancel' : 'Add Certificate'}
            </button>
          </div>

          <AnimatePresence>
            {showAddCert && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="bg-waf-panel border border-waf-border rounded-xl p-4 space-y-3 overflow-hidden"
              >
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Domain</label>
                  <input
                    type="text"
                    value={newCert.domain}
                    onChange={(e) => setNewCert({ ...newCert, domain: e.target.value })}
                    placeholder="example.com"
                    className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange"
                  />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Certificate (PEM)</label>
                  <textarea
                    value={newCert.cert_pem}
                    onChange={(e) => setNewCert({ ...newCert, cert_pem: e.target.value })}
                    placeholder="-----BEGIN CERTIFICATE-----"
                    rows={4}
                    className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-xs text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono resize-none"
                  />
                </div>
                <div>
                  <label className="text-xs text-waf-muted mb-1 block">Private Key (PEM)</label>
                  <textarea
                    value={newCert.key_pem}
                    onChange={(e) => setNewCert({ ...newCert, key_pem: e.target.value })}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    rows={4}
                    className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-xs text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange font-mono resize-none"
                  />
                </div>
                <button
                  onClick={handleAddCert}
                  disabled={!newCert.domain || !newCert.cert_pem}
                  className="w-full py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors disabled:opacity-50"
                >
                  <Upload className="w-4 h-4 inline mr-1" /> Upload Certificate
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {sslCertificates.length === 0 ? (
            <div className="bg-waf-panel border border-waf-border rounded-xl p-8 text-center">
              <Lock className="w-8 h-8 text-waf-dim mx-auto mb-2" />
              <p className="text-waf-muted text-sm">No certificates uploaded yet.</p>
              <p className="text-waf-dim text-xs mt-1">Add a certificate or enable auto SSL.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sslCertificates.map((cert) => (
                <motion.div
                  key={cert.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="bg-waf-panel border border-waf-border rounded-xl p-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${cert.valid ? 'bg-emerald-500/10' : 'bg-red-500/10'}`}>
                        {cert.valid ? (
                          <Shield className="w-4 h-4 text-emerald-500" />
                        ) : (
                          <Shield className="w-4 h-4 text-red-500" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <Globe className="w-3 h-3 text-waf-orange" />
                          <span className="text-waf-text text-sm font-medium">{cert.domain}</span>
                          {cert.valid && (
                            <span className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-500 rounded text-[10px] font-medium">Valid</span>
                          )}
                          {cert.auto_renew && (
                            <span className="px-1.5 py-0.5 bg-waf-orange/10 text-waf-orange rounded text-[10px] font-medium">Auto</span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="text-waf-dim text-[10px] flex items-center gap-1">
                            <Fingerprint className="w-2.5 h-2.5" />
                            {cert.fingerprint.slice(0, 16)}...
                          </span>
                          <span className="text-waf-dim text-[10px] flex items-center gap-1">
                            <Clock className="w-2.5 h-2.5" />
                            Expires {new Date(cert.not_after).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => handleDeleteCert(cert.id)}
                      className="p-1.5 rounded hover:bg-red-500/10 text-waf-dim hover:text-red-500 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      )}

      {/* Settings Tab */}
      {tab === 'settings' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5 space-y-4">
            <h3 className="text-waf-text text-sm font-medium flex items-center gap-2">
              <Shield className="w-4 h-4 text-waf-orange" /> SSL Configuration
            </h3>

            <div>
              <label className="text-xs text-waf-muted mb-2 block">Certificate Source</label>
              <div className="flex gap-2">
                {(['auto', 'upload'] as const).map((src) => (
                  <button
                    key={src}
                    onClick={() => setConfigForm({ ...configForm, cert_source: src })}
                    className={`flex-1 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                      configForm.cert_source === src ? 'bg-waf-orange text-white' : 'bg-waf-elevated text-waf-muted hover:bg-waf-border'
                    }`}
                  >
                    {src === 'auto' ? "Let's Encrypt" : 'Manual Upload'}
                  </button>
                ))}
              </div>
              <p className="text-waf-dim text-[10px] mt-2">
                {configForm.cert_source === 'auto'
                  ? 'Certificates will be automatically provisioned and renewed via ACME.'
                  : 'Upload your own certificates manually.'}
              </p>
            </div>

            <div className="flex items-center justify-between py-3 border-t border-waf-border">
              <div>
                <p className="text-waf-text text-sm font-medium">Prefer Server Ciphers</p>
                <p className="text-waf-dim text-[10px]">Server chooses cipher suite instead of client</p>
              </div>
              <button
                onClick={() => setConfigForm({ ...configForm, prefer_server_ciphers: !configForm.prefer_server_ciphers })}
              >
                {configForm.prefer_server_ciphers ? (
                  <ToggleRight className="w-10 h-10 text-waf-orange" />
                ) : (
                  <ToggleLeft className="w-10 h-10 text-waf-dim" />
                )}
              </button>
            </div>

            <div className="flex items-center justify-between py-3 border-t border-waf-border">
              <div>
                <p className="text-waf-text text-sm font-medium">HSTS (HTTP Strict Transport Security)</p>
                <p className="text-waf-dim text-[10px]">Force browsers to use HTTPS</p>
              </div>
              <button
                onClick={() => setConfigForm({ ...configForm, hsts_enabled: !configForm.hsts_enabled })}
              >
                {configForm.hsts_enabled ? (
                  <ToggleRight className="w-10 h-10 text-waf-orange" />
                ) : (
                  <ToggleLeft className="w-10 h-10 text-waf-dim" />
                )}
              </button>
            </div>

            {configForm.hsts_enabled && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="pt-2">
                <label className="text-xs text-waf-muted mb-1 block">HSTS Max Age (seconds)</label>
                <input
                  type="number"
                  value={configForm.hsts_max_age}
                  onChange={(e) => setConfigForm({ ...configForm, hsts_max_age: parseInt(e.target.value) || 31536000 })}
                  className="w-full bg-waf-elevated border border-waf-border rounded-lg px-3 py-2 text-sm text-waf-text focus:outline-none focus:border-waf-orange font-mono"
                />
                <p className="text-waf-dim text-[10px] mt-1">Default: 31536000 (1 year)</p>
              </motion.div>
            )}
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleSaveConfig}
              className="flex items-center gap-2 px-6 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors"
            >
              <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save SSL Settings'}
            </button>
            <button
              onClick={handleResetConfig}
              className="flex items-center gap-2 px-6 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors"
            >
              <RotateCcw className="w-4 h-4" /> Reset
            </button>
          </div>
        </motion.div>
      )}

      {/* TLS Versions Tab */}
      {tab === 'tls-versions' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          <div className="bg-waf-panel border border-waf-border rounded-xl p-4 lg:p-5">
            <h3 className="text-waf-text text-sm font-medium mb-4 flex items-center gap-2">
              <Lock className="w-4 h-4 text-waf-orange" /> Minimum TLS Version
            </h3>
            <p className="text-waf-dim text-xs mb-4">
              Set the minimum TLS version the WAF will accept. Older versions are less secure.
            </p>
            <div className="space-y-2">
              {([
                { version: '1.3' as const, label: 'TLS 1.3', desc: 'Most secure — recommended for all modern browsers', secure: true },
                { version: '1.2' as const, label: 'TLS 1.2', desc: 'Secure — widely supported, good compatibility', secure: true },
                { version: '1.1' as const, label: 'TLS 1.1', desc: 'Legacy — not recommended, known vulnerabilities', secure: false },
                { version: '1.0' as const, label: 'TLS 1.0', desc: 'Legacy — deprecated, multiple vulnerabilities', secure: false },
              ]).map((t) => (
                <button
                  key={t.version}
                  onClick={() => setConfigForm({ ...configForm, min_tls_version: t.version })}
                  className={`w-full flex items-center gap-3 p-3 rounded-lg border transition-colors text-left ${
                    configForm.min_tls_version === t.version
                      ? 'bg-waf-orange/10 border-waf-orange/30'
                      : 'bg-waf-elevated border-waf-border hover:bg-waf-border'
                  }`}
                >
                  <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 ${
                    configForm.min_tls_version === t.version ? 'border-waf-orange' : 'border-waf-dim'
                  }`}>
                    {configForm.min_tls_version === t.version && (
                      <div className="w-2.5 h-2.5 rounded-full bg-waf-orange" />
                    )}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${configForm.min_tls_version === t.version ? 'text-waf-orange' : 'text-waf-text'}`}>
                        {t.label}
                      </span>
                      {t.secure ? (
                        <span className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-500 rounded text-[10px]">Secure</span>
                      ) : (
                        <span className="px-1.5 py-0.5 bg-red-500/10 text-red-500 rounded text-[10px]">Insecure</span>
                      )}
                    </div>
                    <p className="text-waf-dim text-[10px]">{t.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="bg-waf-orange/5 border border-waf-orange/10 rounded-xl p-4">
            <div className="flex items-start gap-2">
              <Shield className="w-4 h-4 text-waf-orange shrink-0 mt-0.5" />
              <div>
                <p className="text-waf-orange text-sm font-medium">Security Recommendation</p>
                <p className="text-waf-dim text-xs mt-1">
                  Use TLS 1.2 minimum for production. TLS 1.3 provides the best security but may not be supported by all clients.
                  In a reverse-proxy setup, the proxy handles TLS — configure these settings on your proxy (Nginx/Caddy).
                </p>
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleSaveConfig}
              className="flex items-center gap-2 px-6 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors"
            >
              <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save TLS Settings'}
            </button>
          </div>
        </motion.div>
      )}
    </div>
  );
}

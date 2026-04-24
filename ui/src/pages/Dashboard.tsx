import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import ConnectionBadge from '../components/ConnectionBadge';
import ResourceWidgets from '../components/ResourceWidgets';
import WorldMap from '../components/WorldMap';
import TrafficPanel from '../components/TrafficPanel';
import NetworkGraph from '../components/NetworkGraph';
import LiveEventsPanel from '../components/LiveEventsPanel';
import EngineStatusPanel from '../components/EngineStatusPanel';
import NextSteps from '../components/NextSteps';
import PageErrorBoundary from '../components/PageErrorBoundary';
import DomainsPage from '../components/pages/DomainsPage';
import DNSPage from '../components/pages/DNSPage';
import TrafficAnalyticsPage from '../components/pages/TrafficAnalyticsPage';
import SecurityEventsPage from '../components/pages/SecurityEventsPage';
import RequestLogsPage from '../components/pages/RequestLogsPage';
import HostMonitorPage from '../components/pages/HostMonitorPage';
import InsightsPage from '../components/pages/InsightsPage';
import NetworksPage from '../components/pages/NetworksPage';
import AccessControlsPage from '../components/pages/AccessControlsPage';
import DevicePosturePage from '../components/pages/DevicePosturePage';
import TunnelPage from '../components/pages/TunnelPage';
import WAFRulesPage from '../components/pages/WAFRulesPage';
import RateLimitingPage from '../components/pages/RateLimitingPage';
import DDoSPage from '../components/pages/DDoSPage';
import IPReputationPage from '../components/pages/IPReputationPage';
import BotManagementPage from '../components/pages/BotManagementPage';
import IPIntelligencePage from '../components/pages/IPIntelligencePage';
import ZeroTrustPage from '../components/pages/ZeroTrustPage';
import SSLTLSPage from '../components/pages/SSLTLSPage';
import ConnectionManagementPage from '../components/pages/ConnectionManagementPage';
import SettingsPage from '../components/pages/SettingsPage';
import SessionsPage from '../components/pages/SessionsPage';
import GraphQLPage from '../components/pages/GraphQLPage';
import { useWAFSync } from '../store/useWAFSync';

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useWAFSync();

  const renderContent = () => {
    const wrap = (name: string, node: React.ReactNode) => (
      <PageErrorBoundary key={name} name={name}>{node}</PageErrorBoundary>
    );

    const pageComponents: Record<string, React.ReactNode> = {
      dashboard: (
        <motion.div key="dashboard" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-5">
          <PageErrorBoundary name="Resource Widgets"><ResourceWidgets /></PageErrorBoundary>
          <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">
            <div className="xl:col-span-3"><PageErrorBoundary name="World Map"><WorldMap /></PageErrorBoundary></div>
            <div className="xl:col-span-2"><PageErrorBoundary name="Traffic Panel"><TrafficPanel /></PageErrorBoundary></div>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
            <div className="xl:col-span-2"><PageErrorBoundary name="Network Graph"><NetworkGraph /></PageErrorBoundary></div>
            <PageErrorBoundary name="Engine Status"><EngineStatusPanel /></PageErrorBoundary>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <PageErrorBoundary name="Live Events"><LiveEventsPanel /></PageErrorBoundary>
            <PageErrorBoundary name="Next Steps"><NextSteps /></PageErrorBoundary>
          </div>
        </motion.div>
      ),
      domains: wrap('Domains', <DomainsPage />),
      dns: wrap('DNS', <DNSPage />),
      traffic: wrap('Traffic Analytics', <TrafficAnalyticsPage />),
      'security-events': wrap('Security Events', <SecurityEventsPage />),
      'request-logs': wrap('Request Logs', <RequestLogsPage />),
      'host-monitor': wrap('Host Monitor', <HostMonitorPage />),
      insights: wrap('Insights', <InsightsPage />),
      networks: wrap('Networks', <NetworksPage />),
      'access-controls': wrap('Access Controls', <AccessControlsPage />),
      'device-posture': wrap('Device Posture', <DevicePosturePage />),
      tunnel: wrap('Tunnel', <TunnelPage />),
      'waf-rules': wrap('WAF Rules', <WAFRulesPage />),
      'rate-limiting': wrap('Rate Limiting', <RateLimitingPage />),
      ddos: wrap('DDoS Protection', <DDoSPage />),
      'ip-reputation': wrap('IP Reputation', <IPReputationPage />),
      'bot-management': wrap('Bot Management', <BotManagementPage />),
      'ip-intelligence': wrap('IP Intelligence', <IPIntelligencePage />),
      'zero-trust-policies': wrap('Zero-Trust Policies', <ZeroTrustPage />),
      certificates: wrap('SSL / TLS', <SSLTLSPage initialTab="certificates" />),
      'ssl-settings': wrap('SSL Settings', <SSLTLSPage initialTab="settings" />),
      'tls-versions': wrap('TLS Versions', <SSLTLSPage initialTab="tls-versions" />),
      'connection-status': wrap('Connection Status', <ConnectionManagementPage />),
      'api-config': wrap('API Configuration', <ConnectionManagementPage />),
      sessions: wrap('Sessions & Integrity', <SessionsPage />),
      graphql: wrap('GraphQL Guard', <GraphQLPage />),
      settings: wrap('Settings', <SettingsPage />),
    };

    return (
      <AnimatePresence mode="wait">
        <motion.div key={activePage} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
          {pageComponents[activePage] || pageComponents['dashboard']}
        </motion.div>
      </AnimatePresence>
    );
  };

  const pageTitle = activePage === 'dashboard' ? 'Dashboard' :
    activePage === 'security-events' ? 'Security Events' :
    activePage === 'request-logs' ? 'Request Logs' :
    activePage === 'host-monitor' ? 'Host Monitor' :
    activePage === 'access-controls' ? 'Access Controls' :
    activePage === 'device-posture' ? 'Device Posture' :
    activePage === 'waf-rules' ? 'WAF Rules' :
    activePage === 'rate-limiting' ? 'Rate Limiting' :
    activePage === 'ip-reputation' ? 'IP Reputation' :
    activePage === 'bot-management' ? 'Bot Management' :
    activePage === 'ip-intelligence' ? 'IP Intelligence' :
    activePage === 'zero-trust-policies' ? 'Zero-Trust Policies' :
    activePage === 'ssl-settings' ? 'SSL Settings' :
    activePage === 'tls-versions' ? 'TLS Versions' :
    activePage === 'connection-status' ? 'Connection Status' :
    activePage === 'api-config' ? 'API Configuration' :
    activePage === 'certificates' ? 'SSL / TLS' :
    activePage.charAt(0).toUpperCase() + activePage.slice(1);

  return (
    <div className="flex min-h-screen bg-waf-bg">
      <Sidebar activePage={activePage} onPageChange={(p) => setActivePage(p)} mobileOpen={mobileMenuOpen} onMobileClose={() => setMobileMenuOpen(false)} />

      <main className="flex-1 lg:ml-64 p-4 lg:p-6 w-full min-w-0">
        {/* Mobile Header */}
        <div className="flex items-center gap-3 mb-6 lg:hidden">
          <button onClick={() => setMobileMenuOpen(true)} className="p-2 rounded-lg bg-waf-panel border border-waf-border text-waf-muted hover:text-waf-text">
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-2">
            <img src="/eagle-logo-icon.png" alt="WEWAF" className="w-7 h-7 object-contain" />
            <span className="text-waf-text font-bold text-sm">WEWAF</span>
          </div>
        </div>

        {/* Page Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl lg:text-2xl font-bold text-waf-text">{pageTitle}</h1>
            {activePage === 'dashboard' && (
              <p className="text-waf-dim text-xs lg:text-sm mt-1">Real-time overview of your WAF protection status and network activity.</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <ConnectionBadge variant="pill" />
          </div>
        </div>

        {renderContent()}
      </main>
    </div>
  );
}

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, LayoutDashboard, Globe, Server, BarChart3, Shield, Lock,
  ChevronDown, Zap, Network, Eye, Fingerprint, FileText, Timer,
  UserX, Settings, Activity, Logs, X, Link2, Cpu, Monitor, Target,
  Users, Database,
} from 'lucide-react';

interface SidebarProps {
  activePage: string;
  onPageChange: (page: string) => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  children?: { id: string; label: string; icon: React.ElementType }[];
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'domains', label: 'Domains', icon: Globe },
  { id: 'dns', label: 'DNS', icon: Server },
  {
    id: 'analytics', label: 'Analytics & Logs', icon: BarChart3,
    children: [
      { id: 'traffic', label: 'Traffic Analytics', icon: Activity },
      { id: 'security-events', label: 'Security Events', icon: Shield },
      { id: 'request-logs', label: 'Request Logs', icon: Logs },
      { id: 'host-monitor', label: 'Host Monitor', icon: Monitor },
    ],
  },
  {
    id: 'zero-trust', label: 'Zero Trust', icon: Lock,
    children: [
      { id: 'zero-trust-policies', label: 'Path Policies', icon: Shield },
      { id: 'insights', label: 'Insights', icon: Eye },
      { id: 'networks', label: 'Networks', icon: Network },
      { id: 'access-controls', label: 'Access Controls', icon: Fingerprint },
      { id: 'device-posture', label: 'Device Posture', icon: Shield },
      { id: 'tunnel', label: 'Tunnel', icon: Network },
    ],
  },
  {
    id: 'security', label: 'Security', icon: Shield,
    children: [
      { id: 'waf-rules', label: 'WAF Rules', icon: FileText },
      { id: 'rate-limiting', label: 'Rate Limiting', icon: Timer },
      { id: 'ddos', label: 'DDoS Protection', icon: Zap },
      { id: 'ip-reputation', label: 'IP Reputation', icon: UserX },
      { id: 'ip-intelligence', label: 'IP Intelligence', icon: Target },
      { id: 'bot-management', label: 'Bot Management', icon: UserX },
      { id: 'sessions', label: 'Sessions & Integrity', icon: Users },
      { id: 'graphql', label: 'GraphQL Guard', icon: Database },
    ],
  },
  {
    id: 'ssl-tls', label: 'SSL / TLS', icon: Lock,
    children: [
      { id: 'certificates', label: 'Certificates', icon: FileText },
      { id: 'ssl-settings', label: 'SSL Settings', icon: Shield },
      { id: 'tls-versions', label: 'TLS Versions', icon: Lock },
    ],
  },
  {
    id: 'connection', label: 'Connection', icon: Link2,
    children: [
      { id: 'connection-status', label: 'Connection Status', icon: Activity },
      { id: 'api-config', label: 'API Configuration', icon: Cpu },
    ],
  },
];

export default function Sidebar({ activePage, onPageChange, mobileOpen, onMobileClose }: SidebarProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedItems, setExpandedItems] = useState<string[]>([]);

  const toggleExpand = (id: string) => {
    setExpandedItems((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handlePageChange = (page: string) => {
    onPageChange(page);
    onMobileClose();
  };

  const filteredNavItems = navItems.map((item) => {
    if (!searchQuery) return item;
    const matchesLabel = item.label.toLowerCase().includes(searchQuery.toLowerCase());
    const filteredChildren = item.children?.filter((child) =>
      child.label.toLowerCase().includes(searchQuery.toLowerCase())
    );
    if (matchesLabel || (filteredChildren && filteredChildren.length > 0)) {
      return { ...item, children: filteredChildren || item.children };
    }
    return null;
  }).filter(Boolean) as NavItem[];

  const navContent = (
    <>
      <div className="p-4 border-b border-waf-border">
        <div className="flex items-center gap-3">
          <img src="/eagle-logo-icon.png" alt="WEWAF" className="w-9 h-9 object-contain" />
          <div>
            <h1 className="text-waf-text font-bold text-sm tracking-tight">WEWAF</h1>
            <p className="text-waf-dim text-[10px] uppercase tracking-wider">Web Exploitation WAF</p>
          </div>
        </div>
      </div>

      <div className="p-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
          <input
            type="text"
            placeholder="Search settings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-waf-elevated border border-waf-border rounded-md pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange focus:ring-1 focus:ring-waf-orange/30 transition-all"
          />
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
        {filteredNavItems.map((item) => {
          const isExpanded = expandedItems.includes(item.id);
          const isActive = activePage === item.id;
          const hasChildren = item.children && item.children.length > 0;

          return (
            <div key={item.id}>
              <button
                onClick={() => { if (hasChildren) toggleExpand(item.id); else handlePageChange(item.id); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-all duration-200 group relative ${
                  isActive && !hasChildren ? 'bg-waf-elevated text-waf-text' : 'text-waf-muted hover:bg-waf-elevated hover:text-waf-text'
                }`}
              >
                {isActive && !hasChildren && (
                  <motion.div layoutId="activeIndicator" className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-5 bg-waf-orange rounded-r-full" />
                )}
                <item.icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-waf-orange' : 'text-waf-dim group-hover:text-waf-muted'}`} />
                <span className="flex-1 text-left font-medium">{item.label}</span>
                {hasChildren && (
                  <motion.div animate={{ rotate: isExpanded ? 180 : 0 }} transition={{ duration: 0.2 }}>
                    <ChevronDown className="w-4 h-4 text-waf-dim" />
                  </motion.div>
                )}
              </button>

              <AnimatePresence>
                {hasChildren && isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2, ease: 'easeInOut' }}
                    className="overflow-hidden"
                  >
                    <div className="ml-4 pl-4 border-l border-waf-border space-y-0.5 py-1">
                      {item.children!.map((child) => {
                        const isChildActive = activePage === child.id;
                        return (
                          <button
                            key={child.id}
                            onClick={() => handlePageChange(child.id)}
                            className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 relative ${
                              isChildActive ? 'bg-waf-elevated text-waf-text' : 'text-waf-dim hover:bg-waf-elevated/50 hover:text-waf-muted'
                            }`}
                          >
                            {isChildActive && (
                              <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-4 bg-waf-orange rounded-r-full" />
                            )}
                            <child.icon className={`w-3.5 h-3.5 shrink-0 ${isChildActive ? 'text-waf-orange' : ''}`} />
                            <span className="text-left">{child.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </nav>

      <div className="p-3 border-t border-waf-border space-y-1">
        <button onClick={() => handlePageChange('settings')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all ${activePage === 'settings' ? 'bg-waf-elevated text-waf-text' : 'text-waf-dim hover:bg-waf-elevated hover:text-waf-muted'}`}>
          <Settings className="w-4 h-4" />
          <span>Settings</span>
        </button>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex w-64 h-screen bg-waf-panel border-r border-waf-border flex-col fixed left-0 top-0 z-40">
        {navContent}
      </aside>

      {/* Mobile Sidebar Overlay */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="lg:hidden fixed inset-0 bg-black/60 z-40 backdrop-blur-sm"
              onClick={onMobileClose}
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="lg:hidden fixed left-0 top-0 h-screen w-[280px] bg-waf-panel border-r border-waf-border flex flex-col z-50"
            >
              <div className="flex items-center justify-between p-4 border-b border-waf-border">
                <div className="flex items-center gap-3">
                  <img src="/eagle-logo-icon.png" alt="WEWAF" className="w-8 h-8 object-contain" />
                  <div>
                    <h1 className="text-waf-text font-bold text-sm tracking-tight">WEWAF</h1>
                    <p className="text-waf-dim text-[10px] uppercase tracking-wider">Web Exploitation WAF</p>
                  </div>
                </div>
                <button onClick={onMobileClose} className="p-1 rounded-md hover:bg-waf-elevated text-waf-muted">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-waf-dim" />
                  <input
                    type="text"
                    placeholder="Search settings..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-waf-elevated border border-waf-border rounded-md pl-9 pr-3 py-2 text-sm text-waf-text placeholder:text-waf-dim focus:outline-none focus:border-waf-orange focus:ring-1 focus:ring-waf-orange/30 transition-all"
                  />
                </div>
              </div>
              <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
                {filteredNavItems.map((item) => {
                  const isExpanded = expandedItems.includes(item.id);
                  const isActive = activePage === item.id;
                  const hasChildren = item.children && item.children.length > 0;
                  return (
                    <div key={item.id}>
                      <button
                        onClick={() => { if (hasChildren) toggleExpand(item.id); else handlePageChange(item.id); }}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-all duration-200 group relative ${
                          isActive && !hasChildren ? 'bg-waf-elevated text-waf-text' : 'text-waf-muted hover:bg-waf-elevated hover:text-waf-text'
                        }`}
                      >
                        {isActive && !hasChildren && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-5 bg-waf-orange rounded-r-full" />}
                        <item.icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-waf-orange' : 'text-waf-dim group-hover:text-waf-muted'}`} />
                        <span className="flex-1 text-left font-medium">{item.label}</span>
                        {hasChildren && (
                          <motion.div animate={{ rotate: isExpanded ? 180 : 0 }} transition={{ duration: 0.2 }}>
                            <ChevronDown className="w-4 h-4 text-waf-dim" />
                          </motion.div>
                        )}
                      </button>
                      <AnimatePresence>
                        {hasChildren && isExpanded && (
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                            <div className="ml-4 pl-4 border-l border-waf-border space-y-0.5 py-1">
                              {item.children!.map((child) => {
                                const isChildActive = activePage === child.id;
                                return (
                                  <button key={child.id} onClick={() => handlePageChange(child.id)} className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all ${isChildActive ? 'bg-waf-elevated text-waf-text' : 'text-waf-dim hover:bg-waf-elevated/50 hover:text-waf-muted'}`}>
                                    {isChildActive && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-4 bg-waf-orange rounded-r-full" />}
                                    <child.icon className={`w-3.5 h-3.5 shrink-0 ${isChildActive ? 'text-waf-orange' : ''}`} />
                                    <span className="text-left">{child.label}</span>
                                  </button>
                                );
                              })}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  );
                })}
              </nav>
              <div className="p-3 border-t border-waf-border">
                <button onClick={() => handlePageChange('settings')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all ${activePage === 'settings' ? 'bg-waf-elevated text-waf-text' : 'text-waf-dim hover:bg-waf-elevated hover:text-waf-muted'}`}>
                  <Settings className="w-4 h-4" />
                  <span>Settings</span>
                </button>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}

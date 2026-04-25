import React, { createContext, useContext, useReducer, useEffect } from 'react';
import type { ReactNode } from 'react';

// Types
export interface Domain {
  id: string;
  name: string;
  status: 'active' | 'pending' | 'error';
  ssl: boolean;
  originIP: string;
  createdAt: string;
  trafficToday: number;
  threatsBlocked: number;
}

export interface DNSRecord {
  id: string;
  domainId: string;
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS';
  name: string;
  value: string;
  ttl: number;
  proxied: boolean;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'xss' | 'sql_injection' | 'brute_force' | 'ddos' | 'bot' | 'rate_limit' | 'ip_reputation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  sourceIP: string;
  country: string;
  url: string;
  action: 'blocked' | 'challenged' | 'logged';
  details: string;
}

export interface RequestLog {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  sourceIP: string;
  country: string;
  userAgent: string;
  status: 'allowed' | 'blocked' | 'challenged';
  responseTime: number;
  ruleTriggered?: string;
}

export interface WAFRules {
  id: string;
  name: string;
  description: string;
  pattern: string;
  action: 'block' | 'challenge' | 'log';
  enabled: boolean;
  priority: number;
  category: 'xss' | 'sqli' | 'lfi' | 'rfi' | 'xxe' | 'command_injection' | 'custom';
  hits: number;
}

export interface RateLimit {
  id: string;
  name: string;
  requests: number;
  window: number;
  action: 'block' | 'challenge' | 'throttle';
  enabled: boolean;
  matchPath: string;
}

export interface IPReputationEntry {
  id: string;
  ip: string;
  country: string;
  reputation: 'known_malicious' | 'suspicious' | 'tor' | 'vpn' | 'datacenter' | 'whitelist';
  firstSeen: string;
  lastSeen: string;
  threatCount: number;
  action: 'block' | 'challenge' | 'monitor';
}

export interface BotRule {
  id: string;
  name: string;
  botName: string;
  category: 'search_engine' | 'monitoring' | 'scraping' | 'spam' | 'credential_stuffing' | 'custom';
  action: 'allow' | 'block' | 'challenge';
  enabled: boolean;
  hits: number;
}

export interface AccessPolicy {
  id: string;
  name: string;
  description: string;
  allowedIPs: string[];
  blockedIPs: string[];
  allowedCountries: string[];
  blockedCountries: string[];
  requireAuth: boolean;
  enabled: boolean;
}

export interface NetworkPolicy {
  id: string;
  name: string;
  description: string;
  subnets: string[];
  allowedPorts: number[];
  action: 'allow' | 'block';
  enabled: boolean;
}

export interface DevicePosture {
  id: string;
  name: string;
  os: string;
  minVersion: string;
  requireEncryption: boolean;
  requireFirewall: boolean;
  requireAntivirus: boolean;
  enabled: boolean;
}

export interface Tunnel {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'error';
  protocol: 'wireguard' | 'ipsec' | 'openvpn';
  localEndpoint: string;
  remoteEndpoint: string;
  port: number;
  uptime: number;
  bytesTransferred: number;
}

export interface DDoSConfig {
  id: string;
  level: 'low' | 'medium' | 'high' | 'emergency';
  autoMitigate: boolean;
  challengeSuspicious: boolean;
  rateThreshold: number;
  burstThreshold: number;
  geoBlockHighRisk: boolean;
  bruteForceWindowSec: number;
}

export interface WAFSettings {
  mode: 'active' | 'detection' | 'learning';
  resourceMode: 'auto' | 'manual';
  cpuLimit: number;
  memoryLimit: number;
  workerThreads: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  logRetention: number;
  blockMode: 'aggressive' | 'standard' | 'passive';
  challengeSuspicious: boolean;
  autoUpdateRules: boolean;
  alertEmail: string;
  alertWebhook: string;
  historyRotateHours: number;
  egressEnabled: boolean;
  egressAddr: string;
  egressAllowlist: string;
  egressBlockPrivateIPs: boolean;
  egressExfilInspect: boolean;
  egressExfilBlock: boolean;
  meshEnabled: boolean;
  meshPeers: string;
  meshGossipIntervalSec: number;
  meshSyncTimeoutSec: number;
  meshAPIKey: string;
  securityHeadersEnabled: boolean;
  cspEnabled: boolean;
  cspPolicy: string;
  trustXFF: boolean;
  hstsEnabled: boolean;
  hstsMaxAgeSec: number;
  hstsIncludeSubdomains: boolean;
  hstsPreload: boolean;

  // JA3 TLS fingerprinting.
  ja3Enabled: boolean;
  ja3HardBlock: boolean;
  ja3Header: string;
  ja3TrustedSources: string;

  // Proof-of-work for high-risk sessions.
  powEnabled: boolean;
  powTriggerScore: number;
  powMinDifficulty: number;
  powMaxDifficulty: number;
  powTokenTTLSec: number;
  powCookieTTLSec: number;
}

export interface HostMachineStats {
  online: boolean;
  uptime_seconds: number;
  hostname: string;
  platform: string;
  architecture: string;
  go_version: string;
  waf_version: string;
}

export interface HostResources {
  total_cpu_cores: number;
  total_memory_mb: number;
  total_disk_gb: number;
  allocated_cpu_cores: number;
  allocated_memory_mb: number;
  allocated_disk_gb: number;
  cpu_usage_percent: number;
  memory_usage_percent: number;
  disk_usage_percent: number;
  load_average: [number, number, number];
  network_io: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
  };
}

export interface SSLCert {
  id: string;
  domain: string;
  issuer: string;
  not_before: string;
  not_after: string;
  fingerprint: string;
  auto_renew: boolean;
  valid: boolean;
}

export interface SSLTLSConfig {
  enabled: boolean;
  cert_source: 'auto' | 'upload';
  min_tls_version: '1.0' | '1.1' | '1.2' | '1.3';
  prefer_server_ciphers: boolean;
  hsts_enabled: boolean;
  hsts_max_age: number;
}

export interface ConnectionInfo {
  backend_url: string;
  listen_addr: string;
  admin_addr: string;
  poll_interval_sec: number;
  retry_attempts: number;
  timeout_ms: number;
  last_ping_ms: number;
  connected: boolean;
  last_connected_at: string;
  failover_active: boolean;
}

export interface SessionHistory {
  total_online_seconds: number;
  total_offline_seconds: number;
  last_online_at: string;
  last_offline_at: string;
  longest_online_streak_seconds: number;
  session_start_at: string;
  connection_events: {
    timestamp: string;
    state: ConnectionState;
    ping_ms: number;
  }[];
  ping_history: {
    timestamp: string;
    ping_ms: number;
  }[];
}

export type ConnectionState = 'connecting' | 'online' | 'offline' | 'configured';

interface WAFState {
  domains: Domain[];
  dnsRecords: DNSRecord[];
  securityEvents: SecurityEvent[];
  requestLogs: RequestLog[];
  wafRules: WAFRules[];
  rateLimits: RateLimit[];
  ipReputation: IPReputationEntry[];
  botRules: BotRule[];
  accessPolicies: AccessPolicy[];
  networkPolicies: NetworkPolicy[];
  devicePostures: DevicePosture[];
  tunnels: Tunnel[];
  ddosConfig: DDoSConfig;
  settings: WAFSettings;
  nextSteps: { id: number; label: string; description: string; completed: boolean }[];
  connectionState: ConnectionState;
  resourceUsage: {
    cpu: number;
    memory: number;
    diskIO: number;
    networkLatency: number;
  };
  trafficStats: {
    totalRequests: number;
    blockedRequests: number;
    allowedRequests: number;
    uniqueIPs: number;
    totalIPs: number;
  };
  hostStats: HostMachineStats;
  hostResources: HostResources;
  sslConfig: SSLTLSConfig;
  sslCertificates: SSLCert[];
  connectionInfo: ConnectionInfo;
  sessionHistory: SessionHistory;
  meshStatus: {
    enabled: boolean;
    peers: string[];
    lastSync: string;
    peerCount: number;
  };
  egressStatus: {
    enabled: boolean;
    addr: string;
    totalBlocked: number;
    totalAllowed: number;
  };
  meshPeers: string[];
  botsDetected: number;
}

type Action =
  | { type: 'SET_DOMAINS'; payload: Domain[] }
  | { type: 'ADD_DOMAIN'; payload: Domain }
  | { type: 'UPDATE_DOMAIN'; payload: Domain }
  | { type: 'DELETE_DOMAIN'; payload: string }
  | { type: 'SET_DNS_RECORDS'; payload: DNSRecord[] }
  | { type: 'ADD_DNS_RECORD'; payload: DNSRecord }
  | { type: 'DELETE_DNS_RECORD'; payload: string }
  | { type: 'SET_SECURITY_EVENTS'; payload: SecurityEvent[] }
  | { type: 'SET_REQUEST_LOGS'; payload: RequestLog[] }
  | { type: 'SET_WAF_RULES'; payload: WAFRules[] }
  | { type: 'UPDATE_WAF_RULE'; payload: WAFRules }
  | { type: 'SET_RATE_LIMITS'; payload: RateLimit[] }
  | { type: 'UPDATE_RATE_LIMIT'; payload: RateLimit }
  | { type: 'SET_IP_REPUTATION'; payload: IPReputationEntry[] }
  | { type: 'UPDATE_IP_REPUTATION'; payload: IPReputationEntry }
  | { type: 'SET_BOT_RULES'; payload: BotRule[] }
  | { type: 'UPDATE_BOT_RULE'; payload: BotRule }
  | { type: 'SET_ACCESS_POLICIES'; payload: AccessPolicy[] }
  | { type: 'UPDATE_ACCESS_POLICY'; payload: AccessPolicy }
  | { type: 'SET_NETWORK_POLICIES'; payload: NetworkPolicy[] }
  | { type: 'SET_DEVICE_POSTURES'; payload: DevicePosture[] }
  | { type: 'SET_TUNNELS'; payload: Tunnel[] }
  | { type: 'SET_DDOS_CONFIG'; payload: DDoSConfig }
  | { type: 'SET_SETTINGS'; payload: WAFSettings }
  | { type: 'UPDATE_RESOURCE_USAGE'; payload: WAFState['resourceUsage'] }
  | { type: 'UPDATE_TRAFFIC_STATS'; payload: WAFState['trafficStats'] }
  | { type: 'TOGGLE_NEXT_STEP'; payload: number }
  | { type: 'UPDATE_SETTINGS'; payload: Partial<WAFSettings> }
  | { type: 'SET_CONNECTION_STATE'; payload: ConnectionState }
  | { type: 'SET_HOST_STATS'; payload: HostMachineStats }
  | { type: 'SET_HOST_RESOURCES'; payload: HostResources }
  | { type: 'SET_SSL_CONFIG'; payload: SSLTLSConfig }
  | { type: 'SET_SSL_CERTIFICATES'; payload: SSLCert[] }
  | { type: 'SET_CONNECTION_INFO'; payload: ConnectionInfo }
  | { type: 'UPDATE_CONNECTION_INFO'; payload: Partial<ConnectionInfo> }
  | { type: 'SET_SESSION_HISTORY'; payload: SessionHistory }
  | { type: 'RECORD_CONNECTION_EVENT'; payload: { state: ConnectionState; ping_ms: number } }
  | { type: 'SET_MESH_STATUS'; payload: WAFState['meshStatus'] }
  | { type: 'UPDATE_MESH_STATUS'; payload: Partial<WAFState['meshStatus']> }
  | { type: 'SET_EGRESS_STATUS'; payload: WAFState['egressStatus'] }
  | { type: 'SET_MESH_PEERS'; payload: string[] }
  | { type: 'SET_BOTS_DETECTED'; payload: number }
  | { type: 'RECORD_PING'; payload: number };

const defaultSettings: WAFSettings = {
  mode: 'detection',
  resourceMode: 'auto',
  cpuLimit: 80,
  memoryLimit: 80,
  workerThreads: 4,
  logLevel: 'info',
  logRetention: 30,
  blockMode: 'standard',
  challengeSuspicious: true,
  autoUpdateRules: true,
  alertEmail: '',
  alertWebhook: '',
  historyRotateHours: 168,
  egressEnabled: false,
  egressAddr: ':8081',
  egressAllowlist: '',
  egressBlockPrivateIPs: true,
  egressExfilInspect: false,
  egressExfilBlock: false,
  meshEnabled: false,
  meshPeers: '',
  meshGossipIntervalSec: 60,
  meshSyncTimeoutSec: 10,
  meshAPIKey: '',
  securityHeadersEnabled: true,
  cspEnabled: false,
  cspPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  trustXFF: false,
  hstsEnabled: false,
  hstsMaxAgeSec: 15552000,
  hstsIncludeSubdomains: true,
  hstsPreload: false,
  ja3Enabled: false,
  ja3HardBlock: false,
  ja3Header: '',
  ja3TrustedSources: '',
  powEnabled: false,
  powTriggerScore: 60,
  powMinDifficulty: 18,
  powMaxDifficulty: 24,
  powTokenTTLSec: 120,
  powCookieTTLSec: 3600,
};

const defaultDDoS: DDoSConfig = {
  id: '1',
  level: 'medium',
  autoMitigate: true,
  challengeSuspicious: true,
  rateThreshold: 1000,
  burstThreshold: 5000,
  geoBlockHighRisk: false,
  bruteForceWindowSec: 60,
};

const defaultHostStats: HostMachineStats = {
  online: false,
  uptime_seconds: 0,
  hostname: 'unknown',
  platform: 'unknown',
  architecture: 'unknown',
  go_version: 'unknown',
  waf_version: 'unknown',
};

const defaultHostResources: HostResources = {
  total_cpu_cores: 0,
  total_memory_mb: 0,
  total_disk_gb: 0,
  allocated_cpu_cores: 0,
  allocated_memory_mb: 0,
  allocated_disk_gb: 0,
  cpu_usage_percent: 0,
  memory_usage_percent: 0,
  disk_usage_percent: 0,
  load_average: [0, 0, 0],
  network_io: { bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0 },
};

const defaultSSLConfig: SSLTLSConfig = {
  enabled: false,
  cert_source: 'auto',
  min_tls_version: '1.2',
  prefer_server_ciphers: true,
  hsts_enabled: true,
  hsts_max_age: 31536000,
};

const defaultConnectionInfo: ConnectionInfo = {
  backend_url: 'http://localhost:3000',
  listen_addr: ':8080',
  admin_addr: ':8443',
  poll_interval_sec: 10,
  retry_attempts: 3,
  timeout_ms: 2000,
  last_ping_ms: -1,
  connected: false,
  last_connected_at: '',
  failover_active: false,
};

const defaultSessionHistory: SessionHistory = {
  total_online_seconds: 0,
  total_offline_seconds: 0,
  last_online_at: '',
  last_offline_at: '',
  longest_online_streak_seconds: 0,
  session_start_at: new Date().toISOString(),
  connection_events: [],
  ping_history: [],
};

const initialState: WAFState = {
  domains: [],
  dnsRecords: [],
  securityEvents: [],
  requestLogs: [],
  wafRules: [
    {
      id: '1',
      name: 'XSS Protection',
      description: 'Blocks known XSS attack patterns including script injection and event handler abuse',
      pattern: '<script|onerror=|onload=|javascript:|eval\(',
      action: 'block',
      enabled: true,
      priority: 1,
      category: 'xss',
      hits: 0,
    },
    {
      id: '2',
      name: 'SQL Injection',
      description: 'Blocks SQL injection attempts including UNION-based and time-based attacks',
      pattern: 'union\s+select|sleep\(|benchmark\(|1=1|--|;--|drop\s+table',
      action: 'block',
      enabled: true,
      priority: 1,
      category: 'sqli',
      hits: 0,
    },
    {
      id: '3',
      name: 'Path Traversal (LFI)',
      description: 'Blocks local file inclusion and directory traversal attempts',
      pattern: '\.\./|\.\.\\\\|/etc/passwd|/proc/self|file://',
      action: 'block',
      enabled: true,
      priority: 2,
      category: 'lfi',
      hits: 0,
    },
    {
      id: '4',
      name: 'Command Injection',
      description: 'Blocks command injection via shell metacharacters',
      pattern: ';\s*cat\s|&&\s*whoami|\|\s*bash|\$\(.*\)|`.*`',
      action: 'block',
      enabled: true,
      priority: 1,
      category: 'command_injection',
      hits: 0,
    },
    {
      id: '5',
      name: 'XXE Protection',
      description: 'Blocks XML External Entity attacks',
      pattern: '<!ENTITY\s+.*\s+SYSTEM|file://|php://',
      action: 'block',
      enabled: true,
      priority: 2,
      category: 'xxe',
      hits: 0,
    },
  ],
  rateLimits: [
    { id: '1', name: 'General API Rate Limit', requests: 100, window: 60, action: 'throttle', enabled: true, matchPath: '/api/*' },
    { id: '2', name: 'Login Brute Force', requests: 5, window: 300, action: 'block', enabled: true, matchPath: '/login' },
  ],
  ipReputation: [],
  botRules: [
    { id: '1', name: 'Google Bot', botName: 'Googlebot', category: 'search_engine', action: 'allow', enabled: true, hits: 0 },
    { id: '2', name: 'Bing Bot', botName: 'Bingbot', category: 'search_engine', action: 'allow', enabled: true, hits: 0 },
    { id: '3', name: 'Known Scraper Block', botName: 'Scrapy', category: 'scraping', action: 'block', enabled: true, hits: 0 },
    { id: '4', name: 'Credential Stuffing', botName: 'Sentry MBA', category: 'credential_stuffing', action: 'block', enabled: true, hits: 0 },
  ],
  accessPolicies: [],
  networkPolicies: [],
  devicePostures: [],
  tunnels: [],
  ddosConfig: defaultDDoS,
  settings: defaultSettings,
  connectionState: 'connecting',
  nextSteps: [
    { id: 1, label: 'Configure DNS', description: 'Point your domain A record to the WAF server IP', completed: false },
    { id: 2, label: 'Set Origin IP', description: 'Configure your backend server IP in WAF settings', completed: false },
    { id: 3, label: 'Enable SSL/TLS', description: 'Upload certificate or use auto-generated one', completed: false },
    { id: 4, label: 'Test Connectivity', description: 'Verify traffic flows through WAF to your endpoint', completed: false },
  ],
  resourceUsage: { cpu: 0, memory: 0, diskIO: 0, networkLatency: 0 },
  trafficStats: { totalRequests: 0, blockedRequests: 0, allowedRequests: 0, uniqueIPs: 0, totalIPs: 0 },
  hostStats: defaultHostStats,
  hostResources: defaultHostResources,
  sslConfig: defaultSSLConfig,
  sslCertificates: [],
  connectionInfo: defaultConnectionInfo,
  sessionHistory: defaultSessionHistory,
  meshStatus: {
    enabled: false,
    peers: [],
    lastSync: '',
    peerCount: 0,
  },
  egressStatus: { enabled: false, addr: ':8081', totalBlocked: 0, totalAllowed: 0 },
  meshPeers: [],
  botsDetected: 0,
};

function wafReducer(state: WAFState, action: Action): WAFState {
  switch (action.type) {
    case 'SET_DOMAINS':
      return { ...state, domains: action.payload };
    case 'ADD_DOMAIN':
      return { ...state, domains: [...state.domains, action.payload] };
    case 'UPDATE_DOMAIN':
      return {
        ...state,
        domains: state.domains.map((d) => (d.id === action.payload.id ? action.payload : d)),
      };
    case 'DELETE_DOMAIN':
      return { ...state, domains: state.domains.filter((d) => d.id !== action.payload) };
    case 'SET_DNS_RECORDS':
      return { ...state, dnsRecords: action.payload };
    case 'ADD_DNS_RECORD':
      return { ...state, dnsRecords: [...state.dnsRecords, action.payload] };
    case 'DELETE_DNS_RECORD':
      return { ...state, dnsRecords: state.dnsRecords.filter((r) => r.id !== action.payload) };
    case 'SET_SECURITY_EVENTS':
      return { ...state, securityEvents: action.payload };
    case 'SET_REQUEST_LOGS':
      return { ...state, requestLogs: action.payload };
    case 'SET_WAF_RULES':
      return { ...state, wafRules: action.payload };
    case 'UPDATE_WAF_RULE':
      return {
        ...state,
        wafRules: state.wafRules.map((r) => (r.id === action.payload.id ? action.payload : r)),
      };
    case 'SET_RATE_LIMITS':
      return { ...state, rateLimits: action.payload };
    case 'UPDATE_RATE_LIMIT':
      return {
        ...state,
        rateLimits: state.rateLimits.map((r) => (r.id === action.payload.id ? action.payload : r)),
      };
    case 'SET_IP_REPUTATION':
      return { ...state, ipReputation: action.payload };
    case 'UPDATE_IP_REPUTATION':
      return {
        ...state,
        ipReputation: state.ipReputation.map((r) => (r.id === action.payload.id ? action.payload : r)),
      };
    case 'SET_BOT_RULES':
      return { ...state, botRules: action.payload };
    case 'UPDATE_BOT_RULE':
      return {
        ...state,
        botRules: state.botRules.map((r) => (r.id === action.payload.id ? action.payload : r)),
      };
    case 'SET_ACCESS_POLICIES':
      return { ...state, accessPolicies: action.payload };
    case 'UPDATE_ACCESS_POLICY':
      return {
        ...state,
        accessPolicies: state.accessPolicies.map((p) => (p.id === action.payload.id ? action.payload : p)),
      };
    case 'SET_NETWORK_POLICIES':
      return { ...state, networkPolicies: action.payload };
    case 'SET_DEVICE_POSTURES':
      return { ...state, devicePostures: action.payload };
    case 'SET_TUNNELS':
      return { ...state, tunnels: action.payload };
    case 'SET_DDOS_CONFIG':
      return { ...state, ddosConfig: action.payload };
    case 'SET_SETTINGS':
      return { ...state, settings: action.payload };
    case 'UPDATE_SETTINGS':
      return { ...state, settings: { ...state.settings, ...action.payload } };
    case 'UPDATE_RESOURCE_USAGE':
      return { ...state, resourceUsage: action.payload };
    case 'UPDATE_TRAFFIC_STATS':
      return { ...state, trafficStats: action.payload };
    case 'TOGGLE_NEXT_STEP':
      return {
        ...state,
        nextSteps: state.nextSteps.map((s) =>
          s.id === action.payload ? { ...s, completed: !s.completed } : s
        ),
      };
    case 'SET_CONNECTION_STATE':
      return { ...state, connectionState: action.payload };
    case 'SET_HOST_STATS':
      return { ...state, hostStats: action.payload };
    case 'SET_HOST_RESOURCES':
      return { ...state, hostResources: action.payload };
    case 'SET_SSL_CONFIG':
      return { ...state, sslConfig: action.payload };
    case 'SET_SSL_CERTIFICATES':
      return { ...state, sslCertificates: action.payload };
    case 'SET_CONNECTION_INFO':
      return { ...state, connectionInfo: action.payload };
    case 'UPDATE_CONNECTION_INFO':
      return { ...state, connectionInfo: { ...state.connectionInfo, ...action.payload } };
    case 'SET_SESSION_HISTORY':
      return { ...state, sessionHistory: action.payload };
    case 'RECORD_CONNECTION_EVENT': {
      const now = new Date().toISOString();
      const events = [...state.sessionHistory.connection_events, { timestamp: now, state: action.payload.state, ping_ms: action.payload.ping_ms }].slice(-100);
      const isOnline = action.payload.state === 'online';
      const isOffline = action.payload.state === 'offline';
      return {
        ...state,
        sessionHistory: {
          ...state.sessionHistory,
          connection_events: events,
          last_online_at: isOnline ? now : state.sessionHistory.last_online_at,
          last_offline_at: isOffline ? now : state.sessionHistory.last_offline_at,
        },
      };
    }
    case 'SET_MESH_STATUS':
      return { ...state, meshStatus: action.payload };
    case 'UPDATE_MESH_STATUS':
      return { ...state, meshStatus: { ...state.meshStatus, ...action.payload } };
    case 'SET_EGRESS_STATUS':
      return { ...state, egressStatus: action.payload };
    case 'SET_MESH_PEERS':
      return { ...state, meshPeers: action.payload };
    case 'SET_BOTS_DETECTED':
      return { ...state, botsDetected: action.payload };
    case 'RECORD_PING': {
      const now = new Date().toISOString();
      const pings = [...state.sessionHistory.ping_history, { timestamp: now, ping_ms: action.payload }].slice(-50);
      return {
        ...state,
        sessionHistory: {
          ...state.sessionHistory,
          ping_history: pings,
        },
      };
    }
    default:
      return state;
  }
}

interface WAFContextType {
  state: WAFState;
  dispatch: React.Dispatch<Action>;
}

const WAFContext = createContext<WAFContextType | null>(null);

const STORAGE_KEY = 'waf_state_v1';

// Keys that persist between sessions (user data/settings/config)
type PersistedKey =
  | 'domains' | 'dnsRecords' | 'wafRules' | 'rateLimits' | 'ipReputation'
  | 'botRules' | 'accessPolicies' | 'networkPolicies' | 'devicePostures'
  | 'tunnels' | 'ddosConfig' | 'settings' | 'nextSteps'
  | 'sslConfig' | 'sslCertificates' | 'connectionInfo' | 'sessionHistory'
  | 'meshStatus' | 'egressStatus' | 'meshPeers' | 'botsDetected';

const PERSISTED_KEYS: PersistedKey[] = [
  'domains', 'dnsRecords', 'wafRules', 'rateLimits', 'ipReputation',
  'botRules', 'accessPolicies', 'networkPolicies', 'devicePostures',
  'tunnels', 'ddosConfig', 'settings', 'nextSteps',
  'sslConfig', 'sslCertificates', 'connectionInfo', 'sessionHistory',
  'meshStatus', 'egressStatus', 'meshPeers', 'botsDetected',
];

function loadPersistedState(): Partial<WAFState> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<WAFState>;
    // Validate it's an object
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

function savePersistedState(state: WAFState) {
  try {
    const toSave: Partial<WAFState> = {};
    for (const key of PERSISTED_KEYS) {
      (toSave as Record<string, unknown>)[key] = state[key];
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
  } catch {
    // Silently fail (e.g., storage full or private mode)
  }
}

function mergeWithPersisted(initial: WAFState): WAFState {
  const persisted = loadPersistedState();
  if (!persisted) return initial;

  const merged = { ...initial };
  for (const key of PERSISTED_KEYS) {
    const val = persisted[key];
    if (val !== undefined && val !== null) {
      // Type-safe merge - arrays must have at least one element to be valid
      if (Array.isArray(val)) {
        (merged as Record<string, unknown>)[key] = val;
      } else if (typeof val === 'object') {
        (merged as Record<string, unknown>)[key] = val;
      }
    }
  }
  return merged;
}

export function WAFProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(wafReducer, initialState, mergeWithPersisted);

  // Persist state to localStorage whenever persisted keys change
  useEffect(() => {
    savePersistedState(state);
  }, [
    state.domains, state.dnsRecords, state.wafRules, state.rateLimits,
    state.ipReputation, state.botRules, state.accessPolicies,
    state.networkPolicies, state.devicePostures, state.tunnels,
    state.ddosConfig, state.settings, state.nextSteps,
    state.sslConfig, state.sslCertificates, state.connectionInfo,
    state.sessionHistory, state.meshStatus, state.egressStatus,
    state.meshPeers, state.botsDetected,
  ]);

  return <WAFContext.Provider value={{ state, dispatch }}>{children}</WAFContext.Provider>;
}

export function useWAF() {
  const context = useContext(WAFContext);
  if (!context) throw new Error('useWAF must be used within WAFProvider');
  return context;
}

// API Service Layer - connects to WEWAF Go backend
// All endpoints are relative to the same origin (the Go server serves both API and UI)

const API_PREFIX = '/api';

function getHeaders(): Record<string, string> {
  return { 'Content-Type': 'application/json' };
}

async function safeFetch<T>(path: string, options?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(`${API_PREFIX}${path}`, {
      ...options,
      headers: { ...getHeaders(), ...options?.headers },
    });
    if (!res.ok) {
      console.warn(`API ${path} returned ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.warn(`API ${path} failed:`, err);
    return null;
  }
}

async function get<T>(path: string): Promise<T | null> {
  return safeFetch<T>(path);
}

async function post<T>(path: string, body: unknown): Promise<T | null> {
  return safeFetch<T>(path, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

async function put<T>(path: string, body: unknown): Promise<T | null> {
  return safeFetch<T>(path, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

async function del<T>(path: string): Promise<T | null> {
  return safeFetch<T>(path, { method: 'DELETE' });
}

// =====================
// Data Types from Go Backend
// =====================

export interface MetricsResponse {
  total_requests: number;
  blocked_requests: number;
  passed_requests: number;
  total_bytes_in: number;
  total_bytes_out: number;
  bytes_in_per_sec?: number;
  bytes_out_per_sec?: number;
  errors: number;
  unique_ips: number;
  recent_blocks: BlockRecord[];
  traffic_history: TrafficPoint[];
  status_code_buckets?: Record<string, number>;
  egress_blocked?: number;
  egress_allowed?: number;
  bots_detected?: number;
}

export interface BlockRecord {
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  rule_id: string;
  rule_category?: string;
  score: number;
  message: string;
}

export interface TrafficPoint {
  time: string;
  requests: number;
  blocked: number;
}

export interface StatsResponse {
  mode: string;
  version: string;
  uptime_sec: number;
  cpu_percent?: number;
  memory_percent?: number;
  disk_io_percent?: number;
  network_latency_ms?: number;
  [key: string]: unknown;
}

export interface ConfigResponse {
  listen_addr: string;
  backend_url: string;
  admin_addr: string;
  mode: string;
  max_cpu_cores: number;
  max_memory_mb: number;
  read_timeout_sec: number;
  write_timeout_sec: number;
  brute_force_window_sec: number;
  history_rotate_hours: number;
  history_buffer_size: number;
  history_flush_seconds: number;
  [key: string]: unknown;
}

export interface RulesResponse {
  rules: CompiledRule[];
}

export interface CompiledRule {
  id: string;
  name: string;
  phase: string;
  action: string;
  score: number;
  description: string;
}

export interface HealthResponse {
  status: string;
  mode: string;
}

export interface BlocksResponse {
  recent: BlockRecord[];
}

export interface SetModePayload {
  mode: 'active' | 'detection' | 'learning';
}

export interface BanEntry {
  ip: string;
  reason: string;
  expires_at: string;
}

export interface RateLimitConfigResponse {
  rate_limit_rps: number;
  rate_limit_burst: number;
  brute_force_window_sec: number;
  brute_force_threshold: number;
  block_threshold: number;
  max_concurrent_req: number;
  max_body_bytes: number;
}

export interface RequestEvent {
  ts: string;
  ip: string;
  method: string;
  path: string;
  rule_id: string;
  rule_category: string;
  score: number;
  message: string;
}

// =====================
// Host Machine Monitoring
// =====================

export interface HostStatsResponse {
  online: boolean;
  uptime_seconds: number;
  hostname: string;
  platform: string;
  architecture: string;
  go_version: string;
  waf_version: string;
}

export interface HostResourcesResponse {
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

// =====================
// Connection Management
// =====================

export interface ConnectionConfig {
  backend_url: string;
  listen_addr: string;
  admin_addr: string;
  poll_interval_sec: number;
  retry_attempts: number;
  timeout_ms: number;
}

export interface ConnectionStatus {
  connected: boolean;
  last_ping_ms: number;
  last_connected_at: string;
  connection_method: string;
  failover_active: boolean;
  total_probes?: number;
  failed_probes?: number;
}

export interface PingSample {
  timestamp: string;
  ping_ms: number;
  ok: boolean;
}

export interface ConnectionEvent {
  timestamp: string;
  state: 'online' | 'offline';
  ping_ms: number;
}

export interface IPInsights {
  ip: string;
  banned: boolean;
  ban?: BanEntry;
  activity: IPActivityEntry;
  categories: Record<string, number>;
  recent_blocks: Array<{
    timestamp: string;
    ip: string;
    method: string;
    path: string;
    rule_id: string;
    rule_category: string;
    score: number;
    message: string;
  }>;
}

export interface AutoMitigateResponse {
  banned: string[];
  scanned: number;
  threshold: number;
}

export interface DDoSStats {
  total_requests?: number;
  flagged_volumetric?: number;
  flagged_conn_rate?: number;
  flagged_slow_read?: number;
  flagged_botnet?: number;
  under_attack?: boolean;
  last_attack_unix?: number;
  adaptive_baseline?: number;
  spike_streak?: number;
  spike_windows_req?: number;
  min_absolute_rps?: number;
}

export interface ShaperStats {
  enabled?: boolean;
  base_max_rps?: number;
  base_burst?: number;
  current_rps?: number;
  current_burst?: number;
  tokens?: number;
  admitted?: number;
  rejected?: number;
  tightenings?: number;
  under_pressure?: boolean;
}

export interface BreakerStats {
  state?: 'closed' | 'open' | 'half_open';
  consecutive_failures?: number;
  successes?: number;
  total_failures?: number;
  short_circuited?: number;
  opened_at_unix_nano?: number;
  failure_threshold?: number;
  open_timeout_seconds?: number;
}

export interface ZeroTrustPolicy {
  id: string;
  description?: string;
  path_prefix?: string;
  path_exact?: string;
  path_regex?: string;
  methods?: string[];
  require_auth_header?: string;
  require_mtls?: boolean;
  allowed_countries?: string[];
  blocked_countries?: string[];
  allowed_cidrs?: string[];
  blocked_cidrs?: string[];
  fallback_allow?: boolean;
  time_start?: string;
  time_end?: string;
  simulate?: boolean;
  deny_by_default?: boolean;
}

export type SetupCheckStatus = 'pass' | 'fail' | 'warn' | 'skip';

export interface SetupCheckResult {
  step: string;
  status: SetupCheckStatus;
  message: string;
  detail?: Record<string, unknown>;
  at: string;
}

export interface ErrorEvent {
  timestamp: string;
  source: string;
  message: string;
  request_id?: string;
}

export interface HealthDetail {
  overall: 'ok' | 'degraded' | 'fail' | 'unknown';
  failures: number;
  subsystems: Array<{
    subsystem: string;
    status: 'ok' | 'degraded' | 'fail';
    message: string;
    detail?: Record<string, unknown>;
    at: string;
  }>;
}

export interface SSLCertificate {
  id: string;
  domain: string;
  issuer: string;
  not_before: string;
  not_after: string;
  fingerprint: string;
  auto_renew: boolean;
  valid: boolean;
}

export interface SSLConfig {
  enabled: boolean;
  cert_source: 'auto' | 'upload';
  min_tls_version: '1.0' | '1.1' | '1.2' | '1.3';
  prefer_server_ciphers: boolean;
  hsts_enabled: boolean;
  hsts_max_age: number;
}

export interface MeshStatusResponse {
  enabled: boolean;
  peers: string[];
  last_sync: string;
  peer_count: number;
}

export interface EgressConfigResponse {
  egress_enabled: boolean;
  egress_addr: string;
  egress_allowlist: string[];
  egress_block_private_ips: boolean;
  security_headers_enabled: boolean;
}

export interface EgressStatusResponse {
  enabled: boolean;
  addr: string;
  block_private_ips: boolean;
  allowlist: string[];
  allowlist_count: number;
  total_blocked: number;
  total_allowed: number;
  recent?: EgressEvent[];
}

export interface EgressEvent {
  timestamp: string;
  target_url: string;
  reason?: string;
  allowed: boolean;
}

export interface NetworkSummaryResponse {
  total_requests?: number;
  blocked_requests?: number;
  passed_requests?: number;
  total_bytes_in?: number;
  total_bytes_out?: number;
  bytes_in_per_sec?: number;
  bytes_out_per_sec?: number;
  egress_blocked?: number;
  egress_allowed?: number;
  status_code_buckets?: Record<string, number>;
  recent_egress?: EgressEvent[];
  host_network_io?: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
  };
  host_bandwidth_in_bps?: number;
  host_bandwidth_out_bps?: number;
  backend_connected?: boolean;
  backend_latency_ms?: number;
  timestamp: string;
}

export interface TopPathEntry {
  path: string;
  count: number;
}

export interface IPActivityEntry {
  ip: string;
  first_seen: string;
  last_seen: string;
  request_count: number;
  block_count: number;
}

export interface MeshPeersResponse {
  peers: string[];
  count: number;
  status: string;
}

export interface BotEvent {
  timestamp: string;
  ip: string;
  user_agent: string;
  bot_name: string;
  score: number;
}

export interface SessionView {
  id: string;
  first_seen: string;
  last_seen: string;
  request_count: number;
  block_count: number;
  paths: string[];
  user_agents: string[];
  ips: string[];
  mouse_events: number;
  key_events: number;
  time_on_page_ms: number;
  beacon_count: number;
  challenge_passed: boolean;
  risk_score: number;
}

export interface GraphQLStatsResponse {
  enabled: boolean;
  max_depth?: number;
  max_aliases?: number;
  max_fields?: number;
  block?: boolean;
  role_header?: string;
  stats?: {
    requests: number;
    blocked: number;
    depth_fails: number;
    alias_fails: number;
    field_fails: number;
    auth_fails: number;
    parse_fails: number;
  };
}

export interface GraphQLSample {
  timestamp: string;
  operation: string;
  depth: number;
  aliases: number;
  fields: number;
  blocked: boolean;
  reason?: string;
}

export interface BotsDetectedResponse {
  bots: BotEvent[];
  count: number;
}

// =====================
// API Functions (all return null on error - no throws)
// =====================

export const api = {
  // Core WAF
  getMetrics: () => get<MetricsResponse>('/metrics'),
  getStats: () => get<StatsResponse>('/stats'),
  getConfig: () => get<ConfigResponse>('/config'),
  setMode: (mode: 'active' | 'detection' | 'learning') =>
    post<ConfigResponse & { status: string }>('/config', { mode }),
  updateConfig: (payload: {
    mode?: string;
    history_rotate_hours?: number;
    egress_enabled?: boolean;
    egress_addr?: string;
    egress_allowlist?: string[];
    egress_block_private_ips?: boolean;
    mesh_enabled?: boolean;
    mesh_peers?: string[];
    mesh_gossip_interval_sec?: number;
    mesh_sync_timeout_sec?: number;
    mesh_api_key?: string;
    security_headers_enabled?: boolean;
    paranoia_level?: number;
    crs_enabled?: boolean;
    failsafe_mode?: 'closed' | 'open';
    shaper_enabled?: boolean;
    shaper_max_rps?: number;
    shaper_burst?: number;
    decompress_inspect?: boolean;
    decompress_ratio_cap?: number;
    ban_backoff_enabled?: boolean;
    ban_backoff_multiplier?: number;
    ban_backoff_window_sec?: number;
    max_ban_duration_sec?: number;
    per_rule_counters?: boolean;
    block_threshold?: number;
    rate_limit_rps?: number;
    rate_limit_burst?: number;
    session_tracking_enabled?: boolean;
    browser_challenge_enabled?: boolean;
    browser_challenge_block?: boolean;
    session_block_threshold?: number;
    session_request_rate_ceiling?: number;
    session_path_count_ceiling?: number;
    graphql_enabled?: boolean;
    graphql_block_on_error?: boolean;
    graphql_max_depth?: number;
    graphql_max_aliases?: number;
    graphql_max_fields?: number;
    graphql_role_header?: string;
  }) =>
    post<ConfigResponse & { status: string }>('/config', payload),
  getRuleCounters: () => get<{ counters: Record<string, number> }>('/rules/counters'),

  // Sessions + browser integrity.
  getSessions: (limit = 200) => get<{ sessions: SessionView[]; enabled: boolean; count: number }>(`/sessions?limit=${limit}`),
  getSession: (id: string) => get<SessionView>(`/sessions/${encodeURIComponent(id)}`),

  // GraphQL Guard.
  getGraphQLStats: () => get<GraphQLStatsResponse>('/graphql/stats'),
  getGraphQLRecent: () => get<{ recent: GraphQLSample[] }>('/graphql/recent'),
  getBlocks: () => get<BlocksResponse>('/blocks'),
  getTraffic: () => get<TrafficPoint[]>('/traffic'),
  getRules: () => get<RulesResponse>('/rules'),
  getHealth: () => get<HealthResponse>('/health'),
  getBans: () => get<{ bans: BanEntry[] }>('/bans'),
  banIP: (ip: string, durationSec: number, reason?: string) =>
    post<{ status: string }>('/bans', { ip, duration_sec: durationSec, reason: reason || 'manual' }),
  unbanIP: (ip: string) => del<{ status: string }>(`/bans?ip=${encodeURIComponent(ip)}`),
  getRateLimitConfig: () => get<RateLimitConfigResponse>('/ratelimit/config'),
  getRequests: () => get<{ requests: RequestEvent[] }>('/requests'),
  getBotsDetected: () => get<{ bots_detected: number }>('/metrics').then(m => m?.bots_detected ?? null),

  // Host Machine Monitoring
  getHostStats: () => get<HostStatsResponse>('/host/stats'),
  getHostResources: () => get<HostResourcesResponse>('/host/resources'),

  // Connection Management
  getConnectionStatus: () => get<ConnectionStatus>('/connection/status'),
  getConnectionConfig: () => get<ConnectionConfig>('/connection/config'),
  setConnectionConfig: (config: Partial<ConnectionConfig>) =>
    put<ConnectionConfig>('/connection/config', config),
  testConnection: () => post<{ success: boolean; latency_ms: number }>('/connection/test', {}),
  getConnectionHistory: () => get<{ history: PingSample[] }>('/connection/history'),
  getConnectionEvents: () => get<{ events: ConnectionEvent[] }>('/connection/events'),

  // IP Intelligence
  getIPInsights: (ip: string) => get<IPInsights>(`/ip/${encodeURIComponent(ip)}`),
  autoMitigate: (threshold = 10, durationSec = 3600) =>
    post<AutoMitigateResponse>('/ip-auto-mitigate', { threshold, duration_sec: durationSec }),

  // DDoS + circuit breaker + shaper + zero-trust
  getDDoSStats: () => get<DDoSStats>('/ddos/stats'),
  getBreakerStats: () => get<BreakerStats>('/breaker/stats'),
  getShaperStats: () => get<ShaperStats>('/shaper/stats'),
  getZeroTrustPolicies: () => get<{ policies: ZeroTrustPolicy[] }>('/zerotrust/policies'),
  setZeroTrustPolicies: (policies: ZeroTrustPolicy[]) =>
    put<{ status: string; count: number }>('/zerotrust/policies', { policies }),
  getZeroTrustTemplates: () => get<{ templates: ZeroTrustPolicy[] }>('/zerotrust/templates'),

  // Setup checks
  checkSetupDNS: (domain: string, expectedIP?: string) =>
    post<SetupCheckResult>('/setup/checks/dns', { domain, expected_ip: expectedIP }),
  checkSetupOrigin: () => post<SetupCheckResult>('/setup/checks/origin', {}),
  checkSetupSSL: (domain?: string) =>
    get<SetupCheckResult>(`/setup/checks/ssl${domain ? '?domain=' + encodeURIComponent(domain) : ''}`),
  checkSetupTraffic: () => post<SetupCheckResult>('/setup/checks/traffic', {}),
  checkSetupRules: () => get<SetupCheckResult>('/setup/checks/rules'),
  checkSetupHistory: () => get<SetupCheckResult>('/setup/checks/history'),
  runSetupChecks: (domain?: string, expectedIP?: string) =>
    post<{ results: SetupCheckResult[] }>('/setup/checks/all', { domain, expected_ip: expectedIP }),

  // Ops panels
  getErrors: () => get<{ errors: ErrorEvent[]; count: number }>('/errors'),
  getHealthDetail: () => get<HealthDetail>('/health/detail'),

  // SSL/TLS
  getCertificates: () => get<{ certificates: SSLCertificate[] }>('/ssl/certificates'),
  uploadCertificate: (cert: { domain: string; cert_pem: string; key_pem: string }) =>
    post<SSLCertificate>('/ssl/certificates', cert),
  deleteCertificate: (id: string) => del(`/ssl/certificates/${id}`),
  getSSLConfig: () => get<SSLConfig>('/ssl/config'),
  setSSLConfig: (config: Partial<SSLConfig>) => put<SSLConfig>('/ssl/config', config),

  getEgressConfig: () => get<EgressConfigResponse>('/config'),
  getMeshStatus: () => get<MeshStatusResponse>('/mesh/status'),
  getEgressStatus: () => get<EgressStatusResponse>('/egress/status'),
  getEgressRecent: (limit = 100) => get<{ events: EgressEvent[] }>(`/egress/recent?limit=${limit}`),
  getMeshPeers: () => get<MeshPeersResponse>('/mesh/peers'),

  // Network Monitoring
  getNetworkSummary: () => get<NetworkSummaryResponse>('/network/summary'),
  getTopPaths: (limit = 25) => get<{ paths: TopPathEntry[]; from: string; to: string }>(`/network/top-paths?limit=${limit}`),
  getTopIPs: (limit = 50) => get<{ ips: IPActivityEntry[]; from: string; to: string }>(`/network/top-ips?limit=${limit}`),
  getBots: (limit = 100) => get<BotsDetectedResponse>(`/bots/detected?limit=${limit}`),
  syncMeshPeer: (peerUrl: string, apiKey: string) =>
    fetch(`${peerUrl}/api/mesh/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Mesh-Key': apiKey },
      body: JSON.stringify({}),
    }).then(r => r.ok ? r.json() : null).catch(() => null),
};

// Polling helper for real-time data
export function startPolling(
  callback: () => void,
  intervalMs: number = 5000
): () => void {
  const id = setInterval(callback, intervalMs);
  return () => clearInterval(id);
}

// Live-events SSE helper. Returns a cleanup function that closes the stream.
export interface LiveEventHandlers {
  onBlock?: (e: BlockRecord) => void;
  onEgress?: (e: EgressEvent) => void;
  onBot?: (e: BotEvent) => void;
  onError?: (err: Event) => void;
  onOpen?: () => void;
}

export function connectLiveEvents(handlers: LiveEventHandlers): () => void {
  let es: EventSource | null = null;
  let stopped = false;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  const open = () => {
    if (stopped) return;
    try {
      es = new EventSource(`${API_PREFIX}/events/stream`);
    } catch (err) {
      handlers.onError?.(err as unknown as Event);
      return;
    }
    es.addEventListener('hello', () => handlers.onOpen?.());
    es.addEventListener('block', (ev) => {
      try { handlers.onBlock?.(JSON.parse((ev as MessageEvent).data)); } catch { /* ignore parse */ }
    });
    es.addEventListener('egress', (ev) => {
      try { handlers.onEgress?.(JSON.parse((ev as MessageEvent).data)); } catch { /* ignore parse */ }
    });
    es.addEventListener('bot', (ev) => {
      try { handlers.onBot?.(JSON.parse((ev as MessageEvent).data)); } catch { /* ignore parse */ }
    });
    es.onerror = (ev) => {
      handlers.onError?.(ev);
      // Reconnect after a backoff so transient network loss recovers.
      if (!stopped) {
        es?.close();
        es = null;
        reconnectTimer = setTimeout(open, 3000);
      }
    };
  };

  open();
  return () => {
    stopped = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    es?.close();
  };
}

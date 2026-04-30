package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"wewaf/internal/clientip"
)

// Config holds all WAF runtime settings.
type Config struct {
	// Proxy settings
	ListenAddr      string `json:"listen_addr"`      // e.g. ":8080"
	AdminAddr       string `json:"admin_addr"`       // e.g. ":8443"
	BackendURL      string `json:"backend_url"`      // e.g. "http://localhost:3000"
	TrustXFF        bool   `json:"trust_xff"`        // trust X-Forwarded-For header
	// TrustedProxies is the CIDR allowlist of upstream proxies whose
	// X-Forwarded-For / X-Real-Ip headers we honour. When empty AND
	// TrustXFF is true, the WAF falls back to the legacy left-most
	// behaviour and emits a startup warning. Production deployments
	// behind a CDN should always populate this with the CDN's egress
	// CIDRs so an attacker who reaches the WAF directly cannot spoof
	// the client IP via headers.
	TrustedProxies  []string `json:"trusted_proxies"`
	ReadTimeoutSec  int    `json:"read_timeout_sec"`
	WriteTimeoutSec int    `json:"write_timeout_sec"`

	// Resource limits (0 = unlimited / use all available)
	MaxCPUCores      int   `json:"max_cpu_cores"`      // GOMAXPROCS
	MaxMemoryMB      int64 `json:"max_memory_mb"`      // soft memory ceiling
	MaxConcurrentReq int   `json:"max_concurrent_req"` // connection semaphore
	MaxBodyBytes     int64 `json:"max_body_bytes"`     // max request body to inspect

	// Security thresholds
	BlockThreshold      int `json:"block_threshold"`      // score >= this -> block
	RateLimitRPS        int `json:"rate_limit_rps"`       // per-IP rate limit
	RateLimitBurst      int `json:"rate_limit_burst"`
	BruteForceWindowSec int `json:"brute_force_window_sec"`
	BruteForceThreshold int `json:"brute_force_threshold"`

	// Reputation-based auto-ban
	ReputationWindowSec      int `json:"reputation_window_sec"`       // default 600 (10 min)
	ReputationThreshold      int `json:"reputation_threshold"`        // default 5 blocks before auto-ban
	ReputationBanDurationSec int `json:"reputation_ban_duration_sec"` // default 3600 (1 hour)

	// Engine behaviour
	Mode         string   `json:"mode"`           // "active", "detection", "learning"
	LogLevel     string   `json:"log_level"`      // "debug", "info", "warn", "error"
	AuditLogPath string   `json:"audit_log_path"`
	RuleFiles    []string `json:"rule_files"`

	// Persistent history storage
	HistoryDir          string `json:"history_dir"`           // default "history"
	HistoryRotateHours  int    `json:"history_rotate_hours"`  // default 24
	HistoryBufferSize   int    `json:"history_buffer_size"`   // default 4096
	HistoryFlushSeconds int    `json:"history_flush_seconds"` // default 2

	// Egress proxy settings
	EgressEnabled         bool     `json:"egress_enabled"`
	EgressAddr            string   `json:"egress_addr"`
	EgressAllowlist       []string `json:"egress_allowlist"`
	EgressBlockPrivateIPs bool     `json:"egress_block_private_ips"`
	EgressMaxBodyBytes    int64    `json:"egress_max_body_bytes"`
	// Outbound response inspection: scan the first 256 KiB of each
	// forwarded response for credit-card numbers (Luhn-verified) and
	// common cloud-provider secret formats. Block rather than forward
	// when EgressExfilBlock is true; default is observe-only.
	EgressExfilInspect bool `json:"egress_exfil_inspect"`
	EgressExfilBlock   bool `json:"egress_exfil_block"`

	// Distributed threat mesh
	MeshEnabled           bool     `json:"mesh_enabled"`
	MeshPeers             []string `json:"mesh_peers"`
	MeshGossipIntervalSec int      `json:"mesh_gossip_interval_sec"`
	MeshAPIKey            string   `json:"mesh_api_key"`
	MeshSyncTimeoutSec    int      `json:"mesh_sync_timeout_sec"`

	// Response hardening
	SecurityHeadersEnabled bool `json:"security_headers_enabled"`
	// HSTS (Strict-Transport-Security). Only emitted when the backend is
	// reached over HTTPS; browsers ignore HSTS on plain HTTP anyway and
	// setting it on an http:// response is spec-non-compliant.
	HSTSEnabled         bool `json:"hsts_enabled"`
	HSTSMaxAgeSec       int  `json:"hsts_max_age_sec"`
	HSTSIncludeSubdoms  bool `json:"hsts_include_subdomains"`
	HSTSPreload         bool `json:"hsts_preload"`

	// Failsafe behaviour when the engine panics or the backend is unhealthy.
	// "closed" (default) returns 503 to fail secure; "open" forwards the
	// request unfiltered. Production deployments should keep this closed.
	FailsafeMode string `json:"failsafe_mode"` // "closed" | "open"

	// Circuit breaker for the backend. If the backend produces
	// ConsecutiveFailures errors in a row the breaker opens for
	// OpenTimeoutSec, during which the proxy short-circuits to 503.
	BreakerConsecutiveFailures int `json:"breaker_consecutive_failures"`
	BreakerOpenTimeoutSec      int `json:"breaker_open_timeout_sec"`

	// DDoS detection
	DDoSVolumetricBaseline      int     `json:"ddos_volumetric_baseline"`       // initial "normal" RPS guess, replaced by adaptive EMA after warmup
	DDoSVolumetricSpike         float64 `json:"ddos_volumetric_spike"`          // multiplier over baseline that counts as a spike
	DDoSConnRateThreshold       int     `json:"ddos_conn_rate_threshold"`       // per-IP conns in 10s to mitigate (default 300 — CDN-friendly)
	DDoSSlowReadBPS             int     `json:"ddos_slow_read_bps"`             // bytes/sec below which a slow read is flagged
	DDoSWarmupSeconds           int     `json:"ddos_warmup_seconds"`            // before adaptive baseline takes over
	DDoSMinAbsoluteRPS          int     `json:"ddos_min_absolute_rps"`          // floor: never flag under this RPS regardless of multiplier
	DDoSSpikeWindowsRequired    int     `json:"ddos_spike_windows_required"`    // consecutive spike windows before declaring attack
	DDoSCoolDownSeconds         int     `json:"ddos_cooldown_seconds"`          // after last spike before releasing attack state
	DDoSBotnetUniqueIPThreshold int     `json:"ddos_botnet_unique_ip_threshold"` // unique IPs on sensitive path in 60s to flag

	// Pre-WAF shaper — admission control that runs before rule evaluation.
	ShaperEnabled bool `json:"shaper_enabled"`
	ShaperMaxRPS  int  `json:"shaper_max_rps"`  // process-wide cap
	ShaperBurst   int  `json:"shaper_burst"`    // token bucket burst size

	// OWASP CRS-style paranoia level (1-4). Higher levels enable more
	// aggressive rules with more false-positive risk. Levels should be
	// raised gradually after running in detection mode.
	ParanoiaLevel int `json:"paranoia_level"`

	// CRSEnabled toggles the full OWASP CRS rule pack. Disable if you
	// only want the native WEWAF signatures.
	CRSEnabled bool `json:"crs_enabled"`

	// Backend transport tuning — the reverse proxy's outbound HTTP client.
	// Zero values keep hard-coded defaults (see proxy.newBackendTransport).
	BackendDialTimeoutMs           int `json:"backend_dial_timeout_ms"`
	BackendResponseHeaderTimeoutMs int `json:"backend_response_header_timeout_ms"`
	BackendTLSHandshakeTimeoutMs   int `json:"backend_tls_handshake_timeout_ms"`
	BackendMaxIdleConns            int `json:"backend_max_idle_conns"`
	BackendMaxConnsPerHost         int `json:"backend_max_conns_per_host"`

	// Compression defense. If enabled, the WAF decompresses gzip/br bodies
	// into a buffer for inspection, rejecting payloads whose decompressed
	// size exceeds CompressRatioCap * compressed size (classic zip-bomb
	// protection). MaxDecompressBytes caps the absolute decompressed size.
	DecompressInspect   bool  `json:"decompress_inspect"`
	DecompressRatioCap  int   `json:"decompress_ratio_cap"`  // default 100
	MaxDecompressBytes  int64 `json:"max_decompress_bytes"`  // default 64 MB

	// Per-rule telemetry. When enabled the engine counts matches per rule
	// ID so operators can see which rules are firing.
	PerRuleCounters bool `json:"per_rule_counters"`

	// IP reputation feed ingestion. Populates the BanList with published
	// DROP / tor-exit lists at the configured interval.
	IPReputationEnabled       bool     `json:"ip_reputation_enabled"`
	IPReputationRefreshMin    int      `json:"ip_reputation_refresh_min"` // default 360
	IPReputationFeeds         []string `json:"ip_reputation_feeds"`

	// Exponential-backoff bans. When enabled, repeat bans on the same IP
	// within a window double the ban duration (up to MaxBanDurationSec).
	BanBackoffEnabled       bool `json:"ban_backoff_enabled"`
	BanBackoffMultiplier    int  `json:"ban_backoff_multiplier"`
	BanBackoffWindowSec     int  `json:"ban_backoff_window_sec"`
	MaxBanDurationSec       int  `json:"max_ban_duration_sec"`

	// Session tracking + browser-integrity challenge + anomaly scoring.
	SessionTrackingEnabled    bool   `json:"session_tracking_enabled"`
	SessionCookieSecret       string `json:"session_cookie_secret"`
	SessionIdleTTLSec         int    `json:"session_idle_ttl_sec"`
	SessionMaxSessions        int    `json:"session_max_sessions"`
	SessionRequestRateCeiling int    `json:"session_request_rate_ceiling"`
	SessionPathCountCeiling   int    `json:"session_path_count_ceiling"`
	BrowserChallengeEnabled   bool   `json:"browser_challenge_enabled"`
	BrowserChallengeBlock     bool   `json:"browser_challenge_block"` // if true, failed challenge blocks; else score-only
	SessionBlockThreshold     int    `json:"session_block_threshold"` // risk score at/above which to block; 0 = never

	// Deep packet inspection — gRPC + WebSocket. When enabled, the
	// proxy pre-parses protocol framing before handing payloads to the
	// rule engine. Block-on-violation is separate so operators can
	// observe-first, enforce-second.
	GRPCInspect            bool `json:"grpc_inspect"`
	GRPCBlockOnError       bool `json:"grpc_block_on_error"`
	GRPCMaxFrames          int  `json:"grpc_max_frames"`
	GRPCMaxFrameBytes      int  `json:"grpc_max_frame_bytes"`
	// Fail-closed on compressed gRPC frames. The default scanner skips
	// extraction on compressed bodies (binary noise post-codec), which
	// is a clean rule-engine bypass when the operator wants every body
	// inspected. Turning this on rejects any compressed frame rather
	// than letting it through unscanned.
	GRPCBlockCompressed    bool `json:"grpc_block_compressed"`
	WebSocketInspect       bool     `json:"websocket_inspect"`
	WebSocketRequireSubproto bool   `json:"websocket_require_subprotocol"`
	WebSocketOriginAllowlist []string `json:"websocket_origin_allowlist"`
	WebSocketSubprotoAllowlist []string `json:"websocket_subprotocol_allowlist"`

	// Tamper-evident audit log — HMAC-chained, append-only.
	AuditEnabled  bool   `json:"audit_enabled"`
	AuditFilePath string `json:"audit_file_path"`
	AuditSecret   string `json:"audit_secret"`
	AuditRingSize int    `json:"audit_ring_size"`

	// GraphQL schema-aware validation.
	GraphQLEnabled            bool   `json:"graphql_enabled"`
	GraphQLBlockOnError       bool   `json:"graphql_block_on_error"`
	GraphQLMaxDepth           int    `json:"graphql_max_depth"`
	GraphQLMaxAliases         int    `json:"graphql_max_aliases"`
	GraphQLMaxFields          int    `json:"graphql_max_fields"`
	GraphQLSchemaFile         string `json:"graphql_schema_file"`
	GraphQLRoleHeader         string `json:"graphql_role_header"`
	GraphQLBlockSubscriptions bool   `json:"graphql_block_subscriptions"`

	// JA3 TLS fingerprinting. Native capture requires the proxy to
	// terminate TLS itself (TLSEnabled + cert/key). Edge mode reads the
	// hash from a header named JA3Header but only when the request comes
	// from a CIDR in JA3TrustedSources — anyone else's header is ignored.
	JA3Enabled         bool     `json:"ja3_enabled"`
	JA3HardBlock       bool     `json:"ja3_hard_block"`
	JA3Header          string   `json:"ja3_header"`           // e.g. "Cf-Ja3-Hash"
	JA3TrustedSources  []string `json:"ja3_trusted_sources"`  // CIDRs allowed to set JA3Header
	JA3CacheCapacity   int      `json:"ja3_cache_capacity"`
	JA3CacheTTLSec     int      `json:"ja3_cache_ttl_sec"`

	// Proof-of-work challenge for high-risk sessions. When the session
	// risk score reaches PoWTriggerScore and no valid PoW cookie is
	// present, the WAF returns the PoW gate page.
	PoWEnabled        bool   `json:"pow_enabled"`
	PoWTriggerScore   int    `json:"pow_trigger_score"`   // session score that triggers PoW
	PoWMinDifficulty  int    `json:"pow_min_difficulty"`  // bits, default 18
	PoWMaxDifficulty  int    `json:"pow_max_difficulty"`  // bits, default 24
	PoWTokenTTLSec    int    `json:"pow_token_ttl_sec"`   // server-issued challenge TTL
	PoWCookieTTLSec   int    `json:"pow_cookie_ttl_sec"`  // client-pass cookie TTL
	PoWSecret         string `json:"pow_secret"`          // HMAC key for PoW tokens (auto-generated if empty)
	// Adaptive (Tier-2) bit management. When enabled, the configured
	// min/max set the *envelope* and the AdaptiveTier picks the actual
	// difficulty per-request from session risk + per-IP fail history +
	// global load + JA4 rarity. Disabled = legacy fixed-suggest behaviour.
	PoWAdaptiveEnabled bool `json:"pow_adaptive_enabled"`
	PoWAdaptiveTier2Failures int `json:"pow_adaptive_tier2_failures"` // fails before escalation, default 5
	PoWAdaptiveTier2PenaltyBits int `json:"pow_adaptive_tier2_penalty_bits"` // bits added during escalation, default 3

	// Multi-dimensional rate limiter — runs alongside the per-IP one and
	// applies the strictest budget across IP/JA4/cookie/query-key
	// signature dimensions. Zero budget per dim disables that axis.
	MultiLimitEnabled    bool   `json:"multi_limit_enabled"`
	MultiLimitWindowSec  int    `json:"multi_limit_window_sec"`   // default 60
	MultiLimitIPRPM      int    `json:"multi_limit_ip_rpm"`       // 0 = disabled (per-IP limiter already exists)
	MultiLimitJA4RPM     int    `json:"multi_limit_ja4_rpm"`
	MultiLimitCookieRPM  int    `json:"multi_limit_cookie_rpm"`
	MultiLimitCookieName string `json:"multi_limit_cookie_name"`
	MultiLimitQueryRPM   int    `json:"multi_limit_query_rpm"`
	MultiLimitMaxEntries int    `json:"multi_limit_max_entries"`  // default 200000

	// Auto-updating threat-intel feeds. Toggling on starts the
	// supervisor that fetches FREE community lists (FireHOL, Spamhaus
	// DROP, SSLBL JA3, blocklist.de, ET compromised, mitchellkrogza
	// bad-UAs, CISA KEV) and merges entries into the runtime stores.
	IntelFeedsEnabled       bool     `json:"intel_feeds_enabled"`
	IntelFeedsCacheDir      string   `json:"intel_feeds_cache_dir"`       // default <history>/intel
	IntelFeedsLearningHours int      `json:"intel_feeds_learning_hours"`  // observe-only window for new entries; default 0 (off)
	IntelFeedsAllowSources  []string `json:"intel_feeds_allow_sources"`   // empty = all defaults; otherwise allowlist of source names

	modeAtomic atomic.Value // stores string for hot-swapping Mode without copying mutexes
	// mu protects runtime mutation of any non-atomic field (admin API POST
	// /api/config edits, config watcher hot-reloads). Snapshot() takes an
	// RLock to produce a torn-read-free copy.
	mu sync.RWMutex
}

// Lock / Unlock are exposed for callers that need to mutate multiple fields
// atomically (the admin API handler, the hot-reload watcher). Snapshot uses
// RLock internally. Most readers should prefer Snapshot().
func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }

// Default returns a safe baseline configuration.
func Default() *Config {
	c := &Config{
		ListenAddr:               ":8080",
		AdminAddr:                ":8443",
		BackendURL:               "http://localhost:3000",
		TrustXFF:                 false,
		TrustedProxies:           nil,
		ReadTimeoutSec:           30,
		WriteTimeoutSec:          30,
		MaxCPUCores:              runtime.NumCPU(),
		MaxMemoryMB:              0,
		MaxConcurrentReq:         10000,
		MaxBodyBytes:             10 * 1024 * 1024, // 10 MB
		BlockThreshold:           100,
		RateLimitRPS:             100,
		RateLimitBurst:           150,
		BruteForceWindowSec:      300,
		BruteForceThreshold:      10,
		ReputationWindowSec:      600,
		ReputationThreshold:      5,
		ReputationBanDurationSec: 3600,
		Mode:                     "active",
		LogLevel:                 "info",
		AuditLogPath:             "",
		RuleFiles:                []string{"rules.json"},
		HistoryDir:               "history",
		HistoryRotateHours:       168, // 7 days
		HistoryBufferSize:        4096,
		HistoryFlushSeconds:      2,
		EgressEnabled:            false,
		EgressAddr:               ":8081",
		EgressAllowlist:          []string{},
		EgressBlockPrivateIPs:    true,
		EgressMaxBodyBytes:       10 * 1024 * 1024,
		EgressExfilInspect:       false,
		EgressExfilBlock:         false,
		MeshEnabled:              false,
		MeshPeers:                []string{},
		MeshGossipIntervalSec:    60,
		MeshSyncTimeoutSec:       10,
		SecurityHeadersEnabled:   true,
		// HSTS defaults: opt-in. 180 days is the safe starting value most
		// guides recommend before ratcheting up to 2 years and preload.
		HSTSEnabled:        false,
		HSTSMaxAgeSec:      15552000,
		HSTSIncludeSubdoms: true,
		HSTSPreload:        false,

		FailsafeMode:               "closed",
		BreakerConsecutiveFailures: 10,
		BreakerOpenTimeoutSec:      30,
		// DDoS defaults are intentionally conservative — real attacks are
		// sustained, so we require multiple consecutive spike windows and
		// an absolute-rate floor to avoid flagging legitimate traffic spikes.
		DDoSVolumetricBaseline:      100,
		DDoSVolumetricSpike:         4.0,
		DDoSConnRateThreshold:       300,
		DDoSSlowReadBPS:             128,
		DDoSWarmupSeconds:           300,
		DDoSMinAbsoluteRPS:          100,
		DDoSSpikeWindowsRequired:    3,
		DDoSCoolDownSeconds:         60,
		DDoSBotnetUniqueIPThreshold: 200,
		// Shaper off by default — operators opt in once they've observed
		// their traffic profile.
		ShaperEnabled: false,
		ShaperMaxRPS:  2000,
		ShaperBurst:   4000,
		ParanoiaLevel: 1,
		CRSEnabled:    true,

		BackendDialTimeoutMs:           5000,
		BackendResponseHeaderTimeoutMs: 30000,
		BackendTLSHandshakeTimeoutMs:   10000,
		BackendMaxIdleConns:            200,
		BackendMaxConnsPerHost:         64,

		DecompressInspect:  true,
		DecompressRatioCap: 100,
		MaxDecompressBytes: 64 * 1024 * 1024,

		PerRuleCounters: true,

		IPReputationEnabled:    false,
		IPReputationRefreshMin: 360,
		IPReputationFeeds:      []string{},

		BanBackoffEnabled:    true,
		BanBackoffMultiplier: 2,
		BanBackoffWindowSec:  86400,
		MaxBanDurationSec:    7 * 24 * 3600,

		SessionTrackingEnabled:    false,
		SessionIdleTTLSec:         1800,
		SessionMaxSessions:        200000,
		SessionRequestRateCeiling: 600,
		SessionPathCountCeiling:   40,
		BrowserChallengeEnabled:   false,
		BrowserChallengeBlock:     false,
		SessionBlockThreshold:     0, // disabled by default — observe first

		GRPCInspect:            false,
		GRPCBlockOnError:       false,
		GRPCMaxFrames:          1024,
		GRPCMaxFrameBytes:      1 << 20,
		WebSocketInspect:       false,
		WebSocketRequireSubproto: false,
		WebSocketOriginAllowlist: []string{},
		WebSocketSubprotoAllowlist: []string{},

		AuditEnabled:  false,
		AuditFilePath: "audit.log",
		AuditRingSize: 256,

		GraphQLEnabled:            false,
		GraphQLBlockOnError:       false,
		GraphQLMaxDepth:           7,
		GraphQLMaxAliases:         10,
		GraphQLMaxFields:          200,
		GraphQLRoleHeader:         "X-User-Role",
		GraphQLBlockSubscriptions: false,

		// JA3 + PoW default to OFF. Both are heavy-hammer features that
		// need operator review of trust boundaries (JA3 edge header) and
		// UX impact (PoW solve time) before they're switched on.
		JA3Enabled:        false,
		JA3HardBlock:      false,
		JA3Header:         "",
		JA3TrustedSources: []string{},
		JA3CacheCapacity:  4096,
		JA3CacheTTLSec:    30,

		PoWEnabled:       false,
		PoWTriggerScore:  60, // 60 ≈ "high risk" per scoring.go — same line in the sand
		PoWMinDifficulty: 18,
		PoWMaxDifficulty: 24,
		PoWTokenTTLSec:   120,
		PoWCookieTTLSec:  3600,

		PoWAdaptiveEnabled:          false,
		PoWAdaptiveTier2Failures:    5,
		PoWAdaptiveTier2PenaltyBits: 3,

		MultiLimitEnabled:    false,
		MultiLimitWindowSec:  60,
		MultiLimitIPRPM:      0,
		MultiLimitJA4RPM:     0,
		MultiLimitCookieRPM:  0,
		MultiLimitCookieName: "session",
		MultiLimitQueryRPM:   0,
		MultiLimitMaxEntries: 200000,

		IntelFeedsEnabled:       false,
		IntelFeedsCacheDir:      "",
		IntelFeedsLearningHours: 0,
		IntelFeedsAllowSources:  nil,
	}
	c.modeAtomic.Store(c.Mode)
	return c
}

// Load reads a JSON config file and overlays it on top of defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	cfg.modeAtomic.Store(cfg.Mode)
	return cfg, nil
}

// Validate checks that the configuration is sane.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if c.BackendURL == "" {
		return fmt.Errorf("config: backend_url is required")
	}
	if c.BlockThreshold <= 0 {
		c.BlockThreshold = 100
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 10 * 1024 * 1024
	}
	if c.MaxConcurrentReq <= 0 {
		c.MaxConcurrentReq = 10000
	}
	if c.Mode != "active" && c.Mode != "detection" && c.Mode != "learning" {
		c.Mode = "active"
	}
	if c.ReputationWindowSec <= 0 {
		c.ReputationWindowSec = 600
	}
	if c.ReputationThreshold <= 0 {
		c.ReputationThreshold = 5
	}
	if c.ReputationBanDurationSec <= 0 {
		c.ReputationBanDurationSec = 3600
	}
	if c.ReputationBanDurationSec < 60 {
		c.ReputationBanDurationSec = 60
	}
	if c.HistoryDir == "" {
		c.HistoryDir = "history"
	}
	if c.HistoryRotateHours <= 0 {
		c.HistoryRotateHours = 168
	}
	if c.HistoryBufferSize <= 0 {
		c.HistoryBufferSize = 4096
	}
	if c.HistoryFlushSeconds <= 0 {
		c.HistoryFlushSeconds = 2
	}
	if c.EgressAddr == "" {
		c.EgressAddr = ":8081"
	}
	if c.EgressMaxBodyBytes <= 0 {
		c.EgressMaxBodyBytes = 10 * 1024 * 1024
	}
	if c.MeshGossipIntervalSec <= 0 {
		c.MeshGossipIntervalSec = 60
	}
	if c.MeshSyncTimeoutSec <= 0 {
		c.MeshSyncTimeoutSec = 10
	}
	if c.FailsafeMode != "open" && c.FailsafeMode != "closed" {
		c.FailsafeMode = "closed"
	}
	if c.BreakerConsecutiveFailures <= 0 {
		c.BreakerConsecutiveFailures = 10
	}
	if c.BreakerOpenTimeoutSec <= 0 {
		c.BreakerOpenTimeoutSec = 30
	}
	if c.DDoSVolumetricBaseline <= 0 {
		c.DDoSVolumetricBaseline = 500
	}
	if c.DDoSVolumetricSpike <= 0 {
		c.DDoSVolumetricSpike = 4.0
	}
	if c.DDoSConnRateThreshold <= 0 {
		c.DDoSConnRateThreshold = 100
	}
	if c.DDoSSlowReadBPS <= 0 {
		c.DDoSSlowReadBPS = 128
	}
	if c.DDoSWarmupSeconds <= 0 {
		c.DDoSWarmupSeconds = 300
	}
	if c.DDoSMinAbsoluteRPS <= 0 {
		c.DDoSMinAbsoluteRPS = 100
	}
	if c.DDoSSpikeWindowsRequired <= 0 {
		c.DDoSSpikeWindowsRequired = 3
	}
	if c.DDoSCoolDownSeconds <= 0 {
		c.DDoSCoolDownSeconds = 60
	}
	if c.DDoSBotnetUniqueIPThreshold <= 0 {
		c.DDoSBotnetUniqueIPThreshold = 200
	}
	if c.ShaperMaxRPS <= 0 {
		c.ShaperMaxRPS = 2000
	}
	if c.ShaperBurst <= 0 {
		c.ShaperBurst = c.ShaperMaxRPS * 2
	}
	if c.ParanoiaLevel <= 0 {
		c.ParanoiaLevel = 1
	}
	if c.ParanoiaLevel > 4 {
		c.ParanoiaLevel = 4
	}
	if c.BackendDialTimeoutMs <= 0 {
		c.BackendDialTimeoutMs = 5000
	}
	if c.BackendResponseHeaderTimeoutMs <= 0 {
		c.BackendResponseHeaderTimeoutMs = 30000
	}
	if c.BackendTLSHandshakeTimeoutMs <= 0 {
		c.BackendTLSHandshakeTimeoutMs = 10000
	}
	if c.BackendMaxIdleConns <= 0 {
		c.BackendMaxIdleConns = 200
	}
	if c.BackendMaxConnsPerHost <= 0 {
		c.BackendMaxConnsPerHost = 64
	}
	if c.DecompressRatioCap <= 0 {
		c.DecompressRatioCap = 100
	}
	if c.MaxDecompressBytes <= 0 {
		c.MaxDecompressBytes = 64 * 1024 * 1024
	}
	if c.IPReputationRefreshMin <= 0 {
		c.IPReputationRefreshMin = 360
	}
	if c.BanBackoffMultiplier <= 0 {
		c.BanBackoffMultiplier = 2
	}
	if c.BanBackoffWindowSec <= 0 {
		c.BanBackoffWindowSec = 86400
	}
	if c.MaxBanDurationSec <= 0 {
		c.MaxBanDurationSec = 7 * 24 * 3600
	}
	if c.SessionIdleTTLSec <= 0 {
		c.SessionIdleTTLSec = 1800
	}
	if c.SessionMaxSessions <= 0 {
		c.SessionMaxSessions = 200000
	}
	if c.SessionRequestRateCeiling <= 0 {
		c.SessionRequestRateCeiling = 600
	}
	if c.SessionPathCountCeiling <= 0 {
		c.SessionPathCountCeiling = 40
	}
	if c.GraphQLMaxDepth <= 0 {
		c.GraphQLMaxDepth = 7
	}
	if c.GraphQLMaxAliases <= 0 {
		c.GraphQLMaxAliases = 10
	}
	if c.GraphQLMaxFields <= 0 {
		c.GraphQLMaxFields = 200
	}
	if c.GraphQLRoleHeader == "" {
		c.GraphQLRoleHeader = "X-User-Role"
	}

	// JA3 clamping. Out-of-range cache values get the defaults; an empty
	// header with a non-empty trust list is a config typo (the operator
	// turned on edge mode but didn't name the header) so we leave it
	// alone — the runtime treats empty header as "edge mode disabled".
	if c.JA3CacheCapacity <= 0 {
		c.JA3CacheCapacity = 4096
	}
	if c.JA3CacheCapacity > 1_000_000 {
		// Cap to avoid silent OOM if someone fat-fingers the config.
		c.JA3CacheCapacity = 1_000_000
	}
	if c.JA3CacheTTLSec <= 0 {
		c.JA3CacheTTLSec = 30
	}
	if c.JA3CacheTTLSec > 3600 {
		c.JA3CacheTTLSec = 3600
	}

	// PoW clamping. We enforce difficulty bounds here so the proxy
	// doesn't have to re-check on every Issue call. The 32-bit hard cap
	// is a UX safeguard — at 32 bits, mobile clients would solve in
	// minutes and abandon the page.
	if c.PoWMinDifficulty < 8 {
		c.PoWMinDifficulty = 18
	}
	if c.PoWMaxDifficulty < c.PoWMinDifficulty {
		c.PoWMaxDifficulty = c.PoWMinDifficulty
	}
	if c.PoWMaxDifficulty > 32 {
		c.PoWMaxDifficulty = 32
	}
	if c.PoWTriggerScore <= 0 {
		c.PoWTriggerScore = 60
	}
	if c.PoWTriggerScore > 100 {
		c.PoWTriggerScore = 100
	}
	if c.PoWTokenTTLSec <= 0 {
		c.PoWTokenTTLSec = 120
	}
	if c.PoWCookieTTLSec <= 0 {
		c.PoWCookieTTLSec = 3600
	}

	if c.PoWAdaptiveTier2Failures <= 0 {
		c.PoWAdaptiveTier2Failures = 5
	}
	if c.PoWAdaptiveTier2PenaltyBits <= 0 {
		c.PoWAdaptiveTier2PenaltyBits = 3
	}
	if c.PoWAdaptiveTier2PenaltyBits > 10 {
		// Adding more than 10 bits over the floor would push every
		// escalated user past the safety cap; clamp instead of
		// rejecting the config so a fat-finger doesn't brick the WAF.
		c.PoWAdaptiveTier2PenaltyBits = 10
	}

	if c.MultiLimitWindowSec <= 0 {
		c.MultiLimitWindowSec = 60
	}
	if c.MultiLimitMaxEntries <= 0 {
		c.MultiLimitMaxEntries = 200000
	}
	if c.MultiLimitMaxEntries > 5_000_000 {
		c.MultiLimitMaxEntries = 5_000_000
	}
	if c.MultiLimitCookieName == "" {
		c.MultiLimitCookieName = "session"
	}

	if c.IntelFeedsLearningHours < 0 {
		c.IntelFeedsLearningHours = 0
	}
	if c.IntelFeedsLearningHours > 24*30 {
		c.IntelFeedsLearningHours = 24 * 30
	}
	// Reject malformed trusted_proxies entries up front so a typo in
	// production config doesn't silently disable the trust-gate at
	// runtime.
	if _, err := clientip.New(c.TrustXFF, c.TrustedProxies); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// BuildClientIPExtractor returns a *clientip.Extractor configured from
// the current TrustXFF / TrustedProxies values. Validate() must have
// been called first; otherwise a malformed CIDR will surface as a
// non-nil error here too.
func (c *Config) BuildClientIPExtractor() (*clientip.Extractor, error) {
	return clientip.New(c.TrustXFF, c.TrustedProxies)
}

// secretRedactedPlaceholder marks a config field that has a non-empty
// secret in the running daemon. The UI uses presence of this exact
// string to render "secret is configured" without showing the value;
// any POST that sends this placeholder back is treated as "no change"
// by the admin API so a round-trip through the form doesn't corrupt
// the secret to a literal "REDACTED".
const secretRedactedPlaceholder = "[REDACTED]"

// IsRedactedPlaceholder reports whether v is the placeholder used by
// RedactSecrets, so the admin POST handler can ignore it on round-trip.
func IsRedactedPlaceholder(v string) bool { return v == secretRedactedPlaceholder }

// RedactSecrets returns a snapshot with every credential / signing-key
// field replaced by a stable placeholder. /api/config GET returns this
// flavour so authenticated UI sessions can present "configured" /
// "not configured" without an attacker who lands on the admin port
// (or anyone reading a session-replay) walking off with the running
// HMAC keys. The placeholder is deliberately non-empty so the UI can
// distinguish "configured" from "blank"; it's also picked specifically
// so a paste-back round-trip is detectable in the POST handler.
//
// We never include the production secret value in any UI / SDK / log
// surface — the only place it lives is config.json on disk.
func (c *Config) RedactSecrets() *Config {
	cp := c.Snapshot()
	if cp == nil {
		return nil
	}
	if cp.SessionCookieSecret != "" {
		cp.SessionCookieSecret = secretRedactedPlaceholder
	}
	if cp.AuditSecret != "" {
		cp.AuditSecret = secretRedactedPlaceholder
	}
	if cp.PoWSecret != "" {
		cp.PoWSecret = secretRedactedPlaceholder
	}
	if cp.MeshAPIKey != "" {
		cp.MeshAPIKey = secretRedactedPlaceholder
	}
	return cp
}

// Snapshot returns a pointer to a shallow copy for safe read-only access.
// Do not modify the returned value. Takes an RLock so concurrent writers
// (admin API, hot-reload) can't produce a torn read of int64 / slice fields.
func (c *Config) Snapshot() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := &Config{
		ListenAddr:               c.ListenAddr,
		AdminAddr:                c.AdminAddr,
		BackendURL:               c.BackendURL,
		TrustXFF:                 c.TrustXFF,
		TrustedProxies:           append([]string(nil), c.TrustedProxies...),
		ReadTimeoutSec:           c.ReadTimeoutSec,
		WriteTimeoutSec:          c.WriteTimeoutSec,
		MaxCPUCores:              c.MaxCPUCores,
		MaxMemoryMB:              c.MaxMemoryMB,
		MaxConcurrentReq:         c.MaxConcurrentReq,
		MaxBodyBytes:             c.MaxBodyBytes,
		BlockThreshold:           c.BlockThreshold,
		RateLimitRPS:             c.RateLimitRPS,
		RateLimitBurst:           c.RateLimitBurst,
		BruteForceWindowSec:      c.BruteForceWindowSec,
		BruteForceThreshold:      c.BruteForceThreshold,
		ReputationWindowSec:      c.ReputationWindowSec,
		ReputationThreshold:      c.ReputationThreshold,
		ReputationBanDurationSec: c.ReputationBanDurationSec,
		Mode:                     c.ModeSnapshot(),
		LogLevel:                 c.LogLevel,
		AuditLogPath:             c.AuditLogPath,
		RuleFiles:                make([]string, len(c.RuleFiles)),
		HistoryDir:               c.HistoryDir,
		HistoryRotateHours:       c.HistoryRotateHours,
		HistoryBufferSize:        c.HistoryBufferSize,
		HistoryFlushSeconds:      c.HistoryFlushSeconds,
		EgressEnabled:            c.EgressEnabled,
		EgressAddr:               c.EgressAddr,
		EgressAllowlist:          make([]string, len(c.EgressAllowlist)),
		EgressBlockPrivateIPs:    c.EgressBlockPrivateIPs,
		EgressMaxBodyBytes:       c.EgressMaxBodyBytes,
		EgressExfilInspect:       c.EgressExfilInspect,
		EgressExfilBlock:         c.EgressExfilBlock,
		MeshEnabled:              c.MeshEnabled,
		MeshPeers:                make([]string, len(c.MeshPeers)),
		MeshGossipIntervalSec:    c.MeshGossipIntervalSec,
		MeshAPIKey:               c.MeshAPIKey,
		MeshSyncTimeoutSec:       c.MeshSyncTimeoutSec,
		SecurityHeadersEnabled:   c.SecurityHeadersEnabled,
		HSTSEnabled:              c.HSTSEnabled,
		HSTSMaxAgeSec:            c.HSTSMaxAgeSec,
		HSTSIncludeSubdoms:       c.HSTSIncludeSubdoms,
		HSTSPreload:              c.HSTSPreload,

		FailsafeMode:                c.FailsafeMode,
		BreakerConsecutiveFailures:  c.BreakerConsecutiveFailures,
		BreakerOpenTimeoutSec:       c.BreakerOpenTimeoutSec,
		DDoSVolumetricBaseline:      c.DDoSVolumetricBaseline,
		DDoSVolumetricSpike:         c.DDoSVolumetricSpike,
		DDoSConnRateThreshold:       c.DDoSConnRateThreshold,
		DDoSSlowReadBPS:             c.DDoSSlowReadBPS,
		DDoSWarmupSeconds:           c.DDoSWarmupSeconds,
		DDoSMinAbsoluteRPS:          c.DDoSMinAbsoluteRPS,
		DDoSSpikeWindowsRequired:    c.DDoSSpikeWindowsRequired,
		DDoSCoolDownSeconds:         c.DDoSCoolDownSeconds,
		DDoSBotnetUniqueIPThreshold: c.DDoSBotnetUniqueIPThreshold,
		ShaperEnabled:               c.ShaperEnabled,
		ShaperMaxRPS:                c.ShaperMaxRPS,
		ShaperBurst:                 c.ShaperBurst,
		ParanoiaLevel:               c.ParanoiaLevel,
		CRSEnabled:                  c.CRSEnabled,

		BackendDialTimeoutMs:           c.BackendDialTimeoutMs,
		BackendResponseHeaderTimeoutMs: c.BackendResponseHeaderTimeoutMs,
		BackendTLSHandshakeTimeoutMs:   c.BackendTLSHandshakeTimeoutMs,
		BackendMaxIdleConns:            c.BackendMaxIdleConns,
		BackendMaxConnsPerHost:         c.BackendMaxConnsPerHost,

		DecompressInspect:  c.DecompressInspect,
		DecompressRatioCap: c.DecompressRatioCap,
		MaxDecompressBytes: c.MaxDecompressBytes,

		PerRuleCounters: c.PerRuleCounters,

		IPReputationEnabled:    c.IPReputationEnabled,
		IPReputationRefreshMin: c.IPReputationRefreshMin,
		IPReputationFeeds:      append([]string(nil), c.IPReputationFeeds...),

		BanBackoffEnabled:    c.BanBackoffEnabled,
		BanBackoffMultiplier: c.BanBackoffMultiplier,
		BanBackoffWindowSec:  c.BanBackoffWindowSec,
		MaxBanDurationSec:    c.MaxBanDurationSec,

		SessionTrackingEnabled:    c.SessionTrackingEnabled,
		SessionCookieSecret:       c.SessionCookieSecret,
		SessionIdleTTLSec:         c.SessionIdleTTLSec,
		SessionMaxSessions:        c.SessionMaxSessions,
		SessionRequestRateCeiling: c.SessionRequestRateCeiling,
		SessionPathCountCeiling:   c.SessionPathCountCeiling,
		BrowserChallengeEnabled:   c.BrowserChallengeEnabled,
		BrowserChallengeBlock:     c.BrowserChallengeBlock,
		SessionBlockThreshold:     c.SessionBlockThreshold,

		GRPCInspect:              c.GRPCInspect,
		GRPCBlockOnError:         c.GRPCBlockOnError,
		GRPCMaxFrames:            c.GRPCMaxFrames,
		GRPCMaxFrameBytes:        c.GRPCMaxFrameBytes,
		GRPCBlockCompressed:      c.GRPCBlockCompressed,
		WebSocketInspect:         c.WebSocketInspect,
		WebSocketRequireSubproto: c.WebSocketRequireSubproto,
		WebSocketOriginAllowlist: append([]string(nil), c.WebSocketOriginAllowlist...),
		WebSocketSubprotoAllowlist: append([]string(nil), c.WebSocketSubprotoAllowlist...),

		AuditEnabled:  c.AuditEnabled,
		AuditFilePath: c.AuditFilePath,
		AuditSecret:   c.AuditSecret,
		AuditRingSize: c.AuditRingSize,

		GraphQLEnabled:            c.GraphQLEnabled,
		GraphQLBlockOnError:       c.GraphQLBlockOnError,
		GraphQLMaxDepth:           c.GraphQLMaxDepth,
		GraphQLMaxAliases:         c.GraphQLMaxAliases,
		GraphQLMaxFields:          c.GraphQLMaxFields,
		GraphQLSchemaFile:         c.GraphQLSchemaFile,
		GraphQLRoleHeader:         c.GraphQLRoleHeader,
		GraphQLBlockSubscriptions: c.GraphQLBlockSubscriptions,

		JA3Enabled:        c.JA3Enabled,
		JA3HardBlock:      c.JA3HardBlock,
		JA3Header:         c.JA3Header,
		JA3TrustedSources: append([]string(nil), c.JA3TrustedSources...),
		JA3CacheCapacity:  c.JA3CacheCapacity,
		JA3CacheTTLSec:    c.JA3CacheTTLSec,

		PoWEnabled:       c.PoWEnabled,
		PoWTriggerScore:  c.PoWTriggerScore,
		PoWMinDifficulty: c.PoWMinDifficulty,
		PoWMaxDifficulty: c.PoWMaxDifficulty,
		PoWTokenTTLSec:   c.PoWTokenTTLSec,
		PoWCookieTTLSec:  c.PoWCookieTTLSec,
		PoWSecret:        c.PoWSecret,

		PoWAdaptiveEnabled:          c.PoWAdaptiveEnabled,
		PoWAdaptiveTier2Failures:    c.PoWAdaptiveTier2Failures,
		PoWAdaptiveTier2PenaltyBits: c.PoWAdaptiveTier2PenaltyBits,

		MultiLimitEnabled:    c.MultiLimitEnabled,
		MultiLimitWindowSec:  c.MultiLimitWindowSec,
		MultiLimitIPRPM:      c.MultiLimitIPRPM,
		MultiLimitJA4RPM:     c.MultiLimitJA4RPM,
		MultiLimitCookieRPM:  c.MultiLimitCookieRPM,
		MultiLimitCookieName: c.MultiLimitCookieName,
		MultiLimitQueryRPM:   c.MultiLimitQueryRPM,
		MultiLimitMaxEntries: c.MultiLimitMaxEntries,

		IntelFeedsEnabled:       c.IntelFeedsEnabled,
		IntelFeedsCacheDir:      c.IntelFeedsCacheDir,
		IntelFeedsLearningHours: c.IntelFeedsLearningHours,
		IntelFeedsAllowSources:  append([]string(nil), c.IntelFeedsAllowSources...),
	}
	copy(cp.RuleFiles, c.RuleFiles)
	copy(cp.EgressAllowlist, c.EgressAllowlist)
	copy(cp.MeshPeers, c.MeshPeers)
	cp.modeAtomic = atomic.Value{}
	cp.modeAtomic.Store(cp.Mode)
	return cp
}

// SetMode updates the WAF mode at runtime.
func (c *Config) SetMode(m string) {
	c.modeAtomic.Store(m)
}

// ModeSnapshot returns the current mode safely.
func (c *Config) ModeSnapshot() string {
	v := c.modeAtomic.Load()
	if s, ok := v.(string); ok {
		return s
	}
	return c.Mode
}

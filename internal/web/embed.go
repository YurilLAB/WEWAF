package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	stdnet "net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"strconv"

	"wewaf/internal/audit"
	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/core"
	"wewaf/internal/graphql"
	"wewaf/internal/history"
	"wewaf/internal/host"
	"wewaf/internal/intel"
	"wewaf/internal/limits"
	"wewaf/internal/pow"
	"wewaf/internal/proxy"
	"wewaf/internal/session"
	"wewaf/internal/setup"
	"wewaf/internal/ssl"
	"wewaf/internal/telemetry"
	"wewaf/internal/watchdog"
	"wewaf/internal/zerotrust"
)

//go:embed all:dist
var distFS embed.FS

// Server serves the embedded UI and JSON APIs.
type Server struct {
	cfg        *config.Config
	metrics    *telemetry.Metrics
	rulesFn    func() []map[string]interface{}
	banList    *core.BanList
	host       *host.Collector
	connection *connection.Manager
	ssl        *ssl.Manager
	history    *history.Store
	proxy      *proxy.WAFProxy
	checker    *setup.Checker
	watchdog   *watchdog.Watchdog
	sessions   *session.Tracker
	graphql    *graphql.Validator
	audit      *audit.Chain
	pow        *pow.Issuer
	powAdapt   *pow.AdaptiveTier
	intelMgr   *intel.Manager
	multiLim   *limits.MultiLimiter

	meshEnabled  bool
	meshPeers    []string
	meshAPIKey   string
	meshLastSync time.Time
	meshMu       sync.RWMutex

	// Recent engine errors ring buffer for the Errors page.
	errMu     sync.Mutex
	errBuf    []ErrorEvent
	errBufCap int
}

// ErrorEvent is one recorded engine error surfaced to the UI.
type ErrorEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
}

// RecordError appends an error to the server's recent-errors ring.
func (s *Server) RecordError(source, message, requestID string) {
	if s == nil {
		return
	}
	ev := ErrorEvent{
		Timestamp: time.Now().UTC(),
		Source:    source,
		Message:   truncString(message, 1024),
		RequestID: requestID,
	}
	cap := s.errBufCap
	if cap <= 0 {
		cap = 200
	}
	s.errMu.Lock()
	s.errBuf = append(s.errBuf, ev)
	if len(s.errBuf) > cap {
		over := len(s.errBuf) - cap
		copy(s.errBuf, s.errBuf[over:])
		s.errBuf = s.errBuf[:cap]
	}
	s.errMu.Unlock()
}

func truncString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// AttachWatchdog wires the watchdog into the server so its snapshot is
// served at /api/health/detail.
func (s *Server) AttachWatchdog(w *watchdog.Watchdog) {
	if s == nil {
		return
	}
	s.watchdog = w
}

// Deps wires optional subsystems into the admin server.
type Deps struct {
	Config         *config.Config
	Metrics        *telemetry.Metrics
	RulesFn        func() []map[string]interface{}
	BanList        *core.BanList
	Host           *host.Collector
	Connection     *connection.Manager
	SSL            *ssl.Manager
	History        *history.Store
	Proxy          *proxy.WAFProxy
	SessionTracker *session.Tracker
	GraphQL        *graphql.Validator
	Audit          *audit.Chain
	PoW            *pow.Issuer
	PoWAdaptive    *pow.AdaptiveTier
	Intel          *intel.Manager
	MultiLimit     *limits.MultiLimiter

	MeshEnabled bool
	MeshPeers   []string
	MeshAPIKey  string
}

// NewServer creates the admin web server.
func NewServer(d Deps) *Server {
	checker := setup.New(d.Config, d.Connection, d.History, d.SSL, d.RulesFn)
	return &Server{
		cfg:        d.Config,
		metrics:    d.Metrics,
		rulesFn:    d.RulesFn,
		banList:    d.BanList,
		host:       d.Host,
		connection: d.Connection,
		ssl:        d.SSL,
		history:    d.History,
		proxy:      d.Proxy,
		checker:    checker,
		sessions:   d.SessionTracker,
		graphql:    d.GraphQL,
		audit:      d.Audit,
		pow:        d.PoW,
		powAdapt:   d.PoWAdaptive,
		intelMgr:   d.Intel,
		multiLim:   d.MultiLimit,
		errBufCap:  200,
		errBuf:     make([]ErrorEvent, 0, 200),

		meshEnabled: d.MeshEnabled,
		meshPeers:   d.MeshPeers,
		meshAPIKey:  d.MeshAPIKey,
	}
}

// RegisterRoutes wires all admin endpoints and the SPA handler.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	api := http.NewServeMux()
	api.HandleFunc("/api/metrics", s.handleMetrics)
	api.HandleFunc("/api/stats", s.handleStats)
	api.HandleFunc("/api/config", s.handleConfig)
	api.HandleFunc("/api/blocks", s.handleBlocks)
	api.HandleFunc("/api/traffic", s.handleTraffic)
	api.HandleFunc("/api/rules", s.handleRules)
	api.HandleFunc("/api/health", s.handleHealth)
	api.HandleFunc("/api/bans", s.handleBans)

	// Host telemetry.
	api.HandleFunc("/api/host/stats", s.handleHostStats)
	api.HandleFunc("/api/host/resources", s.handleHostResources)

	// Connection management.
	api.HandleFunc("/api/connection/status", s.handleConnectionStatus)
	api.HandleFunc("/api/connection/config", s.handleConnectionConfig)
	api.HandleFunc("/api/connection/test", s.handleConnectionTest)
	api.HandleFunc("/api/connection/history", s.handleConnectionHistory)
	api.HandleFunc("/api/connection/events", s.handleConnectionEvents)

	// SSL / TLS.
	api.HandleFunc("/api/ssl/certificates", s.handleSSLCertificates)
	api.HandleFunc("/api/ssl/certificates/", s.handleSSLCertificateByID)
	api.HandleFunc("/api/ssl/config", s.handleSSLConfig)

	// Historical telemetry (queries the on-disk SQLite rotation set).
	api.HandleFunc("/api/history/databases", s.handleHistoryDatabases)
	api.HandleFunc("/api/history/events", s.handleHistoryEvents)
	api.HandleFunc("/api/history/ips", s.handleHistoryIPs)
	api.HandleFunc("/api/history/traffic", s.handleHistoryTraffic)
	api.HandleFunc("/api/history/stats", s.handleHistoryStats)

	// Convenience aliases the page components expect.
	api.HandleFunc("/api/requests", s.handleRecentRequests)
	api.HandleFunc("/api/ips", s.handleRecentIPs)

	// Rate-limit + resource configuration.
	api.HandleFunc("/api/ratelimit/config", s.handleRateLimitConfig)

	// Distributed threat mesh
	api.HandleFunc("/api/mesh/status", s.handleMeshStatus)
	api.HandleFunc("/api/mesh/sync", s.handleMeshSync)
	api.HandleFunc("/api/mesh/peers", s.handleMeshPeers)

	// Egress proxy
	api.HandleFunc("/api/egress/status", s.handleEgressStatus)
	api.HandleFunc("/api/egress/recent", s.handleEgressRecent)

	// Bot detections
	api.HandleFunc("/api/bots/detected", s.handleBotsDetected)

	// Network monitoring — live bandwidth, byte totals, status distribution.
	api.HandleFunc("/api/network/summary", s.handleNetworkSummary)
	api.HandleFunc("/api/network/top-paths", s.handleNetworkTopPaths)
	api.HandleFunc("/api/network/top-ips", s.handleNetworkTopIPs)

	// IP Intelligence — per-IP insights + one-click auto-mitigation.
	api.HandleFunc("/api/ip/", s.handleIPInsights)
	api.HandleFunc("/api/ip-auto-mitigate", s.handleAutoMitigate)

	// Live events — Server-Sent Events stream of blocks/egress/bots.
	api.HandleFunc("/api/events/stream", s.handleEventsStream)

	// DDoS + circuit-breaker + shaper stats.
	api.HandleFunc("/api/ddos/stats", s.handleDDoSStats)
	api.HandleFunc("/api/breaker/stats", s.handleBreakerStats)
	api.HandleFunc("/api/shaper/stats", s.handleShaperStats)

	// Zero-trust path policies.
	api.HandleFunc("/api/zerotrust/policies", s.handleZeroTrustPolicies)
	api.HandleFunc("/api/zerotrust/templates", s.handleZeroTrustTemplates)

	// Setup checks — self-validating Next Steps.
	api.HandleFunc("/api/setup/checks/dns", s.handleSetupCheckDNS)
	api.HandleFunc("/api/setup/checks/origin", s.handleSetupCheckOrigin)
	api.HandleFunc("/api/setup/checks/ssl", s.handleSetupCheckSSL)
	api.HandleFunc("/api/setup/checks/traffic", s.handleSetupCheckTraffic)
	api.HandleFunc("/api/setup/checks/rules", s.handleSetupCheckRules)
	api.HandleFunc("/api/setup/checks/history", s.handleSetupCheckHistory)
	api.HandleFunc("/api/setup/checks/all", s.handleSetupCheckAll)

	// Recent engine errors for the ops panel.
	api.HandleFunc("/api/errors", s.handleErrors)

	// Per-subsystem health from the watchdog.
	api.HandleFunc("/api/health/detail", s.handleHealthDetail)

	// Session tracking + browser integrity (authenticated admin endpoints).
	api.HandleFunc("/api/dpi/stats", safeSessionHandler("dpi-stats", s.handleDPIStats))
	api.HandleFunc("/api/ja3/stats", safeSessionHandler("ja3-stats", s.handleJA3Stats))
	api.HandleFunc("/api/pow/stats", safeSessionHandler("pow-stats", s.handlePoWStats))
	api.HandleFunc("/api/pow/adaptive", safeSessionHandler("pow-adaptive", s.handlePoWAdaptiveStats))
	api.HandleFunc("/api/intel/stats", safeSessionHandler("intel-stats", s.handleIntelStats))
	api.HandleFunc("/api/multilimit/stats", safeSessionHandler("multilimit-stats", s.handleMultiLimitStats))
	api.HandleFunc("/api/audit/verify", safeSessionHandler("audit-verify", s.handleAuditVerify))
	api.HandleFunc("/api/audit/tail", safeSessionHandler("audit-tail", s.handleAuditTail))
	api.HandleFunc("/api/sessions", safeSessionHandler("sessions", s.handleSessions))
	api.HandleFunc("/api/sessions/", safeSessionHandler("session-detail", s.handleSessionByID))
	api.HandleFunc("/api/graphql/stats", safeSessionHandler("graphql-stats", s.handleGraphQLStats))
	api.HandleFunc("/api/graphql/recent", safeSessionHandler("graphql-recent", s.handleGraphQLRecent))

	mux.Handle("/api/", s.withCORS(s.withAuth(api)))

	// Prometheus scrape endpoint — unauthenticated on the admin port because
	// every Prometheus server expects /metrics without a token; operators
	// running on a hostile network should put this behind a firewall or wrap
	// with withAuth as appropriate.
	mux.HandleFunc("/metrics", s.handlePrometheus)
	api.HandleFunc("/api/rules/counters", s.handleRuleCounters)

	// The browser-challenge + beacon JS are served on a separate prefix
	// that bypasses auth — they're public (served to every page visitor)
	// and CORS-open (the JS runs on the protected site, not the admin UI).
	mux.HandleFunc("/api/browser-challenge.js", safeSessionHandler("challenge-js", s.handleBrowserChallengeJS))
	mux.HandleFunc("/api/browser-beacon.js", safeSessionHandler("beacon-js", s.handleBrowserBeaconJS))
	mux.HandleFunc("/api/browser-challenge/verify", safeSessionHandler("challenge-verify", s.handleBrowserChallengeVerify))
	mux.HandleFunc("/api/session/beacon", safeSessionHandler("session-beacon", s.handleSessionBeacon))
	// Proof-of-work challenge — public, no auth, served on the protected
	// origin like the browser-challenge assets.
	mux.HandleFunc("/api/pow.js", safeSessionHandler("pow-js", s.handlePowJS))
	mux.HandleFunc("/api/pow/verify", safeSessionHandler("pow-verify", s.handlePowVerify))

	// Serve the embedded SPA.
	spaFS, err := fs.Sub(distFS, "dist")
	if err != nil {
		log.Printf("web: embedded dist missing: %v", err)
		spaFS = distFS
	}
	mux.Handle("/", s.spaHandler(spaFS))
}

// spaHandler serves the Vite build output, falling back to index.html for
// client-side routes so React Router can handle them.
func (s *Server) spaHandler(spaFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(spaFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		trimmed := strings.TrimPrefix(r.URL.Path, "/")
		if trimmed == "" {
			trimmed = "index.html"
		}
		if _, err := fs.Stat(spaFS, trimmed); err != nil {
			// Unknown path — serve the SPA entry so the router can handle it.
			data, readErr := fs.ReadFile(spaFS, "index.html")
			if readErr != nil {
				http.Error(w, "UI not built. Run `npm run build` inside ui/.", http.StatusInternalServerError)
				return
			}
			writeSPASecurityHeaders(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(data)
			return
		}
		writeSPASecurityHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
}

// writeSPASecurityHeaders adds the baseline browser-side hardening
// headers to every admin SPA response. Without these, any future XSS
// in the React build (or in a vulnerable transitive dep) would be
// fully exploitable, and the dashboard could be framed by an attacker
// site for clickjacking. The CSP allows inline styles because the
// Vite-built SPA inlines a bootstrap stylesheet; if that's tightened
// upstream we can drop 'unsafe-inline' for style-src.
func writeSPASecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	// Self-only loading; same-origin connect-src lets the SPA call /api/*.
	h.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"connect-src 'self'; "+
			"font-src 'self' data:; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'")
}

// withAuth gates admin endpoints on the WAF_API_KEY environment
// variable. When the env var is empty AND the WAF_ALLOW_NO_AUTH escape
// hatch isn't set, we LOUDLY refuse every request rather than silently
// falling open — silent fail-open meant a deployment that forgot to
// set the secret had its admin API world-readable with no signal.
//
// We compare with subtle.ConstantTimeCompare so a remote attacker
// can't byte-by-byte recover the key via response-time differences.
// Header-only — accepting the key from the URL query allows reflection
// via Referer / browser logs / CDN caches and combined with permissive
// CORS would let a third-party page execute admin calls. The previous
// `?api_key=` fallback has been removed.
func (s *Server) withAuth(next http.Handler) http.Handler {
	expected := os.Getenv("WAF_API_KEY")
	allowNoAuth := os.Getenv("WAF_ALLOW_NO_AUTH") == "1"
	expectedBytes := []byte(expected)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expected == "" {
			if allowNoAuth {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "admin api: WAF_API_KEY not set; refusing to serve. "+
				"Set WAF_API_KEY=<32+ random bytes> or, for local dev only, "+
				"WAF_ALLOW_NO_AUTH=1.", http.StatusServiceUnavailable)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" || subtle.ConstantTimeCompare([]byte(key), expectedBytes) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.metrics.Snapshot())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := limits.Stats()
	stats["mode"] = s.cfg.ModeSnapshot()
	stats["version"] = "0.1.0-foundation"
	stats["uptime_sec"] = int(time.Since(startTime).Seconds())

	// Augment with host telemetry so the UI shows real CPU/mem numbers.
	if s.host != nil {
		res := s.host.ResourcesSnapshot()
		stats["cpu_percent"] = res.CPUUsagePercent
		stats["memory_percent"] = res.MemoryUsagePercent
		stats["disk_io_percent"] = res.DiskUsagePercent
	}
	if s.connection != nil {
		stats["network_latency_ms"] = s.connection.StatusSnapshot().LastPingMs
	}
	writeJSON(w, stats)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Strip HMAC keys before returning. The UI treats the placeholder
		// as "secret is configured" without ever holding the value, and
		// the POST branch ignores any payload that echoes it back so a
		// form round-trip doesn't overwrite the running secret.
		writeJSON(w, s.cfg.RedactSecrets())
	case http.MethodPost:
		var payload struct {
			Mode                   string   `json:"mode"`
			HistoryRotateHours     int      `json:"history_rotate_hours"`
			EgressEnabled          *bool    `json:"egress_enabled"`
			EgressAddr             string   `json:"egress_addr"`
			EgressAllowlist        []string `json:"egress_allowlist"`
			EgressBlockPrivateIPs  *bool    `json:"egress_block_private_ips"`
			EgressExfilInspect     *bool    `json:"egress_exfil_inspect"`
			EgressExfilBlock       *bool    `json:"egress_exfil_block"`
			MeshEnabled            *bool    `json:"mesh_enabled"`
			MeshPeers              []string `json:"mesh_peers"`
			MeshGossipIntervalSec  int      `json:"mesh_gossip_interval_sec"`
			MeshAPIKey             string   `json:"mesh_api_key"`
			MeshSyncTimeoutSec     int      `json:"mesh_sync_timeout_sec"`
			SecurityHeadersEnabled *bool    `json:"security_headers_enabled"`
			ParanoiaLevel          int      `json:"paranoia_level"`
			CRSEnabled             *bool    `json:"crs_enabled"`
			FailsafeMode           string   `json:"failsafe_mode"`
			ShaperEnabled          *bool    `json:"shaper_enabled"`
			ShaperMaxRPS           int      `json:"shaper_max_rps"`
			ShaperBurst            int      `json:"shaper_burst"`
			// Newly surfaced fields — all nullable so the UI can leave them alone.
			DecompressInspect   *bool `json:"decompress_inspect"`
			DecompressRatioCap  int   `json:"decompress_ratio_cap"`
			BanBackoffEnabled   *bool `json:"ban_backoff_enabled"`
			BanBackoffMultiplier int  `json:"ban_backoff_multiplier"`
			BanBackoffWindowSec int   `json:"ban_backoff_window_sec"`
			MaxBanDurationSec   int   `json:"max_ban_duration_sec"`
			PerRuleCounters     *bool `json:"per_rule_counters"`
			BlockThreshold      int   `json:"block_threshold"`
			RateLimitRPS        int   `json:"rate_limit_rps"`
			RateLimitBurst      int   `json:"rate_limit_burst"`

			SessionTrackingEnabled    *bool `json:"session_tracking_enabled"`
			BrowserChallengeEnabled   *bool `json:"browser_challenge_enabled"`
			BrowserChallengeBlock     *bool `json:"browser_challenge_block"`
			SessionBlockThreshold     *int  `json:"session_block_threshold"`
			SessionRequestRateCeiling int       `json:"session_request_rate_ceiling"`
			SessionPathCountCeiling   int       `json:"session_path_count_ceiling"`
			ChallengeTTLSec           int       `json:"challenge_ttl_sec"`
			SessionScoreDecayPerMin   *int      `json:"session_score_decay_per_min"`
			TrustXFF                  *bool     `json:"trust_xff"`
			TrustedProxies            *[]string `json:"trusted_proxies"`

			GRPCInspect            *bool    `json:"grpc_inspect"`
			GRPCBlockOnError       *bool    `json:"grpc_block_on_error"`
			GRPCMaxFrames          int      `json:"grpc_max_frames"`
			GRPCMaxFrameBytes      int      `json:"grpc_max_frame_bytes"`
			WebSocketInspect       *bool    `json:"websocket_inspect"`
			WebSocketRequireSubproto *bool  `json:"websocket_require_subprotocol"`
			WebSocketOriginAllowlist []string `json:"websocket_origin_allowlist"`
			WebSocketSubprotoAllowlist []string `json:"websocket_subprotocol_allowlist"`
			AuditEnabled           *bool  `json:"audit_enabled"`

			GraphQLEnabled            *bool  `json:"graphql_enabled"`
			GraphQLBlockOnError       *bool  `json:"graphql_block_on_error"`
			GraphQLMaxDepth           int    `json:"graphql_max_depth"`
			GraphQLMaxAliases         int    `json:"graphql_max_aliases"`
			GraphQLMaxFields          int    `json:"graphql_max_fields"`
			GraphQLRoleHeader         string `json:"graphql_role_header"`
			GraphQLBlockSubscriptions *bool  `json:"graphql_block_subscriptions"`

			HSTSEnabled        *bool `json:"hsts_enabled"`
			HSTSMaxAgeSec      int   `json:"hsts_max_age_sec"`
			HSTSIncludeSubdoms *bool `json:"hsts_include_subdomains"`
			HSTSPreload        *bool `json:"hsts_preload"`

			JA3Enabled        *bool    `json:"ja3_enabled"`
			JA3HardBlock      *bool    `json:"ja3_hard_block"`
			JA3Header         *string  `json:"ja3_header"`
			JA3TrustedSources []string `json:"ja3_trusted_sources"`

			PoWEnabled       *bool `json:"pow_enabled"`
			PoWTriggerScore  *int  `json:"pow_trigger_score"`
			PoWMinDifficulty *int  `json:"pow_min_difficulty"`
			PoWMaxDifficulty *int  `json:"pow_max_difficulty"`
			PoWTokenTTLSec   *int  `json:"pow_token_ttl_sec"`
			PoWCookieTTLSec  *int  `json:"pow_cookie_ttl_sec"`

			PoWAdaptiveEnabled          *bool `json:"pow_adaptive_enabled"`
			PoWAdaptiveTier2Failures    *int  `json:"pow_adaptive_tier2_failures"`
			PoWAdaptiveTier2PenaltyBits *int  `json:"pow_adaptive_tier2_penalty_bits"`

			MultiLimitEnabled    *bool   `json:"multi_limit_enabled"`
			MultiLimitWindowSec  *int    `json:"multi_limit_window_sec"`
			MultiLimitIPRPM      *int    `json:"multi_limit_ip_rpm"`
			MultiLimitJA4RPM     *int    `json:"multi_limit_ja4_rpm"`
			MultiLimitCookieRPM  *int    `json:"multi_limit_cookie_rpm"`
			MultiLimitCookieName *string `json:"multi_limit_cookie_name"`
			MultiLimitQueryRPM   *int    `json:"multi_limit_query_rpm"`
			MultiLimitMaxEntries *int    `json:"multi_limit_max_entries"`

			IntelFeedsEnabled       *bool    `json:"intel_feeds_enabled"`
			IntelFeedsCacheDir      *string  `json:"intel_feeds_cache_dir"`
			IntelFeedsLearningHours *int     `json:"intel_feeds_learning_hours"`
			IntelFeedsAllowSources  []string `json:"intel_feeds_allow_sources"`
		}
		// Bounded reader so a malicious request can't OOM us with a 1 GB JSON.
		// 64 KiB is generous — every legitimate config payload is under 8 KiB.
		limited := http.MaxBytesReader(w, r.Body, 64*1024)
		if err := json.NewDecoder(limited).Decode(&payload); err != nil {
			http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Validate any pre-lock checks BEFORE acquiring the write lock.
		// Returning early after Lock without Unlock leaks the mutex and
		// deadlocks every subsequent config request — that exact bug
		// existed here previously on the invalid-mode path.
		if payload.Mode != "" && payload.Mode != "active" && payload.Mode != "detection" && payload.Mode != "learning" {
			http.Error(w, "Invalid mode", http.StatusBadRequest)
			return
		}

		// Serialise the mutation batch so a concurrent Snapshot() reader
		// doesn't observe half-applied state. Mode still goes through its
		// atomic setter separately. We unlock explicitly before calling
		// SnapshotToFile at the end (which internally takes the RLock) —
		// RWMutex is not reentrant.
		s.cfg.Lock()
		if payload.Mode != "" {
			s.cfg.SetMode(payload.Mode)
		}
		if payload.HistoryRotateHours > 0 {
			s.cfg.HistoryRotateHours = payload.HistoryRotateHours
			if s.history != nil {
				s.history.SetRotation(time.Duration(payload.HistoryRotateHours) * time.Hour)
			}
		}
		if payload.EgressEnabled != nil {
			s.cfg.EgressEnabled = *payload.EgressEnabled
		}
		if payload.EgressAddr != "" {
			s.cfg.EgressAddr = payload.EgressAddr
		}
		if payload.EgressAllowlist != nil {
			s.cfg.EgressAllowlist = payload.EgressAllowlist
		}
		if payload.EgressBlockPrivateIPs != nil {
			s.cfg.EgressBlockPrivateIPs = *payload.EgressBlockPrivateIPs
		}
		if payload.EgressExfilInspect != nil {
			s.cfg.EgressExfilInspect = *payload.EgressExfilInspect
		}
		if payload.EgressExfilBlock != nil {
			s.cfg.EgressExfilBlock = *payload.EgressExfilBlock
		}
		if payload.MeshEnabled != nil {
			s.cfg.MeshEnabled = *payload.MeshEnabled
			s.meshEnabled = *payload.MeshEnabled
		}
		if payload.MeshPeers != nil {
			s.cfg.MeshPeers = payload.MeshPeers
			s.meshPeers = payload.MeshPeers
		}
		if payload.MeshGossipIntervalSec > 0 {
			s.cfg.MeshGossipIntervalSec = payload.MeshGossipIntervalSec
		}
		if payload.MeshSyncTimeoutSec > 0 {
			s.cfg.MeshSyncTimeoutSec = payload.MeshSyncTimeoutSec
		}
		// A POST that echoes back the redaction placeholder means the
		// UI never had the real value; treat as "no change" rather
		// than overwriting the running key with the literal string.
		if payload.MeshAPIKey != "" && !config.IsRedactedPlaceholder(payload.MeshAPIKey) {
			s.cfg.MeshAPIKey = payload.MeshAPIKey
			s.meshAPIKey = payload.MeshAPIKey
		}
		if payload.SecurityHeadersEnabled != nil {
			s.cfg.SecurityHeadersEnabled = *payload.SecurityHeadersEnabled
		}
		if payload.ParanoiaLevel > 0 {
			pl := payload.ParanoiaLevel
			if pl > 4 {
				pl = 4
			}
			s.cfg.ParanoiaLevel = pl
		}
		if payload.CRSEnabled != nil {
			s.cfg.CRSEnabled = *payload.CRSEnabled
		}
		if payload.FailsafeMode == "open" || payload.FailsafeMode == "closed" {
			s.cfg.FailsafeMode = payload.FailsafeMode
		}
		if payload.ShaperEnabled != nil {
			s.cfg.ShaperEnabled = *payload.ShaperEnabled
		}
		if payload.ShaperMaxRPS > 0 {
			s.cfg.ShaperMaxRPS = payload.ShaperMaxRPS
		}
		if payload.ShaperBurst > 0 {
			s.cfg.ShaperBurst = payload.ShaperBurst
		}
		if payload.DecompressInspect != nil {
			s.cfg.DecompressInspect = *payload.DecompressInspect
		}
		if payload.DecompressRatioCap > 0 {
			// Clamp to a sane range so a typo doesn't disable the defence
			// (cap=1 would reject all real compression) or make it useless
			// (cap=1 000 000 would pass a real bomb).
			rc := payload.DecompressRatioCap
			if rc < 10 {
				rc = 10
			}
			if rc > 10000 {
				rc = 10000
			}
			s.cfg.DecompressRatioCap = rc
		}
		if payload.BanBackoffEnabled != nil {
			s.cfg.BanBackoffEnabled = *payload.BanBackoffEnabled
		}
		if payload.BanBackoffMultiplier > 0 {
			s.cfg.BanBackoffMultiplier = payload.BanBackoffMultiplier
		}
		if payload.BanBackoffWindowSec > 0 {
			s.cfg.BanBackoffWindowSec = payload.BanBackoffWindowSec
		}
		if payload.MaxBanDurationSec > 0 {
			s.cfg.MaxBanDurationSec = payload.MaxBanDurationSec
		}
		if payload.PerRuleCounters != nil {
			s.cfg.PerRuleCounters = *payload.PerRuleCounters
		}
		if payload.BlockThreshold > 0 {
			s.cfg.BlockThreshold = payload.BlockThreshold
		}
		if payload.RateLimitRPS > 0 {
			s.cfg.RateLimitRPS = payload.RateLimitRPS
		}
		if payload.RateLimitBurst > 0 {
			s.cfg.RateLimitBurst = payload.RateLimitBurst
		}
		if payload.SessionTrackingEnabled != nil {
			s.cfg.SessionTrackingEnabled = *payload.SessionTrackingEnabled
		}
		if payload.BrowserChallengeEnabled != nil {
			s.cfg.BrowserChallengeEnabled = *payload.BrowserChallengeEnabled
		}
		if payload.BrowserChallengeBlock != nil {
			s.cfg.BrowserChallengeBlock = *payload.BrowserChallengeBlock
		}
		if payload.SessionBlockThreshold != nil {
			if v := *payload.SessionBlockThreshold; v >= 0 && v <= 100 {
				s.cfg.SessionBlockThreshold = v
			}
		}
		if payload.SessionRequestRateCeiling > 0 {
			s.cfg.SessionRequestRateCeiling = payload.SessionRequestRateCeiling
		}
		if payload.SessionPathCountCeiling > 0 {
			s.cfg.SessionPathCountCeiling = payload.SessionPathCountCeiling
		}
		if payload.ChallengeTTLSec > 0 {
			// Validation in Validate() also clamps the upper bound,
			// but we re-bound here so the live tracker doesn't see a
			// week-and-a-half value for the brief window before the
			// next Validate() pass.
			ttl := payload.ChallengeTTLSec
			if ttl > 7*86400 {
				ttl = 7 * 86400
			}
			s.cfg.ChallengeTTLSec = ttl
		}
		if payload.SessionScoreDecayPerMin != nil {
			d := *payload.SessionScoreDecayPerMin
			if d < 0 {
				d = 0
			}
			if d > 50 {
				d = 50
			}
			s.cfg.SessionScoreDecayPerMin = d
		}
		if payload.GraphQLEnabled != nil {
			s.cfg.GraphQLEnabled = *payload.GraphQLEnabled
		}
		if payload.GraphQLBlockOnError != nil {
			s.cfg.GraphQLBlockOnError = *payload.GraphQLBlockOnError
		}
		if payload.GraphQLMaxDepth > 0 {
			s.cfg.GraphQLMaxDepth = payload.GraphQLMaxDepth
		}
		if payload.GraphQLMaxAliases > 0 {
			s.cfg.GraphQLMaxAliases = payload.GraphQLMaxAliases
		}
		if payload.GraphQLMaxFields > 0 {
			s.cfg.GraphQLMaxFields = payload.GraphQLMaxFields
		}
		if payload.GraphQLRoleHeader != "" {
			s.cfg.GraphQLRoleHeader = payload.GraphQLRoleHeader
		}
		if payload.GRPCInspect != nil {
			s.cfg.GRPCInspect = *payload.GRPCInspect
		}
		if payload.GRPCBlockOnError != nil {
			s.cfg.GRPCBlockOnError = *payload.GRPCBlockOnError
		}
		if payload.GRPCMaxFrames > 0 {
			s.cfg.GRPCMaxFrames = payload.GRPCMaxFrames
		}
		if payload.GRPCMaxFrameBytes > 0 {
			s.cfg.GRPCMaxFrameBytes = payload.GRPCMaxFrameBytes
		}
		if payload.WebSocketInspect != nil {
			s.cfg.WebSocketInspect = *payload.WebSocketInspect
		}
		if payload.WebSocketRequireSubproto != nil {
			s.cfg.WebSocketRequireSubproto = *payload.WebSocketRequireSubproto
		}
		if payload.WebSocketOriginAllowlist != nil {
			s.cfg.WebSocketOriginAllowlist = payload.WebSocketOriginAllowlist
		}
		if payload.WebSocketSubprotoAllowlist != nil {
			s.cfg.WebSocketSubprotoAllowlist = payload.WebSocketSubprotoAllowlist
		}
		if payload.AuditEnabled != nil {
			s.cfg.AuditEnabled = *payload.AuditEnabled
		}
		if payload.GraphQLBlockSubscriptions != nil {
			s.cfg.GraphQLBlockSubscriptions = *payload.GraphQLBlockSubscriptions
		}
		if payload.TrustXFF != nil {
			s.cfg.TrustXFF = *payload.TrustXFF
		}
		if payload.TrustedProxies != nil {
			// Defensive copy — never alias the request body's slice into
			// the live config, otherwise GC of the request would mutate
			// the running policy.
			s.cfg.TrustedProxies = append([]string(nil), (*payload.TrustedProxies)...)
		}
		if payload.HSTSEnabled != nil {
			s.cfg.HSTSEnabled = *payload.HSTSEnabled
		}
		if payload.HSTSMaxAgeSec > 0 {
			// Browsers cap max-age at 2 years internally, but the spec allows
			// any uint31 — clamp at 10 years to keep operators from shooting
			// themselves with an unintended "forever" value.
			if payload.HSTSMaxAgeSec > 315360000 {
				payload.HSTSMaxAgeSec = 315360000
			}
			s.cfg.HSTSMaxAgeSec = payload.HSTSMaxAgeSec
		}
		if payload.HSTSIncludeSubdoms != nil {
			s.cfg.HSTSIncludeSubdoms = *payload.HSTSIncludeSubdoms
		}
		if payload.HSTSPreload != nil {
			s.cfg.HSTSPreload = *payload.HSTSPreload
		}
		if payload.JA3Enabled != nil {
			s.cfg.JA3Enabled = *payload.JA3Enabled
		}
		if payload.JA3HardBlock != nil {
			s.cfg.JA3HardBlock = *payload.JA3HardBlock
		}
		if payload.JA3Header != nil {
			s.cfg.JA3Header = *payload.JA3Header
		}
		if payload.JA3TrustedSources != nil {
			s.cfg.JA3TrustedSources = append([]string(nil), payload.JA3TrustedSources...)
		}
		if payload.PoWEnabled != nil {
			s.cfg.PoWEnabled = *payload.PoWEnabled
		}
		if payload.PoWTriggerScore != nil && *payload.PoWTriggerScore > 0 && *payload.PoWTriggerScore <= 100 {
			s.cfg.PoWTriggerScore = *payload.PoWTriggerScore
		}
		if payload.PoWMinDifficulty != nil && *payload.PoWMinDifficulty >= 8 && *payload.PoWMinDifficulty <= 32 {
			s.cfg.PoWMinDifficulty = *payload.PoWMinDifficulty
		}
		if payload.PoWMaxDifficulty != nil && *payload.PoWMaxDifficulty >= 8 && *payload.PoWMaxDifficulty <= 32 {
			s.cfg.PoWMaxDifficulty = *payload.PoWMaxDifficulty
		}
		if payload.PoWTokenTTLSec != nil && *payload.PoWTokenTTLSec >= 30 && *payload.PoWTokenTTLSec <= 600 {
			s.cfg.PoWTokenTTLSec = *payload.PoWTokenTTLSec
		}
		if payload.PoWCookieTTLSec != nil && *payload.PoWCookieTTLSec >= 60 && *payload.PoWCookieTTLSec <= 86400 {
			s.cfg.PoWCookieTTLSec = *payload.PoWCookieTTLSec
		}

		// Adaptive PoW (tier-2). Caller flips on/off live; the proxy reads
		// the field on the next gate decision so no restart is needed.
		if payload.PoWAdaptiveEnabled != nil {
			s.cfg.PoWAdaptiveEnabled = *payload.PoWAdaptiveEnabled
		}
		if payload.PoWAdaptiveTier2Failures != nil && *payload.PoWAdaptiveTier2Failures >= 1 && *payload.PoWAdaptiveTier2Failures <= 100 {
			s.cfg.PoWAdaptiveTier2Failures = *payload.PoWAdaptiveTier2Failures
		}
		if payload.PoWAdaptiveTier2PenaltyBits != nil && *payload.PoWAdaptiveTier2PenaltyBits >= 1 && *payload.PoWAdaptiveTier2PenaltyBits <= 10 {
			s.cfg.PoWAdaptiveTier2PenaltyBits = *payload.PoWAdaptiveTier2PenaltyBits
		}

		// Multi-dimensional rate limiter.
		if payload.MultiLimitEnabled != nil {
			s.cfg.MultiLimitEnabled = *payload.MultiLimitEnabled
		}
		if payload.MultiLimitWindowSec != nil && *payload.MultiLimitWindowSec > 0 && *payload.MultiLimitWindowSec <= 3600 {
			s.cfg.MultiLimitWindowSec = *payload.MultiLimitWindowSec
		}
		if payload.MultiLimitIPRPM != nil && *payload.MultiLimitIPRPM >= 0 {
			s.cfg.MultiLimitIPRPM = *payload.MultiLimitIPRPM
		}
		if payload.MultiLimitJA4RPM != nil && *payload.MultiLimitJA4RPM >= 0 {
			s.cfg.MultiLimitJA4RPM = *payload.MultiLimitJA4RPM
		}
		if payload.MultiLimitCookieRPM != nil && *payload.MultiLimitCookieRPM >= 0 {
			s.cfg.MultiLimitCookieRPM = *payload.MultiLimitCookieRPM
		}
		if payload.MultiLimitCookieName != nil && len(*payload.MultiLimitCookieName) > 0 && len(*payload.MultiLimitCookieName) < 128 {
			s.cfg.MultiLimitCookieName = *payload.MultiLimitCookieName
		}
		if payload.MultiLimitQueryRPM != nil && *payload.MultiLimitQueryRPM >= 0 {
			s.cfg.MultiLimitQueryRPM = *payload.MultiLimitQueryRPM
		}
		if payload.MultiLimitMaxEntries != nil && *payload.MultiLimitMaxEntries >= 1024 {
			s.cfg.MultiLimitMaxEntries = *payload.MultiLimitMaxEntries
		}

		// Intel feeds toggles. Adding/removing sources at runtime is a
		// restart-required change; the toggle and learning-window ARE
		// hot-swappable.
		if payload.IntelFeedsEnabled != nil {
			s.cfg.IntelFeedsEnabled = *payload.IntelFeedsEnabled
		}
		if payload.IntelFeedsCacheDir != nil && *payload.IntelFeedsCacheDir != "" {
			s.cfg.IntelFeedsCacheDir = *payload.IntelFeedsCacheDir
		}
		if payload.IntelFeedsLearningHours != nil && *payload.IntelFeedsLearningHours >= 0 && *payload.IntelFeedsLearningHours <= 24*30 {
			s.cfg.IntelFeedsLearningHours = *payload.IntelFeedsLearningHours
		}
		if payload.IntelFeedsAllowSources != nil {
			cleaned := make([]string, 0, len(payload.IntelFeedsAllowSources))
			for _, src := range payload.IntelFeedsAllowSources {
				src = strings.TrimSpace(src)
				if src != "" && len(src) <= 64 {
					cleaned = append(cleaned, src)
				}
			}
			s.cfg.IntelFeedsAllowSources = cleaned
		}

		// Push live changes to the multi-limiter if it exists, so RPS
		// changes apply without a restart.
		if s.multiLim != nil {
			s.multiLim.SetConfig(limits.MultiConfig{
				Window:          time.Duration(s.cfg.MultiLimitWindowSec) * time.Second,
				IPBudget:        s.cfg.MultiLimitIPRPM,
				JA4Budget:       s.cfg.MultiLimitJA4RPM,
				CookieBudget:    s.cfg.MultiLimitCookieRPM,
				CookieName:      s.cfg.MultiLimitCookieName,
				QueryKeysBudget: s.cfg.MultiLimitQueryRPM,
				MaxEntries:      s.cfg.MultiLimitMaxEntries,
			})
		}
		// Push updated ban-list backoff to the live object so changes take
		// effect without a restart. Capture values under the write lock so
		// the ConfigureBackoff call outside the lock sees a consistent set.
		backoffEnabled := s.cfg.BanBackoffEnabled
		backoffMult := s.cfg.BanBackoffMultiplier
		backoffWindow := time.Duration(s.cfg.BanBackoffWindowSec) * time.Second
		backoffMax := time.Duration(s.cfg.MaxBanDurationSec) * time.Second
		rotateHours := s.cfg.HistoryRotateHours
		// Capture live-push scalars under the lock as well so the hot-reload
		// calls below see a consistent snapshot even if another request
		// enters handleConfig concurrently.
		sessionEnabled := s.cfg.SessionTrackingEnabled
		sessionRateCeiling := s.cfg.SessionRequestRateCeiling
		sessionPathCeiling := s.cfg.SessionPathCountCeiling
		sessionChallengeTTL := time.Duration(s.cfg.ChallengeTTLSec) * time.Second
		sessionScoreDecay := s.cfg.SessionScoreDecayPerMin
		// Snapshot under the lock so the Update() call below sees the
		// same TrustXFF / TrustedProxies pair the caller posted, even
		// under concurrent hot-reloads.
		updateTrustXFF := s.cfg.TrustXFF
		updateTrustedProxies := append([]string(nil), s.cfg.TrustedProxies...)
		graphqlCfg := graphql.Config{
			Enabled:            s.cfg.GraphQLEnabled,
			MaxDepth:           s.cfg.GraphQLMaxDepth,
			MaxAliases:         s.cfg.GraphQLMaxAliases,
			MaxFields:          s.cfg.GraphQLMaxFields,
			RequireRoleHdr:     s.cfg.GraphQLRoleHeader,
			BlockOnError:       s.cfg.GraphQLBlockOnError,
			BlockSubscriptions: s.cfg.GraphQLBlockSubscriptions,
		}
		s.cfg.Unlock()

		if s.banList != nil {
			s.banList.ConfigureBackoff(backoffEnabled, backoffMult, backoffWindow, backoffMax)
		}
		// Push updated session + GraphQL toggles to the live subsystems.
		if s.sessions != nil {
			s.sessions.SetEnabled(sessionEnabled)
			s.sessions.SetThresholds(sessionRateCeiling, sessionPathCeiling)
			s.sessions.SetChallengeTTL(sessionChallengeTTL)
			s.sessions.SetScoreDecayPerMin(sessionScoreDecay)
		}
		// The proxy + tracker share a single *clientip.Extractor so a
		// single Update() propagates the new trust policy atomically
		// to every hot-path caller. A malformed CIDR in the new list
		// leaves the previous policy in place and surfaces in the log
		// — refusing to apply is safer than silently dropping the gate.
		if s.proxy != nil {
			if ipx := s.proxy.IPExtractor(); ipx != nil {
				if err := ipx.Update(updateTrustXFF, updateTrustedProxies); err != nil {
					log.Printf("config: trusted_proxies update rejected: %v", err)
				}
			}
		}
		if s.graphql != nil {
			// Preserve any previously-loaded SDL across hot-reloads — config
			// posts don't carry the schema text, only the structural limits.
			graphqlCfg.SchemaSDL = s.graphql.ConfigSnapshot().SchemaSDL
			_ = s.graphql.Reload(graphqlCfg)
		}
		// Persist a config snapshot after any successful change so operators
		// have a rollback target.
		if path, err := s.cfg.SnapshotToFile("config_backup", 10); err == nil {
			log.Printf("config snapshot saved: %s", path)
		}
		// Append an audit entry. We deliberately don't dump the whole
		// payload — secrets like mesh_api_key would land in the log.
		// A short summary plus the snapshot file path is enough to
		// correlate "config changed at T" with "the snapshot at T".
		if s.audit != nil {
			_, _ = s.audit.Append("config_write", s.clientIPOf(r),
				"admin POST /api/config",
				fmt.Sprintf(`{"mode":%q,"history_rotate_hours":%d}`,
					s.cfg.ModeSnapshot(), rotateHours))
		}
		writeJSON(w, map[string]interface{}{"status": "ok", "mode": s.cfg.ModeSnapshot(), "history_rotate_hours": rotateHours})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	recent := s.metrics.RecentBlocksSnapshot(50)
	if s.banList != nil {
		for _, ban := range s.banList.List() {
			recent = append(recent, telemetry.BlockRecord{
				Timestamp: ban.Timestamp,
				IP:        ban.IP,
				Method:    "-",
				Path:      "-",
				RuleID:    "REPUTATION",
				Score:     0,
				Message:   ban.Reason,
			})
		}
	}
	writeJSON(w, map[string]interface{}{
		"recent": recent,
	})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.metrics.GetTrafficHistory())
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.rulesFn != nil {
		writeJSON(w, map[string]interface{}{"rules": s.rulesFn()})
	} else {
		writeJSON(w, map[string]interface{}{"rules": []map[string]interface{}{}})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"status": "ok",
		"mode":   s.cfg.ModeSnapshot(),
	})
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.banList == nil {
			writeJSON(w, map[string]interface{}{"bans": []core.BanEntry{}})
			return
		}
		writeJSON(w, map[string]interface{}{"bans": s.banList.List()})
	case http.MethodPost:
		if s.banList == nil {
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
		var payload struct {
			IP          string `json:"ip"`
			DurationSec int    `json:"duration_sec"`
			Reason      string `json:"reason"`
		}
		// DisallowUnknownFields refuses any field outside the three
		// above. /api/bans is a high-blast-radius endpoint; rejecting
		// surprise fields means a future code reader can't accidentally
		// add a field that an attacker has already been smuggling.
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if payload.IP == "" || stdnet.ParseIP(payload.IP) == nil {
			http.Error(w, "Invalid IP", http.StatusBadRequest)
			return
		}
		if payload.Reason == "" {
			payload.Reason = "manual"
		}
		s.banList.Ban(payload.IP, payload.Reason, time.Duration(payload.DurationSec)*time.Second)
		// Tamper-evident audit record. Without this, an admin who
		// reaches /api/bans (e.g. by stealing the API key) leaves no
		// chain entry — the previous design only logged WAF-issued
		// bans, not operator-issued ones.
		if s.audit != nil {
			meta := fmt.Sprintf(`{"ip":%q,"duration_sec":%d,"reason":%q}`,
				payload.IP, payload.DurationSec, payload.Reason)
			_, _ = s.audit.Append("ban_admin", s.clientIPOf(r),
				"admin POST /api/bans", meta)
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "Missing ip parameter", http.StatusBadRequest)
			return
		}
		if s.banList != nil {
			s.banList.Unban(ip)
		}
		if s.audit != nil {
			_, _ = s.audit.Append("unban_admin", s.clientIPOf(r),
				"admin DELETE /api/bans",
				fmt.Sprintf(`{"ip":%q}`, ip))
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Host telemetry ----

func (s *Server) handleHostStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.host == nil {
		writeJSON(w, map[string]interface{}{"online": true})
		return
	}
	writeJSON(w, s.host.StatsSnapshot())
}

func (s *Server) handleHostResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.host == nil {
		writeJSON(w, host.Resources{})
		return
	}
	writeJSON(w, s.host.ResourcesSnapshot())
}

// ---- Connection management ----

func (s *Server) handleConnectionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.connection == nil {
		writeJSON(w, connection.Status{Connected: false})
		return
	}
	writeJSON(w, s.connection.StatusSnapshot())
}

func (s *Server) handleConnectionConfig(w http.ResponseWriter, r *http.Request) {
	if s.connection == nil {
		writeJSON(w, connection.Config{})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.connection.ConfigSnapshot())
	case http.MethodPut, http.MethodPost:
		var patch connection.Config
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		writeJSON(w, s.connection.UpdateConfig(patch))
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConnectionTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.connection == nil {
		writeJSON(w, map[string]interface{}{"success": false, "latency_ms": 0})
		return
	}
	status := s.connection.Probe(r.Context())
	writeJSON(w, map[string]interface{}{
		"success":    status.Connected,
		"latency_ms": status.LastPingMs,
	})
}

// handleConnectionHistory returns the ping-latency ring buffer so the UI
// can render a sparkline without synthesising it client-side.
func (s *Server) handleConnectionHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.connection == nil {
		writeJSON(w, map[string]interface{}{"history": []connection.PingSample{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"history": s.connection.PingHistory(),
	})
}

// handleConnectionEvents returns state-transition events.
func (s *Server) handleConnectionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.connection == nil {
		writeJSON(w, map[string]interface{}{"events": []connection.Event{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"events": s.connection.EventHistory(),
	})
}

// ---- SSL / TLS ----

func (s *Server) handleSSLCertificates(w http.ResponseWriter, r *http.Request) {
	if s.ssl == nil {
		writeJSON(w, map[string]interface{}{"certificates": []ssl.Certificate{}})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"certificates": s.ssl.List()})
	case http.MethodPost:
		// Bound the body envelope. The SSL Upload validator caps cert
		// and key strings at 256 KiB each, but that check happens AFTER
		// json.Decode allocates the whole body — without this, an
		// authenticated attacker could feed multi-GB JSON and OOM the
		// admin process. 1 MiB comfortably covers cert + key + JSON
		// overhead.
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
		var req ssl.UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		cert, err := s.ssl.Upload(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, cert)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSLCertificateByID(w http.ResponseWriter, r *http.Request) {
	if s.ssl == nil {
		writeJSON(w, map[string]string{"status": "ok"})
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/ssl/certificates/")
	id = strings.Trim(id, "/")
	if id == "" {
		http.Error(w, "Missing cert ID", http.StatusBadRequest)
		return
	}
	if err := s.ssl.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{"status": "deleted", "id": id})
}

func (s *Server) handleSSLConfig(w http.ResponseWriter, r *http.Request) {
	if s.ssl == nil {
		writeJSON(w, ssl.Config{})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.ssl.ConfigSnapshot())
	case http.MethodPut, http.MethodPost:
		// SSL config is a tiny set of scalars; cap aggressively so a
		// malformed admin client (or attacker with the API key) can't
		// allocate gigabytes through json.Decode.
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		var patch ssl.Config
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		cfg, err := s.ssl.UpdateConfig(patch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, cfg)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ---- History ----

func (s *Server) handleHistoryDatabases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"databases": []history.DatabaseInfo{}})
		return
	}
	dbs, err := s.history.ListDatabases()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"databases": dbs})
}

func (s *Server) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"events": []history.BlockEvent{}})
		return
	}
	from, to, limit := parseTimeRange(r, 500)
	events, err := s.history.QueryBlocks(from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"events": events, "from": from, "to": to})
}

func (s *Server) handleHistoryIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"ips": []history.IPActivity{}})
		return
	}
	from, to, limit := parseTimeRange(r, 100)
	ips, err := s.history.QueryIPs(from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ips": ips, "from": from, "to": to})
}

func (s *Server) handleHistoryTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"traffic": []history.TrafficPoint{}})
		return
	}
	from, to, limit := parseTimeRange(r, 1000)
	points, err := s.history.QueryTraffic(from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"traffic": points, "from": from, "to": to})
}

func (s *Server) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, history.Stats{})
		return
	}
	writeJSON(w, s.history.StatsSnapshot())
}

// handleRecentRequests proxies to the current-window IP activity so the
// RequestLogs page has a cheap, always-fresh endpoint to poll.
func (s *Server) handleRecentRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		// Fall back to recent blocks from memory so the UI isn't empty.
		writeJSON(w, map[string]interface{}{"requests": s.metrics.RecentBlocksSnapshot(50)})
		return
	}
	limit := clampInt(parseInt(r.URL.Query().Get("limit"), 100), 1, 1000)
	now := time.Now().UTC()
	events, _ := s.history.QueryBlocks(now.Add(-24*time.Hour), now, limit)
	writeJSON(w, map[string]interface{}{"requests": events})
}

// handleRecentIPs returns top IPs by activity within the last 24h.
func (s *Server) handleRecentIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"ips": []history.IPActivity{}})
		return
	}
	limit := clampInt(parseInt(r.URL.Query().Get("limit"), 100), 1, 1000)
	now := time.Now().UTC()
	ips, _ := s.history.QueryIPs(now.Add(-24*time.Hour), now, limit)
	writeJSON(w, map[string]interface{}{"ips": ips})
}

// ---- Rate-limit config ----

func (s *Server) handleRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"rate_limit_rps":         s.cfg.RateLimitRPS,
			"rate_limit_burst":       s.cfg.RateLimitBurst,
			"brute_force_window_sec": s.cfg.BruteForceWindowSec,
			"brute_force_threshold":  s.cfg.BruteForceThreshold,
			"block_threshold":        s.cfg.BlockThreshold,
			"max_concurrent_req":     s.cfg.MaxConcurrentReq,
			"max_body_bytes":         s.cfg.MaxBodyBytes,
		})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Helpers ----

func parseTimeRange(r *http.Request, defaultLimit int) (time.Time, time.Time, int) {
	q := r.URL.Query()
	now := time.Now().UTC()
	to := now
	from := now.Add(-24 * time.Hour)
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		} else if unix, err := strconv.ParseInt(v, 10, 64); err == nil {
			from = time.Unix(unix, 0).UTC()
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		} else if unix, err := strconv.ParseInt(v, 10, 64); err == nil {
			to = time.Unix(unix, 0).UTC()
		}
	}
	limit := clampInt(parseInt(q.Get("limit"), defaultLimit), 1, 10000)
	return from, to, limit
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (s *Server) handleMeshStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	s.meshMu.RLock()
	lastSync := s.meshLastSync
	s.meshMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"enabled":    s.meshEnabled,
		"peers":      s.meshPeers,
		"last_sync":  lastSync,
		"peer_count": len(s.meshPeers),
	})
}

func (s *Server) handleMeshSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Fail closed when no mesh key is configured. The previous behaviour
	// was "skip the auth check when the key is blank", which let any
	// network-reachable peer POST forged ban entries — exactly the
	// abuse the constant-time compare exists to prevent. Empty key now
	// means mesh sync is unusable, full stop, and the operator must
	// supply a key in config.json or via /api/config to enable it.
	if s.meshAPIKey == "" {
		http.Error(w, "mesh disabled: no mesh_api_key configured", http.StatusServiceUnavailable)
		return
	}
	// Constant-time peer-key compare. Direct string `!=` would leak the
	// key one byte at a time over the network — slow but real. A peer
	// payload is never larger than a few MB of bans either way, so we
	// also cap the body so a malicious peer can't OOM us.
	got := r.Header.Get("X-Mesh-Key")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.meshAPIKey)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	var payload struct {
		Bans []core.BanEntry `json:"bans"`
	}
	// Mesh peers are trusted enough to skip every other check, so this
	// is the right place to refuse surprise top-level fields. A peer
	// running a future protocol version learns of the upgrade via 400.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// Merge incoming bans into local ban list.
	if s.banList != nil {
		// Cap ban duration so a malicious peer (or a peer with a bug)
		// can't pin an IP forever. We pick the configured operator
		// max — if they haven't set one, fall back to 30 days, which
		// is long enough to be useful and short enough to recover.
		maxDur := time.Duration(s.cfg.MaxBanDurationSec) * time.Second
		if maxDur <= 0 {
			maxDur = 30 * 24 * time.Hour
		}
		for _, b := range payload.Bans {
			if b.IP == "" || stdnet.ParseIP(b.IP) == nil {
				continue
			}
			duration := time.Until(b.ExpiresAt)
			if duration <= 0 {
				continue
			}
			if duration > maxDur {
				duration = maxDur
			}
			reason := b.Reason
			if len(reason) > 256 {
				reason = reason[:256]
			}
			s.banList.Ban(b.IP, reason, duration)
		}
	}
	s.meshMu.Lock()
	s.meshLastSync = time.Now().UTC()
	s.meshMu.Unlock()

	// Return our own active bans.
	var bans []core.BanEntry
	if s.banList != nil {
		bans = s.banList.List()
	}
	writeJSON(w, map[string]interface{}{
		"status": "synced",
		"bans":   bans,
	})
}

func (s *Server) handleEgressStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var blocked, allowed uint64
	var recent []telemetry.EgressEvent
	if s.metrics != nil {
		counters := s.metrics.CountersSnapshot()
		blocked = counters["egress_blocked"]
		allowed = counters["egress_allowed"]
		recent = s.metrics.RecentEgressSnapshot(50)
	}
	writeJSON(w, map[string]interface{}{
		"enabled":           s.cfg.EgressEnabled,
		"addr":              s.cfg.EgressAddr,
		"block_private_ips": s.cfg.EgressBlockPrivateIPs,
		"allowlist":         s.cfg.EgressAllowlist,
		"allowlist_count":   len(s.cfg.EgressAllowlist),
		"total_blocked":     blocked,
		"total_allowed":     allowed,
		"recent":            recent,
	})
}

func (s *Server) handleMeshPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"peers":  s.meshPeers,
		"count":  len(s.meshPeers),
		"status": "active",
	})
}

func (s *Server) handleBotsDetected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.metrics == nil {
		writeJSON(w, map[string]interface{}{"bots": []telemetry.BotEvent{}, "count": 0})
		return
	}
	limit := clampInt(parseInt(r.URL.Query().Get("limit"), 100), 1, 500)
	bots := s.metrics.RecentBotsSnapshot(limit)
	writeJSON(w, map[string]interface{}{
		"bots":  bots,
		"count": len(bots),
	})
}

// handleEgressRecent returns the recent egress decision ring buffer.
func (s *Server) handleEgressRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.metrics == nil {
		writeJSON(w, map[string]interface{}{"events": []telemetry.EgressEvent{}})
		return
	}
	limit := clampInt(parseInt(r.URL.Query().Get("limit"), 100), 1, 500)
	writeJSON(w, map[string]interface{}{
		"events": s.metrics.RecentEgressSnapshot(limit),
	})
}

// handleNetworkSummary returns a compact network-health payload: byte totals,
// current bandwidth rates, host-level NIC snapshot, and status distribution.
func (s *Server) handleNetworkSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	out := map[string]interface{}{}
	if s.metrics != nil {
		snap := s.metrics.Snapshot()
		for _, k := range []string{
			"total_requests", "blocked_requests", "passed_requests",
			"total_bytes_in", "total_bytes_out",
			"bytes_in_per_sec", "bytes_out_per_sec",
			"egress_blocked", "egress_allowed",
			"status_code_buckets",
		} {
			if v, ok := snap[k]; ok {
				out[k] = v
			}
		}
		out["recent_egress"] = s.metrics.RecentEgressSnapshot(25)
	}
	if s.host != nil {
		res := s.host.ResourcesSnapshot()
		out["host_network_io"] = res.NetworkIO
		out["host_bandwidth_in_bps"] = res.BandwidthInBps
		out["host_bandwidth_out_bps"] = res.BandwidthOutBps
	}
	if s.connection != nil {
		status := s.connection.StatusSnapshot()
		out["backend_connected"] = status.Connected
		out["backend_latency_ms"] = status.LastPingMs
	}
	out["timestamp"] = time.Now().UTC()
	writeJSON(w, out)
}

// handleNetworkTopPaths returns the most frequently blocked paths from the
// persisted history in the given time window.
func (s *Server) handleNetworkTopPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"paths": []map[string]interface{}{}})
		return
	}
	from, to, _ := parseTimeRange(r, 2000)
	events, err := s.history.QueryBlocks(from, to, 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := make(map[string]int, 64)
	for _, e := range events {
		counts[e.Method+" "+e.Path]++
	}
	type pathCount struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
	}
	out := make([]pathCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, pathCount{Path: k, Count: v})
	}
	// Simple in-place sort: largest count first. Using a handwritten compare
	// avoids importing sort on a file that already has enough imports.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Count > out[j-1].Count; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	limit := clampInt(parseInt(r.URL.Query().Get("limit"), 25), 1, 200)
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, map[string]interface{}{"paths": out, "from": from, "to": to})
}

// handleNetworkTopIPs wraps QueryIPs for the Network Monitoring page.
func (s *Server) handleNetworkTopIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil {
		writeJSON(w, map[string]interface{}{"ips": []history.IPActivity{}})
		return
	}
	from, to, limit := parseTimeRange(r, 50)
	ips, err := s.history.QueryIPs(from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ips": ips, "from": from, "to": to})
}

// ---- IP Intelligence ----

// handleIPInsights returns everything known about one IP: request + block
// counts, first/last seen, triggered rule categories, ban status.
// Path: /api/ip/<ip>
func (s *Server) handleIPInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimPrefix(r.URL.Path, "/api/ip/")
	ip = strings.Trim(ip, "/")
	if ip == "" || stdnet.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}

	out := map[string]interface{}{
		"ip":       ip,
		"banned":   false,
		"activity": history.IPActivity{IP: ip},
	}
	if s.banList != nil {
		for _, b := range s.banList.List() {
			if b.IP == ip {
				out["banned"] = true
				out["ban"] = b
				break
			}
		}
	}

	// Aggregate 24 h of history for this IP.
	categories := map[string]int{}
	var recent []history.BlockEvent
	if s.history != nil {
		now := time.Now().UTC()
		events, _ := s.history.QueryBlocks(now.Add(-24*time.Hour), now, 5000)
		for _, e := range events {
			if e.IP != ip {
				continue
			}
			recent = append(recent, e)
			if len(recent) > 100 {
				recent = recent[len(recent)-100:]
			}
			cat := e.RuleCategory
			if cat == "" {
				cat = "other"
			}
			categories[cat]++
		}

		// IP activity aggregate.
		ips, _ := s.history.QueryIPs(now.Add(-24*time.Hour), now, 10000)
		for _, a := range ips {
			if a.IP == ip {
				out["activity"] = a
				break
			}
		}
	}
	out["categories"] = categories
	out["recent_blocks"] = recent
	writeJSON(w, out)
}

// handleAutoMitigate scans the top attacker IPs from the last hour and bans
// any whose block_count exceeds the given threshold. Returns the list of
// newly banned IPs. Requires POST with JSON body:
//
//	{ "threshold": 10, "duration_sec": 3600 }
func (s *Server) handleAutoMitigate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.history == nil || s.banList == nil {
		writeJSON(w, map[string]interface{}{"banned": []string{}, "scanned": 0})
		return
	}
	var req struct {
		Threshold   int `json:"threshold"`
		DurationSec int `json:"duration_sec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Threshold <= 0 {
		req.Threshold = 10
	}
	if req.DurationSec <= 0 {
		req.DurationSec = 3600
	}
	now := time.Now().UTC()
	ips, err := s.history.QueryIPs(now.Add(-time.Hour), now, 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var banned []string
	for _, a := range ips {
		if int(a.BlockCount) < req.Threshold {
			continue
		}
		if s.banList.IsBanned(a.IP) {
			continue
		}
		s.banList.Ban(a.IP, "auto-mitigation: exceeded block threshold", time.Duration(req.DurationSec)*time.Second)
		banned = append(banned, a.IP)
	}
	// One audit entry summarising the bulk action — operator-initiated
	// bulk bans are exactly the kind of mutation an incident timeline
	// needs to be able to reconstruct after the fact.
	if s.audit != nil && len(banned) > 0 {
		_, _ = s.audit.Append("auto_mitigate", s.clientIPOf(r),
			"admin POST /api/ip-auto-mitigate",
			fmt.Sprintf(`{"threshold":%d,"duration_sec":%d,"banned_count":%d}`,
				req.Threshold, req.DurationSec, len(banned)))
	}
	writeJSON(w, map[string]interface{}{
		"banned":    banned,
		"scanned":   len(ips),
		"threshold": req.Threshold,
	})
}

// ---- Live Events (Server-Sent Events) ----

// handleEventsStream pushes blocks/egress/bots to connected clients in real
// time using SSE. Each client gets its own goroutine polling the telemetry
// ring buffers with a short cadence; new entries are flushed immediately.
// No channel-based pub/sub so telemetry stays lock-local and simple.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send an initial hello so the client knows the stream is open.
	_, _ = w.Write([]byte("event: hello\ndata: {\"status\":\"connected\"}\n\n"))
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	// Per-client cursors — we stream only new events since the last tick so
	// the same entry isn't sent twice. Cursors track the last-seen UTC timestamp.
	var lastBlockTS, lastEgressTS, lastBotTS time.Time

	send := func(event, data string) bool {
		if _, err := w.Write([]byte("event: " + event + "\ndata: " + data + "\n\n")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if !send("ping", `{}`) {
				return
			}
		case <-ticker.C:
			if s.metrics == nil {
				continue
			}
			for _, b := range s.metrics.RecentBlocksSnapshot(50) {
				if !b.Timestamp.After(lastBlockTS) {
					continue
				}
				lastBlockTS = b.Timestamp
				buf, err := json.Marshal(b)
				if err != nil {
					continue
				}
				if !send("block", string(buf)) {
					return
				}
			}
			for _, e := range s.metrics.RecentEgressSnapshot(50) {
				if !e.Timestamp.After(lastEgressTS) {
					continue
				}
				lastEgressTS = e.Timestamp
				buf, err := json.Marshal(e)
				if err != nil {
					continue
				}
				if !send("egress", string(buf)) {
					return
				}
			}
			for _, b := range s.metrics.RecentBotsSnapshot(50) {
				if !b.Timestamp.After(lastBotTS) {
					continue
				}
				lastBotTS = b.Timestamp
				buf, err := json.Marshal(b)
				if err != nil {
					continue
				}
				if !send("bot", string(buf)) {
					return
				}
			}
		}
	}
}

// ---- DDoS / Circuit breaker ----

func (s *Server) handleDDoSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.proxy == nil {
		writeJSON(w, map[string]interface{}{})
		return
	}
	writeJSON(w, s.proxy.DDoSStats())
}

func (s *Server) handleBreakerStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.proxy == nil {
		writeJSON(w, map[string]interface{}{})
		return
	}
	writeJSON(w, s.proxy.BreakerStats())
}

func (s *Server) handleShaperStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.proxy == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, s.proxy.ShaperStats())
}

// ---- Zero-trust ----

func (s *Server) handleZeroTrustPolicies(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil || s.proxy.ZeroTrustEngine() == nil {
		http.Error(w, "zero-trust unavailable", http.StatusServiceUnavailable)
		return
	}
	zt := s.proxy.ZeroTrustEngine()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"policies": zt.Policies()})
	case http.MethodPut, http.MethodPost:
		var payload struct {
			Policies []*zerotrust.Policy `json:"policies"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if err := zt.SetPolicies(payload.Policies); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.audit != nil {
			_, _ = s.audit.Append("zerotrust_write", s.clientIPOf(r),
				"admin "+r.Method+" /api/zerotrust/policies",
				fmt.Sprintf(`{"count":%d}`, len(payload.Policies)))
		}
		writeJSON(w, map[string]interface{}{"status": "ok", "count": len(payload.Policies)})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Setup checks ----

func (s *Server) handleSetupCheckDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := r.URL.Query().Get("domain")
	expected := r.URL.Query().Get("expected_ip")
	if r.Method == http.MethodPost {
		var payload struct {
			Domain     string `json:"domain"`
			ExpectedIP string `json:"expected_ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload.Domain != "" {
			domain = payload.Domain
		}
		if payload.ExpectedIP != "" {
			expected = payload.ExpectedIP
		}
	}
	writeJSON(w, s.checker.CheckDNS(r.Context(), domain, expected))
}

func (s *Server) handleSetupCheckOrigin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.checker.CheckOrigin(r.Context()))
}

func (s *Server) handleSetupCheckSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := r.URL.Query().Get("domain")
	writeJSON(w, s.checker.CheckSSL(r.Context(), domain))
}

func (s *Server) handleSetupCheckTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.checker.CheckTraffic(r.Context()))
}

func (s *Server) handleSetupCheckRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.checker.CheckRules(r.Context()))
}

func (s *Server) handleSetupCheckHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.checker.CheckHistory(r.Context()))
}

func (s *Server) handleSetupCheckAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := r.URL.Query().Get("domain")
	expectedIP := r.URL.Query().Get("expected_ip")
	if r.Method == http.MethodPost {
		var p struct {
			Domain     string `json:"domain"`
			ExpectedIP string `json:"expected_ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		if p.Domain != "" {
			domain = p.Domain
		}
		if p.ExpectedIP != "" {
			expectedIP = p.ExpectedIP
		}
	}
	results := s.checker.RunAll(r.Context(), domain, expectedIP)
	writeJSON(w, map[string]interface{}{"results": results})
}

// ---- Errors panel ----

func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	s.errMu.Lock()
	out := make([]ErrorEvent, len(s.errBuf))
	copy(out, s.errBuf)
	s.errMu.Unlock()
	writeJSON(w, map[string]interface{}{"errors": out, "count": len(out)})
}

// ---- Health detail ----

func (s *Server) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.watchdog == nil {
		writeJSON(w, map[string]interface{}{"overall": "unknown", "subsystems": []watchdog.Health{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"overall":    s.watchdog.Overall(),
		"failures":   s.watchdog.Failures(),
		"subsystems": s.watchdog.Snapshot(),
	})
}

// ---- Zero-trust templates ----

func (s *Server) handleZeroTrustTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"templates": zerotrust.Templates(),
	})
}

// handlePrometheus exposes counters in Prometheus text exposition format so
// operators can scrape the WAF from their existing monitoring stack.
func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	if s.metrics == nil {
		return
	}
	if err := s.metrics.WritePrometheus(w); err != nil {
		log.Printf("web: prometheus exposition error: %v", err)
	}
}

// handleRuleCounters returns a JSON map of rule_id -> match count so the UI
// can highlight the noisiest rules and flag candidates for tuning.
func (s *Server) handleRuleCounters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.metrics == nil {
		writeJSON(w, map[string]interface{}{"counters": map[string]uint64{}})
		return
	}
	writeJSON(w, map[string]interface{}{"counters": s.metrics.RuleCountersSnapshot()})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	buf, err := json.Marshal(v)
	if err != nil {
		log.Printf("web: json marshal error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(buf); err != nil {
		log.Printf("web: write error: %v", err)
	}
}

var startTime = time.Now().UTC()

package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	stdnet "net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"strconv"

	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/core"
	"wewaf/internal/history"
	"wewaf/internal/host"
	"wewaf/internal/limits"
	"wewaf/internal/ssl"
	"wewaf/internal/telemetry"
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

	meshEnabled  bool
	meshPeers    []string
	meshAPIKey   string
	meshLastSync time.Time
	meshMu       sync.RWMutex
}

// Deps wires optional subsystems into the admin server.
type Deps struct {
	Config     *config.Config
	Metrics    *telemetry.Metrics
	RulesFn    func() []map[string]interface{}
	BanList    *core.BanList
	Host       *host.Collector
	Connection *connection.Manager
	SSL        *ssl.Manager
	History    *history.Store

	MeshEnabled bool
	MeshPeers   []string
	MeshAPIKey  string
}

// NewServer creates the admin web server.
func NewServer(d Deps) *Server {
	return &Server{
		cfg:        d.Config,
		metrics:    d.Metrics,
		rulesFn:    d.RulesFn,
		banList:    d.BanList,
		host:       d.Host,
		connection: d.Connection,
		ssl:        d.SSL,
		history:    d.History,

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

	mux.Handle("/api/", s.withCORS(s.withAuth(api)))

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
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(data)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	expected := os.Getenv("WAF_API_KEY")
	if expected == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key != expected {
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
		writeJSON(w, s.cfg.Snapshot())
	case http.MethodPost:
		var payload struct {
			Mode                   string   `json:"mode"`
			HistoryRotateHours     int      `json:"history_rotate_hours"`
			EgressEnabled          *bool    `json:"egress_enabled"`
			EgressAddr             string   `json:"egress_addr"`
			EgressAllowlist        []string `json:"egress_allowlist"`
			EgressBlockPrivateIPs  *bool    `json:"egress_block_private_ips"`
			MeshEnabled            *bool    `json:"mesh_enabled"`
			MeshPeers              []string `json:"mesh_peers"`
			MeshGossipIntervalSec  int      `json:"mesh_gossip_interval_sec"`
			MeshAPIKey             string   `json:"mesh_api_key"`
			MeshSyncTimeoutSec     int      `json:"mesh_sync_timeout_sec"`
			SecurityHeadersEnabled *bool    `json:"security_headers_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if payload.Mode != "" {
			if payload.Mode != "active" && payload.Mode != "detection" && payload.Mode != "learning" {
				http.Error(w, "Invalid mode", http.StatusBadRequest)
				return
			}
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
		if payload.MeshAPIKey != "" {
			s.cfg.MeshAPIKey = payload.MeshAPIKey
			s.meshAPIKey = payload.MeshAPIKey
		}
		if payload.SecurityHeadersEnabled != nil {
			s.cfg.SecurityHeadersEnabled = *payload.SecurityHeadersEnabled
		}
		writeJSON(w, map[string]interface{}{"status": "ok", "mode": s.cfg.ModeSnapshot(), "history_rotate_hours": s.cfg.HistoryRotateHours})
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
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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
	// Simple shared-secret auth between peers.
	if s.meshAPIKey != "" && r.Header.Get("X-Mesh-Key") != s.meshAPIKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var payload struct {
		Bans []core.BanEntry `json:"bans"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// Merge incoming bans into local ban list.
	if s.banList != nil {
		for _, b := range payload.Bans {
			if b.IP == "" || stdnet.ParseIP(b.IP) == nil {
				continue
			}
			duration := time.Until(b.ExpiresAt)
			if duration <= 0 {
				continue
			}
			s.banList.Ban(b.IP, b.Reason, duration)
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

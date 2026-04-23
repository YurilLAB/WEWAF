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
			Mode string `json:"mode"`
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
		writeJSON(w, map[string]string{"status": "ok", "mode": s.cfg.ModeSnapshot()})
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
				Timestamp: time.Now().UTC(),
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

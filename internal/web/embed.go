package web

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/limits"
	"wewaf/internal/telemetry"
)

//go:embed index.html
//go:embed world-topology.json
//go:embed assets/*
var content embed.FS

// Server serves the embedded UI and JSON APIs.
type Server struct {
	cfg     *config.Config
	metrics *telemetry.Metrics
}

// NewServer creates the admin web server.
func NewServer(cfg *config.Config, metrics *telemetry.Metrics) *Server {
	return &Server{cfg: cfg, metrics: metrics}
}

// RegisterRoutes wires all admin endpoints.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// API routes with optional auth and CORS.
	api := http.NewServeMux()
	api.HandleFunc("/api/metrics", s.handleMetrics)
	api.HandleFunc("/api/stats", s.handleStats)
	api.HandleFunc("/api/config", s.handleConfig)
	api.HandleFunc("/api/blocks", s.handleBlocks)
	api.HandleFunc("/api/traffic", s.handleTraffic)
	api.HandleFunc("/api/rules", s.handleRules)

	mux.Handle("/api/", s.withCORS(s.withAuth(api)))

	// Static files — serve embedded content directly.
	fileServer := http.FileServer(http.FS(content))
	mux.Handle("/assets/", fileServer)
	mux.HandleFunc("/world-topology.json", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
	writeJSON(w, map[string]interface{}{
		"recent": s.metrics.RecentBlocksSnapshot(50),
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
	writeJSON(w, map[string]interface{}{
		"rules": []map[string]string{
			{"id": "XSS-001", "name": "XSS Script Tag", "severity": "critical"},
			{"id": "SQLI-001", "name": "SQLi Union Select", "severity": "critical"},
			{"id": "RCE-001", "name": "RCE Command Substitution", "severity": "critical"},
			{"id": "TRAV-001", "name": "Traversal Null Byte", "severity": "high"},
			{"id": "SSRF-001", "name": "SSRF Cloud Metadata", "severity": "high"},
			{"id": "SCAN-001", "name": "Known Scanner UA", "severity": "medium"},
		},
	})
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

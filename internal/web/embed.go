package web

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
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
	// API routes
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/blocks", s.handleBlocks)
	mux.HandleFunc("/api/traffic", s.handleTraffic)

	// Static files — serve embedded content directly
	fileServer := http.FileServer(http.FS(content))
	mux.Handle("/assets/", fileServer)
	mux.HandleFunc("/world-topology.json", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
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
	writeJSON(w, s.metrics.Snapshot()["traffic_history"])
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: json encode error: %v", err)
	}
}

var startTime = time.Now().UTC()

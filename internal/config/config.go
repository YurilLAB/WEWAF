package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
)

// Config holds all WAF runtime settings.
type Config struct {
	// Proxy settings
	ListenAddr      string `json:"listen_addr"`      // e.g. ":8080"
	AdminAddr       string `json:"admin_addr"`       // e.g. ":8443"
	BackendURL      string `json:"backend_url"`      // e.g. "http://localhost:3000"
	TrustXFF        bool   `json:"trust_xff"`        // trust X-Forwarded-For header
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

	// Distributed threat mesh
	MeshEnabled           bool     `json:"mesh_enabled"`
	MeshPeers             []string `json:"mesh_peers"`
	MeshGossipIntervalSec int      `json:"mesh_gossip_interval_sec"`
	MeshAPIKey            string   `json:"mesh_api_key"`
	MeshSyncTimeoutSec    int      `json:"mesh_sync_timeout_sec"`

	// Response hardening
	SecurityHeadersEnabled bool `json:"security_headers_enabled"`

	modeAtomic atomic.Value // stores string for hot-swapping Mode without copying mutexes
}

// Default returns a safe baseline configuration.
func Default() *Config {
	c := &Config{
		ListenAddr:               ":8080",
		AdminAddr:                ":8443",
		BackendURL:               "http://localhost:3000",
		TrustXFF:                 false,
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
		MeshEnabled:              false,
		MeshPeers:                []string{},
		MeshGossipIntervalSec:    60,
		MeshSyncTimeoutSec:       10,
		SecurityHeadersEnabled:   true,
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
	return nil
}

// Snapshot returns a pointer to a shallow copy for safe read-only access.
// Do not modify the returned value.
func (c *Config) Snapshot() *Config {
	cp := &Config{
		ListenAddr:               c.ListenAddr,
		AdminAddr:                c.AdminAddr,
		BackendURL:               c.BackendURL,
		TrustXFF:                 c.TrustXFF,
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
		MeshEnabled:              c.MeshEnabled,
		MeshPeers:                make([]string, len(c.MeshPeers)),
		MeshGossipIntervalSec:    c.MeshGossipIntervalSec,
		MeshAPIKey:               c.MeshAPIKey,
		MeshSyncTimeoutSec:       c.MeshSyncTimeoutSec,
		SecurityHeadersEnabled:   c.SecurityHeadersEnabled,
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

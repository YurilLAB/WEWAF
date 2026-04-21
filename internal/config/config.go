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

	// Engine behaviour
	Mode         string   `json:"mode"`           // "active", "detection", "learning"
	LogLevel     string   `json:"log_level"`      // "debug", "info", "warn", "error"
	AuditLogPath string   `json:"audit_log_path"`
	RuleFiles    []string `json:"rule_files"`

	modeAtomic atomic.Value // stores string for hot-swapping Mode without copying mutexes
}

// Default returns a safe baseline configuration.
func Default() *Config {
	c := &Config{
		ListenAddr:          ":8080",
		AdminAddr:           ":8443",
		BackendURL:          "http://localhost:3000",
		TrustXFF:            false,
		ReadTimeoutSec:      30,
		WriteTimeoutSec:     30,
		MaxCPUCores:         runtime.NumCPU(),
		MaxMemoryMB:         0,
		MaxConcurrentReq:    10000,
		MaxBodyBytes:        10 * 1024 * 1024, // 10 MB
		BlockThreshold:      100,
		RateLimitRPS:        100,
		RateLimitBurst:      150,
		BruteForceWindowSec: 300,
		BruteForceThreshold: 10,
		Mode:                "active",
		LogLevel:            "info",
		AuditLogPath:        "",
		RuleFiles:           []string{"rules.json"},
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
	return nil
}

// Snapshot returns a pointer to a shallow copy for safe read-only access.
// Do not modify the returned value.
func (c *Config) Snapshot() *Config {
	cp := *c
	cp.RuleFiles = make([]string, len(c.RuleFiles))
	copy(cp.RuleFiles, c.RuleFiles)
	cp.modeAtomic = atomic.Value{}
	cp.modeAtomic.Store(c.ModeSnapshot())
	return &cp
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

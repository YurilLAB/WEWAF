// Package connection tracks the WAF's connectivity to its upstream backend.
package connection

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Status is returned by /api/connection/status.
type Status struct {
	Connected        bool      `json:"connected"`
	LastPingMs       int64     `json:"last_ping_ms"`
	LastConnectedAt  time.Time `json:"last_connected_at"`
	ConnectionMethod string    `json:"connection_method"`
	FailoverActive   bool      `json:"failover_active"`
}

// Config is returned/accepted by /api/connection/config.
type Config struct {
	BackendURL      string `json:"backend_url"`
	ListenAddr      string `json:"listen_addr"`
	AdminAddr       string `json:"admin_addr"`
	PollIntervalSec int    `json:"poll_interval_sec"`
	RetryAttempts   int    `json:"retry_attempts"`
	TimeoutMs       int    `json:"timeout_ms"`
}

// Manager probes the backend and exposes live connection status.
type Manager struct {
	mu       sync.RWMutex
	cfg      Config
	status   Status
	stopOnce sync.Once
	stopCh   chan struct{}
	client   *http.Client
}

// NewManager constructs a manager seeded with initial config.
func NewManager(initial Config) *Manager {
	if initial.PollIntervalSec <= 0 {
		initial.PollIntervalSec = 10
	}
	if initial.TimeoutMs <= 0 {
		initial.TimeoutMs = 2000
	}
	if initial.RetryAttempts <= 0 {
		initial.RetryAttempts = 3
	}
	m := &Manager{
		cfg:    initial,
		stopCh: make(chan struct{}),
		status: Status{ConnectionMethod: "http"},
	}
	m.rebuildClient()
	return m
}

func (m *Manager) rebuildClient() {
	m.client = &http.Client{
		Timeout: time.Duration(m.cfg.TimeoutMs) * time.Millisecond,
	}
}

// Start launches the background probe loop.
func (m *Manager) Start(ctx context.Context) {
	go m.loop(ctx)
}

// Stop halts the probe loop.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

func (m *Manager) loop(ctx context.Context) {
	defer func() { _ = recover() }()
	for {
		m.mu.RLock()
		interval := time.Duration(m.cfg.PollIntervalSec) * time.Second
		m.mu.RUnlock()
		if interval <= 0 {
			interval = 10 * time.Second
		}
		m.Probe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(interval):
		}
	}
}

// Probe sends a single health request to the backend and updates status.
func (m *Manager) Probe(ctx context.Context) Status {
	m.mu.RLock()
	backend := m.cfg.BackendURL
	m.mu.RUnlock()

	started := time.Now()
	ok := false
	if backend != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend, nil)
		if err == nil {
			resp, err := m.client.Do(req)
			if err == nil {
				resp.Body.Close()
				// Any response — even a 5xx — means the backend is reachable.
				ok = true
			}
		}
	}
	ping := time.Since(started).Milliseconds()

	m.mu.Lock()
	m.status.Connected = ok
	m.status.LastPingMs = ping
	if ok {
		m.status.LastConnectedAt = time.Now().UTC()
	}
	snap := m.status
	m.mu.Unlock()
	return snap
}

// StatusSnapshot returns the last known connection status.
func (m *Manager) StatusSnapshot() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// ConfigSnapshot returns the current connection config.
func (m *Manager) ConfigSnapshot() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// UpdateConfig merges non-zero fields from patch into the current config.
func (m *Manager) UpdateConfig(patch Config) Config {
	m.mu.Lock()
	if patch.BackendURL != "" {
		m.cfg.BackendURL = patch.BackendURL
	}
	if patch.ListenAddr != "" {
		m.cfg.ListenAddr = patch.ListenAddr
	}
	if patch.AdminAddr != "" {
		m.cfg.AdminAddr = patch.AdminAddr
	}
	if patch.PollIntervalSec > 0 {
		m.cfg.PollIntervalSec = patch.PollIntervalSec
	}
	if patch.RetryAttempts > 0 {
		m.cfg.RetryAttempts = patch.RetryAttempts
	}
	if patch.TimeoutMs > 0 {
		m.cfg.TimeoutMs = patch.TimeoutMs
		m.rebuildClient()
	}
	out := m.cfg
	m.mu.Unlock()
	return out
}

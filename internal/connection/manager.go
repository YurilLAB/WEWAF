// Package connection tracks the WAF's connectivity to its upstream backend.
//
// The Manager probes the backend on a fixed interval, stores the last status,
// and maintains two ring buffers:
//
//   - Ping history: every probe's latency, so the UI can render a sparkline.
//   - Event history: state transitions (online↔offline), so the UI can show a
//     session timeline without synthesising it client-side.
//
// Probes are guarded so only one runs at a time — a slow backend can't pile
// up an unbounded queue of in-flight requests.
package connection

import (
	"context"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pingHistoryCap  = 100
	eventHistoryCap = 100
)

// Status is returned by /api/connection/status.
type Status struct {
	Connected        bool      `json:"connected"`
	LastPingMs       int64     `json:"last_ping_ms"`
	LastConnectedAt  time.Time `json:"last_connected_at"`
	ConnectionMethod string    `json:"connection_method"`
	FailoverActive   bool      `json:"failover_active"`
	TotalProbes      uint64    `json:"total_probes"`
	FailedProbes     uint64    `json:"failed_probes"`
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

// PingSample is a single latency observation.
type PingSample struct {
	Timestamp time.Time `json:"timestamp"`
	PingMs    int64     `json:"ping_ms"`
	OK        bool      `json:"ok"`
}

// Event records a connection state transition.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	State     string    `json:"state"` // "online" | "offline"
	PingMs    int64     `json:"ping_ms"`
}

// Manager probes the backend and exposes live connection status.
type Manager struct {
	mu           sync.RWMutex
	cfg          Config
	status       Status
	pingHistory  []PingSample
	events       []Event
	stopOnce     sync.Once
	stopCh       chan struct{}
	client       *http.Client
	probing      atomic.Bool // true while a probe is in flight
	totalProbes  atomic.Uint64
	failedProbes atomic.Uint64
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
		cfg:         initial,
		stopCh:      make(chan struct{}),
		status:      Status{ConnectionMethod: "http"},
		pingHistory: make([]PingSample, 0, pingHistoryCap),
		events:      make([]Event, 0, eventHistoryCap),
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("connection.Manager: loop goroutine panic: %v", r)
		}
	}()
	// One reusable timer so we don't leak one per iteration via time.After.
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		m.mu.RLock()
		interval := time.Duration(m.cfg.PollIntervalSec) * time.Second
		m.mu.RUnlock()
		if interval <= 0 {
			interval = 10 * time.Second
		}
		m.Probe(ctx)
		timer.Reset(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-m.stopCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}

// Probe sends a single health request to the backend and updates status.
// Concurrent calls are coalesced: only one probe runs at a time — additional
// callers get the last known status without triggering a new request.
func (m *Manager) Probe(ctx context.Context) Status {
	if !m.probing.CompareAndSwap(false, true) {
		return m.StatusSnapshot()
	}
	defer m.probing.Store(false)

	// Capture backend + client atomically so a concurrent UpdateConfig
	// swapping m.client doesn't race against the read below.
	m.mu.RLock()
	backend := m.cfg.BackendURL
	timeout := time.Duration(m.cfg.TimeoutMs) * time.Millisecond
	prevConnected := m.status.Connected
	client := m.client
	m.mu.RUnlock()

	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	ok := false
	if backend != "" && client != nil {
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, backend, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				// Any response — even a 5xx — means the backend is reachable.
				ok = true
			}
		}
	}
	ping := time.Since(started).Milliseconds()

	m.totalProbes.Add(1)
	if !ok {
		m.failedProbes.Add(1)
	}

	now := time.Now().UTC()
	m.mu.Lock()
	m.status.Connected = ok
	m.status.LastPingMs = ping
	m.status.TotalProbes = m.totalProbes.Load()
	m.status.FailedProbes = m.failedProbes.Load()
	if ok {
		m.status.LastConnectedAt = now
	}

	// Record ping history.
	sample := PingSample{Timestamp: now, PingMs: ping, OK: ok}
	m.pingHistory = append(m.pingHistory, sample)
	if len(m.pingHistory) > pingHistoryCap {
		over := len(m.pingHistory) - pingHistoryCap
		copy(m.pingHistory, m.pingHistory[over:])
		m.pingHistory = m.pingHistory[:pingHistoryCap]
	}

	// Record transition events only when state changes.
	if ok != prevConnected {
		ev := Event{Timestamp: now, PingMs: ping}
		if ok {
			ev.State = "online"
		} else {
			ev.State = "offline"
		}
		m.events = append(m.events, ev)
		if len(m.events) > eventHistoryCap {
			over := len(m.events) - eventHistoryCap
			copy(m.events, m.events[over:])
			m.events = m.events[:eventHistoryCap]
		}
	}

	snap := m.status
	m.mu.Unlock()
	return snap
}

// StatusSnapshot returns the last known connection status.
func (m *Manager) StatusSnapshot() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.TotalProbes = m.totalProbes.Load()
	s.FailedProbes = m.failedProbes.Load()
	return s
}

// ConfigSnapshot returns the current connection config.
func (m *Manager) ConfigSnapshot() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// PingHistory returns a copy of the ping-latency ring buffer.
func (m *Manager) PingHistory() []PingSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PingSample, len(m.pingHistory))
	copy(out, m.pingHistory)
	return out
}

// EventHistory returns a copy of state transition events.
func (m *Manager) EventHistory() []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
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

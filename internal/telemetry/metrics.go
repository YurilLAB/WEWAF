// Package telemetry provides in-memory counters and bounded ring buffers for
// the WAF's hot paths. The state here is intentionally small: any piece of
// data that should outlive a restart or a rotation window is flushed through
// the optional Persister (typically an *history.Store).
package telemetry

import (
	"log"
	"sync"
	"time"
)

const (
	// Keep a small rolling window in memory so the UI can render without
	// going to disk. Older records are already persisted through Persister.
	defaultRecentBlocksCap = 500
	defaultTrafficCap      = 288 // 24 h @ 5-min buckets
	// UniqueIPs is bounded so an adversary can't OOM us by rotating source
	// IPs. The set is reset on history rotation so long-running daemons keep
	// reporting fresh counts.
	maxUniqueIPs = 100_000
)

// Persister receives every event for durable storage. Implementations MUST be
// non-blocking (drop-on-full) so telemetry never stalls the proxy's hot path.
type Persister interface {
	EnqueueBlock(BlockEvent)
	EnqueueRequest(ip string, blocked bool)
	EnqueueTrafficPoint(BlockTrafficPoint)
}

// BlockEvent mirrors history.BlockEvent at this layer to avoid a cyclic
// import on history. The adapter in cmd/waf bridges the two.
type BlockEvent struct {
	Timestamp    time.Time
	IP           string
	Method       string
	Path         string
	RuleID       string
	RuleCategory string
	Score        int
	Message      string
}

// BlockTrafficPoint mirrors history.TrafficPoint without importing history.
type BlockTrafficPoint struct {
	Timestamp time.Time
	Requests  int
	Blocked   int
}

// Metrics holds runtime counters and ring buffers.
type Metrics struct {
	mu sync.RWMutex

	TotalRequests   uint64
	BlockedRequests uint64
	PassedRequests  uint64
	TotalBytesIn    uint64
	TotalBytesOut   uint64
	ErrorCount      uint64
	UniqueIPs       map[string]struct{}
	RecentBlocks    []BlockRecord
	TrafficHistory  []TrafficPoint

	recentBlocksCap int
	trafficCap      int
	persister       Persister
}

// BlockRecord stores a single blocked request summary.
type BlockRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	IP           string    `json:"ip"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	RuleID       string    `json:"rule_id"`
	RuleCategory string    `json:"rule_category,omitempty"`
	Score        int       `json:"score"`
	Message      string    `json:"message"`
}

// TrafficPoint stores request volume at a point in time.
type TrafficPoint struct {
	Time     time.Time `json:"time"`
	Requests int       `json:"requests"`
	Blocked  int       `json:"blocked"`
}

// NewMetrics creates a metrics collector with the default caps.
func NewMetrics() *Metrics {
	return &Metrics{
		UniqueIPs:       make(map[string]struct{}, 1024),
		RecentBlocks:    make([]BlockRecord, 0, defaultRecentBlocksCap),
		TrafficHistory:  make([]TrafficPoint, 0, defaultTrafficCap),
		recentBlocksCap: defaultRecentBlocksCap,
		trafficCap:      defaultTrafficCap,
	}
}

// SetPersister attaches a durable-storage backend. May be nil.
func (m *Metrics) SetPersister(p Persister) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.persister = p
	m.mu.Unlock()
}

// OnRotation clears in-memory aggregates that are bounded per rotation window.
// The ring buffers are left alone so the UI still has recent data to render.
func (m *Metrics) OnRotation() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.UniqueIPs = make(map[string]struct{}, 1024)
	m.mu.Unlock()
}

// RecordRequest increments total requests and tracks the client IP.
func (m *Metrics) RecordRequest(ip string, bytesIn int) {
	defer recoverPanic("RecordRequest")
	m.mu.Lock()
	m.TotalRequests++
	if len(m.UniqueIPs) < maxUniqueIPs && ip != "" {
		m.UniqueIPs[ip] = struct{}{}
	}
	m.TotalBytesIn += uint64(maxInt(bytesIn, 0))
	p := m.persister
	m.mu.Unlock()
	if p != nil && ip != "" {
		p.EnqueueRequest(ip, false)
	}
}

// RecordBlock increments blocked requests and stores a summary.
func (m *Metrics) RecordBlock(ip, method, path, ruleID, message string, score int) {
	m.RecordBlockWithCategory(ip, method, path, ruleID, categoryFromRuleID(ruleID), message, score)
}

// RecordBlockWithCategory is the full-fidelity block recorder. The category
// ends up in both the in-memory ring buffer and the persisted DB row so the
// Security Events page can render proper type badges.
func (m *Metrics) RecordBlockWithCategory(ip, method, path, ruleID, category, message string, score int) {
	defer recoverPanic("RecordBlockWithCategory")
	now := time.Now().UTC()
	rec := BlockRecord{
		Timestamp:    now,
		IP:           ip,
		Method:       method,
		Path:         path,
		RuleID:       ruleID,
		RuleCategory: category,
		Score:        score,
		Message:      message,
	}
	m.mu.Lock()
	m.BlockedRequests++
	m.RecentBlocks = append(m.RecentBlocks, rec)
	if len(m.RecentBlocks) > m.recentBlocksCap {
		// Retain only the most recent N; older ones are already persisted.
		over := len(m.RecentBlocks) - m.recentBlocksCap
		copy(m.RecentBlocks, m.RecentBlocks[over:])
		m.RecentBlocks = m.RecentBlocks[:m.recentBlocksCap]
	}
	p := m.persister
	m.mu.Unlock()
	if p != nil {
		p.EnqueueBlock(BlockEvent{
			Timestamp:    now,
			IP:           ip,
			Method:       method,
			Path:         path,
			RuleID:       ruleID,
			RuleCategory: category,
			Score:        score,
			Message:      message,
		})
	}
}

// RecordPass increments passed requests and records response status.
func (m *Metrics) RecordPass(bytesOut int, statusCode int) {
	defer recoverPanic("RecordPass")
	m.mu.Lock()
	m.PassedRequests++
	m.TotalBytesOut += uint64(maxInt(bytesOut, 0))
	m.mu.Unlock()
	_ = statusCode // reserved for future per-status telemetry
}

// RecordBlockFromResponse preserved for backwards compatibility with callers.
func (m *Metrics) RecordBlockFromResponse(ip, method, path, ruleID, message string, score int) {
	m.RecordBlock(ip, method, path, ruleID, message, score)
}

// RecordError bumps the backend-error counter.
func (m *Metrics) RecordError() {
	defer recoverPanic("RecordError")
	m.mu.Lock()
	m.ErrorCount++
	m.mu.Unlock()
}

// Snapshot returns a read-only copy of current metrics.
func (m *Metrics) Snapshot() map[string]interface{} {
	defer recoverPanic("Snapshot")
	m.mu.RLock()
	defer m.mu.RUnlock()
	recent := make([]BlockRecord, len(m.RecentBlocks))
	copy(recent, m.RecentBlocks)
	history := make([]TrafficPoint, len(m.TrafficHistory))
	copy(history, m.TrafficHistory)
	return map[string]interface{}{
		"total_requests":   m.TotalRequests,
		"blocked_requests": m.BlockedRequests,
		"passed_requests":  m.PassedRequests,
		"total_bytes_in":   m.TotalBytesIn,
		"total_bytes_out":  m.TotalBytesOut,
		"errors":           m.ErrorCount,
		"unique_ips":       len(m.UniqueIPs),
		"recent_blocks":    recent,
		"traffic_history":  history,
	}
}

// RecentBlocksSnapshot returns the last N block records.
func (m *Metrics) RecentBlocksSnapshot(n int) []BlockRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n <= 0 || n >= len(m.RecentBlocks) {
		out := make([]BlockRecord, len(m.RecentBlocks))
		copy(out, m.RecentBlocks)
		return out
	}
	out := make([]BlockRecord, n)
	copy(out, m.RecentBlocks[len(m.RecentBlocks)-n:])
	return out
}

// AddTrafficPoint appends a traffic sample for the line graph.
func (m *Metrics) AddTrafficPoint(reqs, blocked int) {
	defer recoverPanic("AddTrafficPoint")
	pt := TrafficPoint{
		Time:     time.Now().UTC(),
		Requests: reqs,
		Blocked:  blocked,
	}
	m.mu.Lock()
	m.TrafficHistory = append(m.TrafficHistory, pt)
	if len(m.TrafficHistory) > m.trafficCap {
		over := len(m.TrafficHistory) - m.trafficCap
		copy(m.TrafficHistory, m.TrafficHistory[over:])
		m.TrafficHistory = m.TrafficHistory[:m.trafficCap]
	}
	p := m.persister
	m.mu.Unlock()
	if p != nil {
		p.EnqueueTrafficPoint(BlockTrafficPoint{Timestamp: pt.Time, Requests: reqs, Blocked: blocked})
	}
}

// GetTrafficHistory returns a copy of the traffic history slice.
func (m *Metrics) GetTrafficHistory() []TrafficPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]TrafficPoint, len(m.TrafficHistory))
	copy(out, m.TrafficHistory)
	return out
}

// categoryFromRuleID maps a rule ID prefix to a coarse UI category so
// Security Events can show accurate type badges (xss / sqli / ddos / ...).
func categoryFromRuleID(ruleID string) string {
	switch {
	case ruleID == "":
		return "other"
	case ruleID == "RATE-LIMIT":
		return "rate_limit"
	case ruleID == "BRUTE-FORCE":
		return "brute_force"
	case ruleID == "REPUTATION":
		return "ip_reputation"
	case hasPrefix(ruleID, "XSS"):
		return "xss"
	case hasPrefix(ruleID, "SQLI"), hasPrefix(ruleID, "SQL-"):
		return "sql_injection"
	case hasPrefix(ruleID, "RCE"), hasPrefix(ruleID, "CMD"):
		return "rce"
	case hasPrefix(ruleID, "LFI"), hasPrefix(ruleID, "PATH"), hasPrefix(ruleID, "TRAV"):
		return "path_traversal"
	case hasPrefix(ruleID, "SSRF"):
		return "ssrf"
	case hasPrefix(ruleID, "XXE"):
		return "xxe"
	case hasPrefix(ruleID, "NOSQL"):
		return "nosql_injection"
	case hasPrefix(ruleID, "LDAP"):
		return "ldap_injection"
	case hasPrefix(ruleID, "JNDI"):
		return "jndi"
	case hasPrefix(ruleID, "SCAN"), hasPrefix(ruleID, "BOT"):
		return "bot"
	case hasPrefix(ruleID, "SMUG"):
		return "http_smuggling"
	case hasPrefix(ruleID, "UPLOAD"):
		return "file_upload"
	case hasPrefix(ruleID, "REDIR"):
		return "open_redirect"
	case hasPrefix(ruleID, "CRLF"):
		return "crlf"
	case hasPrefix(ruleID, "PROTO"):
		return "prototype_pollution"
	}
	return "other"
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func recoverPanic(where string) {
	if rec := recover(); rec != nil {
		log.Printf("telemetry: panic in %s: %v", where, rec)
	}
}

package telemetry

import (
	"sync"
	"time"
)

// Metrics holds runtime counters and gauges.
type Metrics struct {
	mu sync.RWMutex

	TotalRequests      uint64
	BlockedRequests    uint64
	PassedRequests     uint64
	TotalBytesIn       uint64
	TotalBytesOut      uint64
	UniqueIPs          map[string]struct{}
	RecentBlocks       []BlockRecord
	TrafficHistory     []TrafficPoint
}

// BlockRecord stores a single blocked request summary.
type BlockRecord struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	RuleID    string    `json:"rule_id"`
	Score     int       `json:"score"`
	Message   string    `json:"message"`
}

// TrafficPoint stores request volume at a point in time.
type TrafficPoint struct {
	Time     time.Time `json:"time"`
	Requests int       `json:"requests"`
	Blocked  int       `json:"blocked"`
}

// NewMetrics creates a metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		UniqueIPs:      make(map[string]struct{}),
		RecentBlocks:   make([]BlockRecord, 0, 100),
		TrafficHistory: make([]TrafficPoint, 0, 288), // 5-min buckets for 24h
	}
}

// RecordRequest increments total requests and tracks the client IP.
func (m *Metrics) RecordRequest(ip string, bytesIn int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalRequests++
	m.UniqueIPs[ip] = struct{}{}
	m.TotalBytesIn += uint64(bytesIn)
}

// RecordBlock increments blocked requests and stores a summary.
func (m *Metrics) RecordBlock(ip, method, path, ruleID, message string, score int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BlockedRequests++
	rec := BlockRecord{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		Method:    method,
		Path:      path,
		RuleID:    ruleID,
		Score:     score,
		Message:   message,
	}
	m.RecentBlocks = append(m.RecentBlocks, rec)
	if len(m.RecentBlocks) > 100 {
		m.RecentBlocks = m.RecentBlocks[len(m.RecentBlocks)-100:]
	}
}

// RecordPass increments passed requests and records response status.
func (m *Metrics) RecordPass(bytesOut int, statusCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PassedRequests++
	m.TotalBytesOut += uint64(bytesOut)
	_ = statusCode // reserved for future per-status telemetry
}

// RecordBlock increments blocked requests and stores a summary.
func (m *Metrics) RecordBlockFromResponse(ip, method, path, ruleID, message string, score int) {
	m.RecordBlock(ip, method, path, ruleID, message, score)
}

// Snapshot returns a read-only copy of current metrics.
func (m *Metrics) Snapshot() map[string]interface{} {
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
		"unique_ips":       len(m.UniqueIPs),
		"recent_blocks":    recent,
		"traffic_history":  history,
	}
}

// RecentBlocksSnapshot returns the last N block records.
func (m *Metrics) RecentBlocksSnapshot(n int) []BlockRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n >= len(m.RecentBlocks) {
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
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TrafficHistory = append(m.TrafficHistory, TrafficPoint{
		Time:     time.Now().UTC(),
		Requests: reqs,
		Blocked:  blocked,
	})
	// Keep last 24 hours of 5-minute buckets = 288 points.
	if len(m.TrafficHistory) > 288 {
		trimmed := make([]TrafficPoint, 288)
		copy(trimmed, m.TrafficHistory[len(m.TrafficHistory)-288:])
		m.TrafficHistory = trimmed
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

// RecordError increments a backend error counter.
func (m *Metrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// TODO: add dedicated error counter field
}

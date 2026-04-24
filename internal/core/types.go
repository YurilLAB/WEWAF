package core

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Phase represents a stage in the HTTP transaction lifecycle.
type Phase int

const (
	PhaseRequestHeaders  Phase = iota // headers received
	PhaseRequestBody                  // body fully buffered
	PhaseResponseHeaders              // backend response headers
	PhaseResponseBody                 // backend response body (optional)
	PhaseLogging                      // after response sent
	PhaseEgressRequest                // outbound request from backend
)

func (p Phase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseResponseBody:
		return "response_body"
	case PhaseLogging:
		return "logging"
	case PhaseEgressRequest:
		return "egress_request"
	default:
		return "unknown"
	}
}

// Action is the enforcement decision for a rule match.
type Action int

const (
	ActionPass  Action = iota // allow traffic
	ActionBlock               // return HTTP error
	ActionDrop                // close connection (no response)
	ActionLog                 // log only, do not block
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionBlock:
		return "block"
	case ActionDrop:
		return "drop"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// Severity maps a score to a human-readable level.
type Severity int

const (
	SeverityInfo     Severity = iota // 0-24
	SeverityLow                      // 25-49
	SeverityMedium                   // 50-74
	SeverityHigh                     // 75-99
	SeverityCritical                 // 100+
)

// Rule is a single WAF inspection rule.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Phase       Phase    `json:"phase"`
	Score       int      `json:"score"`
	Action      Action   `json:"action"`
	Description string   `json:"description"`
	Targets     []string `json:"targets"` // e.g. ["args", "headers", "body"]
	Pattern     string   `json:"pattern"` // regex or literal; compiled by engine
}

// Match records a single rule hit.
type Match struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Phase     Phase     `json:"phase"`
	Target    string    `json:"target"` // e.g. "args.q"
	Value     string    `json:"value"`  // truncated snippet
	Score     int       `json:"score"`
	Action    Action    `json:"action"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// Interruption tells the host what to do when the engine decides to stop the transaction.
type Interruption struct {
	Action  Action  `json:"action"`
	Status  int     `json:"status"`
	Message string  `json:"message"`
	Matches []Match `json:"matches"`
}

// Transaction holds state for one HTTP request/response.
type Transaction struct {
	ID       string
	Started  time.Time
	ClientIP string

	Request        *http.Request
	ResponseWriter http.ResponseWriter

	mu        sync.RWMutex
	Score     int
	Matches   []Match
	Blocked   bool
	BlockedAt Phase
	Metadata  map[string]interface{} // arbitrary per-tx data (e.g. bruteforce counters)
}

// NewTransaction creates a transaction with safe defaults.
func NewTransaction(w http.ResponseWriter, r *http.Request, trustXFF bool) *Transaction {
	tx := &Transaction{
		ID:             generateID(),
		Started:        time.Now().UTC(),
		ClientIP:       clientIP(r, trustXFF),
		Request:        r,
		ResponseWriter: w,
		Metadata:       make(map[string]interface{}),
	}
	return tx
}

// AddMatch records a rule hit thread-safely.
func (tx *Transaction) AddMatch(m Match) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.Score += m.Score
	tx.Matches = append(tx.Matches, m)
}

// ScoreSnapshot returns the current anomaly score safely.
func (tx *Transaction) ScoreSnapshot() int {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return tx.Score
}

// MatchesSnapshot returns a copy of current matches.
func (tx *Transaction) MatchesSnapshot() []Match {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	out := make([]Match, len(tx.Matches))
	copy(out, tx.Matches)
	return out
}

// MatchCount returns the number of recorded matches.
func (tx *Transaction) MatchCount() int {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return len(tx.Matches)
}

// SetBlocked marks the transaction as blocked at a specific phase.
func (tx *Transaction) SetBlocked(at Phase) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.Blocked = true
	tx.BlockedAt = at
}

// IsBlocked reports whether the transaction has been blocked.
func (tx *Transaction) IsBlocked() bool {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return tx.Blocked
}

// SetMetadata stores arbitrary key/value data.
func (tx *Transaction) SetMetadata(key string, val interface{}) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.Metadata[key] = val
}

// MetadataValue retrieves a metadata value.
func (tx *Transaction) MetadataValue(key string) (interface{}, bool) {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	v, ok := tx.Metadata[key]
	return v, ok
}

// generateID creates a simple unique transaction ID.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), nextCounter())
}

var (
	counterMu sync.Mutex
	counter   uint64
)

func nextCounter() uint64 {
	counterMu.Lock()
	defer counterMu.Unlock()
	counter++
	return counter
}

// clientIP extracts the remote address, optionally parsing X-Forwarded-For.
func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// BanEntry records a single IP ban.
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
	Timestamp time.Time `json:"timestamp"`
}

// BanList is a thread-safe in-memory IP ban list with automatic expiry.
type BanList struct {
	mu       sync.RWMutex
	entries  map[string]BanEntry
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewBanList creates a new empty BanList.
func NewBanList() *BanList {
	return &BanList{
		entries: make(map[string]BanEntry),
		stopCh:  make(chan struct{}),
	}
}

// StartCleanup launches a background goroutine that evicts expired entries
// every `interval`. Returns a stop function. Safe to call multiple times —
// subsequent calls are no-ops. This was previously missing, so expired bans
// stayed in memory forever under long-running daemons.
func (bl *BanList) StartCleanup(interval time.Duration) func() {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		defer func() { _ = recover() }()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				bl.Cleanup()
			case <-bl.stopCh:
				return
			}
		}
	}()
	return func() {
		bl.stopOnce.Do(func() { close(bl.stopCh) })
	}
}

// Ban adds or updates a ban entry for the given IP.
func (bl *BanList) Ban(ip, reason string, duration time.Duration) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	now := time.Now().UTC()
	bl.entries[ip] = BanEntry{
		IP:        ip,
		Reason:    reason,
		ExpiresAt: now.Add(duration),
		Timestamp: now,
	}
}

// Unban removes a ban for the given IP.
func (bl *BanList) Unban(ip string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	delete(bl.entries, ip)
}

// IsBanned returns true if the IP exists in the ban list and has not expired.
func (bl *BanList) IsBanned(ip string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	entry, ok := bl.entries[ip]
	if !ok {
		return false
	}
	return !time.Now().UTC().After(entry.ExpiresAt)
}

// List returns all active (non-expired) bans.
func (bl *BanList) List() []BanEntry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]BanEntry, 0, len(bl.entries))
	for _, entry := range bl.entries {
		if !now.After(entry.ExpiresAt) {
			out = append(out, entry)
		}
	}
	return out
}

// Cleanup removes expired entries from the ban list.
func (bl *BanList) Cleanup() {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	now := time.Now().UTC()
	for ip, entry := range bl.entries {
		if now.After(entry.ExpiresAt) {
			delete(bl.entries, ip)
		}
	}
}

// Count returns the number of active (non-expired) bans.
func (bl *BanList) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	now := time.Now().UTC()
	count := 0
	for _, entry := range bl.entries {
		if !now.After(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

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
	PhaseRequestHeaders Phase = iota // headers received
	PhaseRequestBody                 // body fully buffered
	PhaseResponseHeaders             // backend response headers
	PhaseResponseBody                // backend response body (optional)
	PhaseLogging                     // after response sent
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
	default:
		return "unknown"
	}
}

// Action is the enforcement decision for a rule match.
type Action int

const (
	ActionPass Action = iota // allow traffic
	ActionBlock              // return HTTP error
	ActionDrop               // close connection (no response)
	ActionLog                // log only, do not block
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
	SeverityInfo Severity = iota // 0-24
	SeverityLow                  // 25-49
	SeverityMedium               // 50-74
	SeverityHigh                 // 75-99
	SeverityCritical             // 100+
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
	Target    string    `json:"target"`    // e.g. "args.q"
	Value     string    `json:"value"`     // truncated snippet
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

package core

import (
	"fmt"
	"log"
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

	// Paranoia is the CRS-style sensitivity band this rule belongs to.
	// Rules with Paranoia > cfg.ParanoiaLevel are skipped at evaluation
	// time. 0 or unset counts as level 1 so the base rule set ships on.
	Paranoia int `json:"paranoia,omitempty"`

	// Category is an optional grouping tag used for UI filtering and for
	// the CRS category buckets (protocol-enforcement, xss, sqli, etc.).
	Category string `json:"category,omitempty"`
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
	IP         string    `json:"ip"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
	Timestamp  time.Time `json:"timestamp"`
	Offenses   int       `json:"offenses"`    // how many bans on this IP inside the backoff window
	LastBanned time.Time `json:"last_banned"` // most recent ban time (may equal Timestamp)
}

// BanList is a thread-safe in-memory IP ban list with automatic expiry.
type BanList struct {
	mu       sync.RWMutex
	entries  map[string]BanEntry
	history  map[string]banHistory // offender tracking for exponential backoff
	stopCh   chan struct{}
	stopOnce sync.Once
	// cleanupStarted gates StartCleanup so repeated invocations don't
	// each launch a fresh janitor goroutine. The previous design only
	// guarded the returned stop function with sync.Once, so a caller
	// that wired StartCleanup into both engine init and a watchdog
	// re-init path leaked goroutines that no stop function could reach.
	cleanupStarted sync.Once

	// Exponential-backoff configuration. When enabled, Ban's effective
	// duration = duration * multiplier^(offenses-1), clamped at maxDuration.
	// Offenses reset after backoffWindow has elapsed since the last ban.
	backoffEnabled    bool
	backoffMultiplier int
	backoffWindow     time.Duration
	maxDuration       time.Duration
}

// maxBanEntries caps the active-ban map. With BanList.Cleanup running on
// a ticker, expired entries are reaped quickly, but a determined attacker
// rotating through millions of IPs at long ban durations could otherwise
// grow the map without bound until the process OOMs. When the cap is hit
// new bans evict the oldest expiring entries first; if none have expired
// we randomly drop a small budget of entries (same shape as the limiter
// janitor's pathological-flood handling).
const maxBanEntries = 200_000

// banHistory tracks repeat-offender state outside of the active bans map so
// it survives the TTL expiry. This is what lets a returning offender get a
// longer ban the second time.
type banHistory struct {
	offenses   int
	lastBanned time.Time
}

// NewBanList creates a new empty BanList.
func NewBanList() *BanList {
	return &BanList{
		entries: make(map[string]BanEntry),
		history: make(map[string]banHistory),
		stopCh:  make(chan struct{}),
	}
}

// StartCleanup launches a background goroutine that evicts expired entries
// every `interval`. Returns a stop function. Safe to call multiple times —
// subsequent calls truly are no-ops now: only the first invocation spawns
// the janitor, so a caller wired into multiple init paths cannot leak
// goroutines (the stop function returned by every call still works because
// they all close the same shared stopCh).
func (bl *BanList) StartCleanup(interval time.Duration) func() {
	if interval <= 0 {
		interval = time.Minute
	}
	bl.cleanupStarted.Do(func() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Silent recovery here would lose eviction forever; the
					// goroutine returns on panic, so at least log it so an
					// operator can see why bans stopped being cleaned up.
					log.Printf("core.BanList: cleanup goroutine panic: %v", r)
				}
			}()
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
	})
	return func() {
		bl.stopOnce.Do(func() { close(bl.stopCh) })
	}
}

// ConfigureBackoff enables exponential-backoff bans. A multiplier of 2 and
// window of 24 h means a repeat ban within 24 hours doubles the duration, up
// to maxDuration. Passing enabled=false disables backoff. A multiplier < 2
// is silently clamped to 2 so an invalid API value doesn't let an offender
// rebuild state (previous behaviour was to silently disable backoff).
func (bl *BanList) ConfigureBackoff(enabled bool, multiplier int, window, maxDuration time.Duration) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if multiplier < 2 {
		multiplier = 2
	}
	if multiplier > 16 {
		multiplier = 16
	}
	bl.backoffEnabled = enabled
	bl.backoffMultiplier = multiplier
	bl.backoffWindow = window
	bl.maxDuration = maxDuration
}

// Ban adds or updates a ban entry for the given IP. When backoff is enabled,
// repeat bans on the same IP within the backoff window apply an exponential
// multiplier to the duration, capped at maxDuration.
func (bl *BanList) Ban(ip, reason string, duration time.Duration) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	now := time.Now().UTC()

	offenses := 1
	if bl.backoffEnabled && bl.backoffMultiplier > 1 {
		if bl.history == nil {
			bl.history = make(map[string]banHistory)
		}
		h, ok := bl.history[ip]
		if ok && (bl.backoffWindow <= 0 || now.Sub(h.lastBanned) <= bl.backoffWindow) {
			// Cap offenses at 10 — at multiplier=2 that's already 512× base,
			// well past any realistic maxDuration, so further loop iterations
			// only add work under the write lock. 10 keeps the exponent loop
			// at most 9 multiplications, unnoticeable.
			offenses = h.offenses + 1
			if offenses > 10 {
				offenses = 10
			}
		}
		// Apply multiplier^(offenses-1). Use overflow-safe math: once the
		// scaled value would exceed maxDuration (or time.Duration's limit),
		// clamp and stop. time.Duration is int64 nanoseconds, so max is
		// ~292 years — saturating there is the correct behaviour.
		scaled := duration
		for i := 1; i < offenses && scaled > 0; i++ {
			multiplier := time.Duration(bl.backoffMultiplier)
			// Overflow check: scaled*multiplier > maxInt64 iff scaled > maxInt64/multiplier.
			if multiplier > 0 && scaled > time.Duration(1<<62)/multiplier {
				scaled = bl.maxDuration
				if scaled <= 0 {
					scaled = time.Duration(1 << 62)
				}
				break
			}
			scaled = scaled * multiplier
			if bl.maxDuration > 0 && scaled > bl.maxDuration {
				scaled = bl.maxDuration
				break
			}
		}
		if scaled > duration {
			duration = scaled
		}
		bl.history[ip] = banHistory{offenses: offenses, lastBanned: now}
		// Bound history map the same way entries is bounded elsewhere —
		// otherwise an attacker rotating IPs could grow history without limit.
		if len(bl.history) > 50_000 {
			dropBudget := 64
			for k := range bl.history {
				delete(bl.history, k)
				dropBudget--
				if dropBudget <= 0 {
					break
				}
			}
		}
	}

	// Bound the entries map. Without this, an attacker rotating through
	// fresh IPs at long ban durations could grow the map until the
	// process runs out of memory — the periodic Cleanup ticker only
	// reaps EXPIRED entries, so a 24h ban window is plenty of time to
	// pile up. When the cap is hit prefer evicting already-expired
	// entries (cheap, correct), then fall back to dropping a small
	// random sample so a sustained flood can't pin the ban list at the
	// ceiling forever.
	if _, exists := bl.entries[ip]; !exists && len(bl.entries) >= maxBanEntries {
		// First pass: bounded scan for already-expired entries.
		scanBudget := 256
		for k, e := range bl.entries {
			if now.After(e.ExpiresAt) {
				delete(bl.entries, k)
			}
			scanBudget--
			if scanBudget <= 0 {
				break
			}
		}
		// Still full? Random-drop a small budget so sustained pressure
		// doesn't keep us pinned at the cap.
		if len(bl.entries) >= maxBanEntries {
			dropBudget := maxBanEntries / 1000 // 0.1%
			if dropBudget < 16 {
				dropBudget = 16
			}
			for k := range bl.entries {
				delete(bl.entries, k)
				dropBudget--
				if dropBudget <= 0 {
					break
				}
			}
		}
	}

	bl.entries[ip] = BanEntry{
		IP:         ip,
		Reason:     reason,
		ExpiresAt:  now.Add(duration),
		Timestamp:  now,
		Offenses:   offenses,
		LastBanned: now,
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

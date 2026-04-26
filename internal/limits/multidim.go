package limits

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MultiLimiter rate-limits requests across several independent
// dimensions in parallel. A request is rejected if ANY enabled
// dimension exceeds its budget — IP, JA4 hash, cookie value, and the
// signature of querystring keys are the four dimensions we track today.
//
// Why per-dimension instead of one composite key:
//   - IP-only rate-limiting is bypassed by IP-rotating botnets.
//   - JA4-only is bypassed by clients that intentionally rotate
//     fingerprints.
//   - Cookie-only is bypassed by drop-and-rotate sessions.
//   - Querystring-key signature catches enumeration attacks
//     (`?id=1`, `?id=2`, ...) where the *value* changes but the
//     *shape* of the request is constant per-target.
//
// Tracking each independently means an attacker has to bypass ALL of
// them simultaneously — usually requires a distributed bot with
// rotating cookies AND rotating fingerprints, which is much more
// expensive than any single bypass.
//
// Algorithm: two-bucket weighted sliding window (Cloudflare's pattern):
// the rate over the trailing window is `previous * (1 - elapsed_fraction)
// + current`. Smoother than fixed windows (no edge bursts), cheaper than
// a per-event log (O(1) per request).

// MultiLimiter operates on Dim entries; each Dim has its own budget.
//
// Config is held behind atomic.Pointer so that SetConfig (called from
// the admin API) and CheckRequest (hot path) never contend on a mutex.
// A torn read of MultiConfig (which contains an int64 Window field) is
// a real race on 32-bit and a logical bug everywhere — the previous
// version protected only the dim map, not the config itself.
type MultiLimiter struct {
	mu   sync.RWMutex
	dims map[DimKey]*dimState
	cfg  atomic.Pointer[MultiConfig]

	// Atomic counters for the dashboard.
	checks  atomic.Uint64
	allowed atomic.Uint64
	blocked atomic.Uint64
	dropped atomic.Uint64 // entries evicted under cap

	// Per-dimension blocked counters, lazy-initialised.
	dimBlocked sync.Map // DimKind → *atomic.Uint64
}

// DimKind enumerates the four parallel limiter axes.
type DimKind uint8

const (
	DimIP DimKind = iota
	DimJA4
	DimCookie
	DimQueryKeys
)

func (k DimKind) String() string {
	switch k {
	case DimIP:
		return "ip"
	case DimJA4:
		return "ja4"
	case DimCookie:
		return "cookie"
	case DimQueryKeys:
		return "querykeys"
	}
	return "unknown"
}

// DimKey identifies one tracked entity. Value is the dimension-specific
// string ("203.0.113.5", or a JA4 hash, or a cookie value, etc).
type DimKey struct {
	Kind  DimKind
	Value string
}

// MultiConfig is per-dimension policy. Zero budget = dimension disabled.
type MultiConfig struct {
	Window time.Duration // rolling window length, default 60s

	IPBudget         int // events/window; 0 = disabled
	JA4Budget        int
	CookieBudget     int
	CookieName       string // case-insensitive cookie key to track; e.g. "session_id"
	QueryKeysBudget  int

	// Cap on total tracked entries across all dimensions. Eviction is
	// random-drop on overflow to bound memory under hostile input.
	MaxEntries int
}

type dimState struct {
	mu        sync.Mutex
	prevCount uint32    // events in the previous window
	curCount  uint32    // events in the current window
	curStart  time.Time // start of the current window
}

// normalizeMultiConfig clamps zero/negative fields to defaults. Used
// by NewMultiLimiter and SetConfig so the published cfg pointer is
// always self-consistent.
func normalizeMultiConfig(cfg MultiConfig) MultiConfig {
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 200_000
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	return cfg
}

// NewMultiLimiter constructs a MultiLimiter from the config. Defaults are
// applied for zero / negative fields.
func NewMultiLimiter(cfg MultiConfig) *MultiLimiter {
	cfg = normalizeMultiConfig(cfg)
	m := &MultiLimiter{
		dims: make(map[DimKey]*dimState, 1024),
	}
	m.cfg.Store(&cfg)
	return m
}

// snapshotCfg returns a stable view of the current config. Callers MUST
// NOT mutate the returned pointer.
func (m *MultiLimiter) snapshotCfg() *MultiConfig {
	if m == nil {
		return nil
	}
	return m.cfg.Load()
}

// CheckRequest is the convenience entry point: extracts all four
// dimensions from a *http.Request and evaluates the limiter. Pass
// remoteIP separately because the limiter shouldn't try to parse
// X-Forwarded-For (the proxy already determined client IP per its
// trust config).
//
// Returns the first dimension that exceeded budget; empty kind means
// the request is allowed.
func (m *MultiLimiter) CheckRequest(r *http.Request, remoteIP, ja4 string) (kind DimKind, blocked bool, value string) {
	if m == nil || r == nil {
		return 0, false, ""
	}
	cfg := m.snapshotCfg()
	if cfg == nil {
		return 0, false, ""
	}
	m.checks.Add(1)

	// Order: cheapest first — IP is always present and a single map
	// lookup; cookie / querykey scans cost more.
	if v := strings.TrimSpace(remoteIP); v != "" && cfg.IPBudget > 0 {
		if blocked := m.tickAndCheck(cfg, DimIP, v, cfg.IPBudget); blocked {
			m.recordBlock(DimIP)
			return DimIP, true, v
		}
	}
	if v := strings.TrimSpace(ja4); v != "" && cfg.JA4Budget > 0 {
		if blocked := m.tickAndCheck(cfg, DimJA4, v, cfg.JA4Budget); blocked {
			m.recordBlock(DimJA4)
			return DimJA4, true, v
		}
	}
	if cfg.CookieBudget > 0 {
		if c, err := r.Cookie(cfg.CookieName); err == nil && c != nil && c.Value != "" {
			if blocked := m.tickAndCheck(cfg, DimCookie, c.Value, cfg.CookieBudget); blocked {
				m.recordBlock(DimCookie)
				return DimCookie, true, c.Value
			}
		}
	}
	if cfg.QueryKeysBudget > 0 && r.URL != nil && r.URL.RawQuery != "" {
		sig := QueryKeySignature(r.URL)
		if sig != "" {
			full := strings.ToLower(r.Method) + " " + r.URL.Path + "?" + sig
			if blocked := m.tickAndCheck(cfg, DimQueryKeys, full, cfg.QueryKeysBudget); blocked {
				m.recordBlock(DimQueryKeys)
				return DimQueryKeys, true, full
			}
		}
	}

	m.allowed.Add(1)
	return 0, false, ""
}

// tickAndCheck increments the counter for (kind,value) and returns true
// if the smoothed rate over the trailing window exceeds budget. The
// config snapshot is passed in so all four dimensions in one CheckRequest
// see a consistent view, even if SetConfig fires mid-call.
func (m *MultiLimiter) tickAndCheck(cfg *MultiConfig, kind DimKind, value string, budget int) bool {
	if budget <= 0 || cfg == nil {
		return false
	}
	key := DimKey{Kind: kind, Value: value}

	// Try existing entry under RLock.
	m.mu.RLock()
	st, ok := m.dims[key]
	m.mu.RUnlock()
	if !ok {
		// Create-or-find under write lock.
		m.mu.Lock()
		// Re-check after acquiring write lock to avoid duplicate alloc.
		if st = m.dims[key]; st == nil {
			if len(m.dims) >= cfg.MaxEntries {
				m.evictRandomLocked(64)
			}
			st = &dimState{curStart: time.Now()}
			m.dims[key] = st
		}
		m.mu.Unlock()
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(st.curStart)
	if elapsed >= 2*cfg.Window {
		// Two full windows have passed — reset both.
		st.prevCount = 0
		st.curCount = 0
		st.curStart = now
		elapsed = 0
	} else if elapsed >= cfg.Window {
		st.prevCount = st.curCount
		st.curCount = 0
		st.curStart = st.curStart.Add(cfg.Window)
		elapsed = now.Sub(st.curStart)
	}
	// Saturating add: a sustained DDoS could otherwise wrap a uint32
	// counter to zero in ~50 days at 1k QPS — far less under attack —
	// and a wrapped counter silently bypasses the limiter. Cap at a
	// value comfortably above any realistic budget.
	const counterCeiling uint32 = 1 << 30
	if st.curCount < counterCeiling {
		st.curCount++
	}

	// Smoothed weighted rate: `cur + prev * (1 - elapsed/window)`.
	// elapsed is guaranteed in [0, window) here.
	frac := 1.0 - float64(elapsed)/float64(cfg.Window)
	if frac < 0 {
		frac = 0
	}
	est := float64(st.curCount) + float64(st.prevCount)*frac
	return est > float64(budget)
}

func (m *MultiLimiter) evictRandomLocked(n int) {
	dropped := 0
	for k := range m.dims {
		delete(m.dims, k)
		dropped++
		if dropped >= n {
			break
		}
	}
	m.dropped.Add(uint64(dropped))
}

func (m *MultiLimiter) recordBlock(kind DimKind) {
	m.blocked.Add(1)
	c, _ := m.dimBlocked.LoadOrStore(kind, new(atomic.Uint64))
	c.(*atomic.Uint64).Add(1)
}

// QueryKeySignature returns a stable signature of the querystring's KEY
// set, excluding values. Used as the limiter axis "same shape of request,
// different value". Empty input → "".
//
// Example: ?id=42&from=cli&to=foo  →  "from,id,to"
func QueryKeySignature(u *url.URL) string {
	if u == nil || u.RawQuery == "" {
		return ""
	}
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// MultiStats snapshot for the dashboard.
type MultiStats struct {
	Tracked      int               `json:"tracked"`
	Cap          int               `json:"cap"`
	Checks       uint64            `json:"checks"`
	Allowed      uint64            `json:"allowed"`
	Blocked      uint64            `json:"blocked"`
	Dropped      uint64            `json:"dropped"`
	BlockedByDim map[string]uint64 `json:"blocked_by_dim"`
}

func (m *MultiLimiter) Stats() MultiStats {
	if m == nil {
		return MultiStats{}
	}
	cfg := m.snapshotCfg()
	m.mu.RLock()
	n := len(m.dims)
	m.mu.RUnlock()
	per := make(map[string]uint64, 4)
	m.dimBlocked.Range(func(k, v any) bool {
		kind, _ := k.(DimKind)
		c, _ := v.(*atomic.Uint64)
		if c != nil {
			per[kind.String()] = c.Load()
		}
		return true
	})
	cap := 0
	if cfg != nil {
		cap = cfg.MaxEntries
	}
	return MultiStats{
		Tracked:      n,
		Cap:          cap,
		Checks:       m.checks.Load(),
		Allowed:      m.allowed.Load(),
		Blocked:      m.blocked.Load(),
		Dropped:      m.dropped.Load(),
		BlockedByDim: per,
	}
}

// Sweep removes entries idle for longer than 2× window. Cheap; intended
// for the housekeeper goroutine. Bounded scan so a million-entry map
// can't stall the goroutine for seconds.
func (m *MultiLimiter) Sweep() int {
	if m == nil {
		return 0
	}
	cfg := m.snapshotCfg()
	if cfg == nil {
		return 0
	}
	cutoff := time.Now().Add(-2 * cfg.Window)
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	const maxScan = 4096
	scanned := 0
	for k, st := range m.dims {
		scanned++
		if scanned > maxScan {
			break
		}
		st.mu.Lock()
		idle := st.curStart.Before(cutoff) && st.curCount == 0 && st.prevCount == 0
		st.mu.Unlock()
		if idle {
			delete(m.dims, k)
			removed++
		}
	}
	return removed
}

// SetConfig swaps the policy at runtime via an atomic pointer publish.
// New CheckRequest calls pick up the new config on their next snapshot;
// in-flight tickAndCheck calls keep using the snapshot they already
// loaded. No mutex is taken — this is hot-path-safe.
func (m *MultiLimiter) SetConfig(cfg MultiConfig) {
	if m == nil {
		return
	}
	cfg = normalizeMultiConfig(cfg)
	m.cfg.Store(&cfg)
}

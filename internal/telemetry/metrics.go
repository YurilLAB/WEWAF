// Package telemetry provides in-memory counters and bounded ring buffers for
// the WAF's hot paths. The state here is intentionally small: any piece of
// data that should outlive a restart or a rotation window is flushed through
// the optional Persister (typically an *history.Store).
package telemetry

import (
	"log"
	"strconv"
	"sync"
	"time"
)

const (
	// Keep a small rolling window in memory so the UI can render without
	// going to disk. Older records are already persisted through Persister.
	defaultRecentBlocksCap = 500
	defaultTrafficCap      = 288 // 24 h @ 5-min buckets
	defaultEgressCap       = 200 // recent egress decisions for the dashboard
	defaultBotCap          = 200 // recent bot detections
	// UniqueIPs is bounded so an adversary can't OOM us by rotating source
	// IPs. The set is reset on history rotation so long-running daemons keep
	// reporting fresh counts.
	maxUniqueIPs = 100_000
	// recentIPBucketCount is the number of hourly buckets in the
	// sliding-window unique-IP tracker. 24 covers a full day on a
	// per-hour cadence, which matches the typical history-rotation
	// boundary, so the in-memory recent-window resets at the same
	// time the persisted DB rolls.
	recentIPBucketCount = 24
	// recentIPBucketCap caps the size of any single hourly bucket.
	// Each bucket independently holds up to this many distinct IPs,
	// so the worst-case hot-path memory under a rotating-source
	// attack is recentIPBucketCount × recentIPBucketCap entries —
	// 24 × 50K = 1.2M IPs at ~32 bytes each ≈ 40 MB. Acceptable;
	// shrinks to zero once the attack ends and the buckets rotate
	// out.
	recentIPBucketCap = 50_000
	// statusCodeMaxKeys caps the per-code counter map.
	statusCodeMaxKeys = 64
	// methodMaxKeys caps the per-method counter map. Real protocols
	// use 9 standard methods plus the occasional WebDAV / extension
	// — anything past 32 is hostile creativity.
	methodMaxKeys = 32
	// passedPathsMaxKeys caps the live "what passed" path map. 4096
	// covers a busy SPA + a CMS with categories; once full we stop
	// adding new keys but keep counting hits on existing ones, so a
	// scanner spraying random URLs can't bloat memory but real
	// traffic on known paths still increments.
	passedPathsMaxKeys = 4096
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
	BytesIn   uint64
	BytesOut  uint64
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
	EgressBlocked   uint64
	EgressAllowed   uint64
	BotsDetected    uint64
	AnomalyScore    int64
	UniqueIPs       map[string]struct{}
	RecentBlocks    []BlockRecord
	TrafficHistory  []TrafficPoint
	RecentEgress    []EgressEvent
	RecentBots      []BotEvent
	StatusCounts    map[int]uint64
	// StatusCodes is the precise per-code count (200, 301, 401, 404,
	// 429, 503…) — what StatusCounts conflates into 100-buckets. The
	// security-events page uses this to differentiate auth failures
	// (401/403) from rate-limited traffic (429) from origin failures
	// (502/503), which the bucketed view collapses. Capped at
	// statusCodeMaxKeys so a creative attacker can't make us hold a
	// map with one entry per bogus code.
	StatusCodes map[int]uint64
	// MethodCounts is the per-HTTP-method count (GET / POST / PUT /
	// DELETE / PATCH / OPTIONS / HEAD). Capped to a small set so a
	// hostile client can't bloat the map with random tokens. Useful
	// for spotting "flood of POSTs against /login" vs "scanner hit
	// every URL with GETs" at a glance.
	MethodCounts map[string]uint64
	// PassedPathCounts is the live counter behind the "Top paths
	// (all traffic)" view. Without this the only top-paths data is
	// from the blocks table — useful for security but useless for
	// "what URLs are my real users hitting". Capped at
	// passedPathsMaxKeys.
	PassedPathCounts map[string]uint64

	// Bandwidth rate, computed in AddTrafficPoint.
	lastSampleTime   time.Time
	lastBytesIn      uint64
	lastBytesOut     uint64
	CurrentBytesInPS uint64
	CurrentBytesOutPS uint64

	// Sliding-window unique IPs. The previous monotonic UniqueIPs map
	// only ever grew; once it hit maxUniqueIPs the count saturated and
	// the dashboard "unique IPs seen" number stayed at the cap forever
	// regardless of current activity. recentIPBuckets stores one set
	// per hour over a 24-hour ring, rotated on each sampler tick. The
	// cardinality of the union approximates "unique IPs in the last
	// 24 hours" — a number that rises with traffic and falls when an
	// attack ends. UniqueIPs (map above) stays as the lifetime view
	// for backwards compatibility.
	recentIPBuckets       [recentIPBucketCount]map[string]struct{}
	recentIPCurrentBucket int
	recentIPCurrentHour   int64

	recentBlocksCap int
	trafficCap      int
	egressCap       int
	botCap          int
	persister       Persister

	// Per-rule match counters so the UI can highlight the noisiest rules.
	// Lazily initialised in RecordBlockWithCategory to keep the zero value
	// useful for tests.
	RuleCounters map[string]uint64
}

// EgressEvent records an outbound egress decision.
type EgressEvent struct {
	Timestamp time.Time `json:"timestamp"`
	TargetURL string    `json:"target_url"`
	Reason    string    `json:"reason"`
	Allowed   bool      `json:"allowed"`
}

// BotEvent records a bot-fingerprint hit for the UI.
type BotEvent struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	BotName   string    `json:"bot_name"`
	Score     int       `json:"score"`
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

// TrafficPoint stores request volume + bandwidth at a point in time.
// Mirrors history.TrafficPoint so the live /api/traffic endpoint can
// return the same shape the persisted store already records — the
// previous in-memory shape carried only Requests + Blocked, so the
// dashboard's bandwidth-per-bucket view had to fall back to the
// aggregate bytes_in/out_per_sec rate. With bytes on every point
// callers can render a real bandwidth-over-time chart from a single
// query.
type TrafficPoint struct {
	Time     time.Time `json:"time"`
	Requests int       `json:"requests"`
	Blocked  int       `json:"blocked"`
	BytesIn  uint64    `json:"bytes_in"`
	BytesOut uint64    `json:"bytes_out"`
}

// NewMetrics creates a metrics collector with the default caps.
func NewMetrics() *Metrics {
	m := &Metrics{
		UniqueIPs:        make(map[string]struct{}, 1024),
		RecentBlocks:     make([]BlockRecord, 0, defaultRecentBlocksCap),
		TrafficHistory:   make([]TrafficPoint, 0, defaultTrafficCap),
		RecentEgress:     make([]EgressEvent, 0, defaultEgressCap),
		RecentBots:       make([]BotEvent, 0, defaultBotCap),
		StatusCounts:     make(map[int]uint64, 16),
		StatusCodes:      make(map[int]uint64, 32),
		MethodCounts:     make(map[string]uint64, 16),
		PassedPathCounts: make(map[string]uint64, 256),
		recentBlocksCap:  defaultRecentBlocksCap,
		trafficCap:       defaultTrafficCap,
		egressCap:        defaultEgressCap,
		botCap:           defaultBotCap,
	}
	// Pre-seed the first hourly IP bucket so the first RecordRequest
	// doesn't have to grow the array under the hot-path lock.
	m.recentIPBuckets[0] = make(map[string]struct{}, 1024)
	m.recentIPCurrentHour = time.Now().UTC().Unix() / 3600
	return m
}

// rotateUniqueIPsLocked advances the sliding window if the current
// hour-of-day has rolled. Cheap when the wall clock hasn't crossed an
// hour boundary (a single int compare) so the sampler can call it on
// every tick. CALLER MUST HOLD m.mu.
func (m *Metrics) rotateUniqueIPsLocked(now time.Time) {
	hour := now.UTC().Unix() / 3600
	if hour == m.recentIPCurrentHour {
		return
	}
	steps := hour - m.recentIPCurrentHour
	if steps <= 0 {
		// Clock travelled backwards (NTP slew). Keep the existing
		// window — corruption from a wrong time is preferable to
		// blowing away N hours of legitimate traffic data.
		m.recentIPCurrentHour = hour
		return
	}
	if steps >= int64(recentIPBucketCount) {
		// Whole window aged out — clear everything in one pass
		// rather than spinning the rotation N times.
		for i := range m.recentIPBuckets {
			m.recentIPBuckets[i] = nil
		}
		m.recentIPCurrentBucket = 0
		m.recentIPBuckets[0] = make(map[string]struct{}, 1024)
		m.recentIPCurrentHour = hour
		return
	}
	for i := int64(0); i < steps; i++ {
		m.recentIPCurrentBucket = (m.recentIPCurrentBucket + 1) % recentIPBucketCount
		// Replace the slot rather than clearing — replacing drops
		// the entire backing storage in one allocator call.
		m.recentIPBuckets[m.recentIPCurrentBucket] = make(map[string]struct{}, 1024)
	}
	m.recentIPCurrentHour = hour
}

// recordRecentIPLocked stores ip in the current-hour bucket if it's
// not full. CALLER MUST HOLD m.mu.
func (m *Metrics) recordRecentIPLocked(ip string) {
	if ip == "" {
		return
	}
	bucket := m.recentIPBuckets[m.recentIPCurrentBucket]
	if bucket == nil {
		bucket = make(map[string]struct{}, 1024)
		m.recentIPBuckets[m.recentIPCurrentBucket] = bucket
	}
	if len(bucket) >= recentIPBucketCap {
		// Bucket cap hit. We deliberately do NOT evict from the
		// bucket — that would make the cardinality count meaningless
		// (we'd be deleting old IPs we already counted). Instead we
		// just stop adding new IPs to this hour's bucket. Once the
		// hour rolls the next bucket starts fresh.
		return
	}
	bucket[ip] = struct{}{}
}

// recentUniqueIPCountLocked returns the cardinality of the union over
// every hourly bucket. CALLER MUST HOLD m.mu (or RLock).
func (m *Metrics) recentUniqueIPCountLocked() int {
	// Estimate the union without allocating a temporary set: walk
	// each bucket and dedupe via a single shared map. The 1024
	// capacity covers the common case (a steady site) without
	// growing for a quiet WAF; high-traffic deploys will resize it
	// once.
	seen := make(map[string]struct{}, 1024)
	for _, b := range m.recentIPBuckets {
		for ip := range b {
			seen[ip] = struct{}{}
		}
	}
	return len(seen)
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
// Every request feeds both the lifetime-cap UniqueIPs set and the
// sliding-window recent-IPs ring; Snapshot exposes both as
// "unique_ips" (lifetime-since-rotation) and "unique_ips_recent"
// (last 24h).
func (m *Metrics) RecordRequest(ip string, bytesIn int) {
	defer recoverPanic("RecordRequest")
	m.mu.Lock()
	m.TotalRequests++
	if ip != "" {
		if len(m.UniqueIPs) < maxUniqueIPs {
			m.UniqueIPs[ip] = struct{}{}
		}
		m.recordRecentIPLocked(ip)
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
	if ruleID != "" {
		if m.RuleCounters == nil {
			m.RuleCounters = make(map[string]uint64, 64)
		}
		// Bound the map — an attacker crafting synthetic rule IDs could
		// otherwise grow it unboundedly. 4096 covers every real rule pack
		// with headroom; once hit we stop adding new keys but keep
		// incrementing existing ones.
		if len(m.RuleCounters) < 4096 || func() bool {
			_, exists := m.RuleCounters[ruleID]
			return exists
		}() {
			m.RuleCounters[ruleID]++
		}
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
// Deprecated shape kept for backwards compatibility — new callers
// should prefer RecordPassDetailed which records method + path so the
// "top paths (all traffic)" view has data.
func (m *Metrics) RecordPass(bytesOut int, statusCode int) {
	m.RecordPassDetailed("", "", bytesOut, statusCode)
}

// RecordPassDetailed is the full-fidelity passed-request recorder.
// Adds per-method counters, exact status-code counts (in addition to
// the legacy 100-bucketed StatusCounts), and a path-popularity counter
// the network-monitoring page can consume. Each map is capped so a
// hostile client spraying random methods / paths can't bloat memory.
func (m *Metrics) RecordPassDetailed(method, path string, bytesOut, statusCode int) {
	defer recoverPanic("RecordPassDetailed")
	m.mu.Lock()
	m.PassedRequests++
	m.TotalBytesOut += uint64(maxInt(bytesOut, 0))
	if statusCode > 0 {
		// Bucketed view (legacy): 200, 300, 400, 500 etc.
		bucket := (statusCode / 100) * 100
		if m.StatusCounts == nil {
			m.StatusCounts = make(map[int]uint64, 8)
		}
		m.StatusCounts[bucket]++
		// Precise view: exact code. Only commit to the map if either
		// the code is already there or we're under the cap; this lets
		// existing keys keep counting while preventing unbounded growth
		// from a stream of synthetic codes (e.g. an upstream returning
		// random integers).
		if m.StatusCodes == nil {
			m.StatusCodes = make(map[int]uint64, 32)
		}
		if _, exists := m.StatusCodes[statusCode]; exists || len(m.StatusCodes) < statusCodeMaxKeys {
			m.StatusCodes[statusCode]++
		}
	}
	if method != "" {
		// Standard methods are uppercase; normalising avoids
		// "GET" / "get" / "Get" splitting the count three ways
		// when a buggy client mis-cases the verb.
		method = upperASCII(method)
		if m.MethodCounts == nil {
			m.MethodCounts = make(map[string]uint64, 8)
		}
		if _, exists := m.MethodCounts[method]; exists || len(m.MethodCounts) < methodMaxKeys {
			m.MethodCounts[method]++
		}
	}
	if path != "" {
		// Trim query / fragment so /search?q=foo and /search?q=bar
		// merge into one popularity-meaningful key. Cap path length
		// so a 10 KB URL can't bloat a single map entry.
		key := normaliseTopPathKey(method, path)
		if m.PassedPathCounts == nil {
			m.PassedPathCounts = make(map[string]uint64, 256)
		}
		if _, exists := m.PassedPathCounts[key]; exists || len(m.PassedPathCounts) < passedPathsMaxKeys {
			m.PassedPathCounts[key]++
		}
	}
	m.mu.Unlock()
}

// upperASCII converts ASCII letters to upper case without touching
// multi-byte runes — methods are 7-bit per RFC 9110 so we don't need
// strings.ToUpper's locale awareness.
func upperASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}

// normaliseTopPathKey returns "METHOD path-without-query" trimmed to
// a sane length. Used so the top-paths view counts /api/users?id=42
// and /api/users?id=99 together instead of as 2 distinct keys.
func normaliseTopPathKey(method, path string) string {
	const maxPath = 256
	// Drop query + fragment. The proxy never sees a fragment but
	// belt-and-braces here.
	if i := indexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if len(path) > maxPath {
		path = path[:maxPath]
	}
	if method == "" {
		return path
	}
	return method + " " + path
}

// indexAny is a tiny stand-in for strings.IndexAny — kept inline so
// this file's import set doesn't expand for one tiny lookup.
func indexAny(s, chars string) int {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}

// RecordBlockFromResponse preserved for backwards compatibility with callers.
func (m *Metrics) RecordBlockFromResponse(ip, method, path, ruleID, message string, score int) {
	m.RecordBlock(ip, method, path, ruleID, message, score)
}

// RecordEgressBlock increments the egress-blocked counter and stores the event
// in the recent-egress ring buffer so the dashboard can render a live feed.
func (m *Metrics) RecordEgressBlock(targetURL, reason string) {
	defer recoverPanic("RecordEgressBlock")
	ev := EgressEvent{
		Timestamp: time.Now().UTC(),
		TargetURL: truncateString(targetURL, 512),
		Reason:    truncateString(reason, 256),
		Allowed:   false,
	}
	m.mu.Lock()
	m.EgressBlocked++
	m.appendEgressLocked(ev)
	m.mu.Unlock()
}

// RecordEgressAllow increments the egress-allowed counter and records the target.
func (m *Metrics) RecordEgressAllow(targetURL string) {
	defer recoverPanic("RecordEgressAllow")
	ev := EgressEvent{
		Timestamp: time.Now().UTC(),
		TargetURL: truncateString(targetURL, 512),
		Allowed:   true,
	}
	m.mu.Lock()
	m.EgressAllowed++
	m.appendEgressLocked(ev)
	m.mu.Unlock()
}

func (m *Metrics) appendEgressLocked(ev EgressEvent) {
	cap := m.egressCap
	if cap <= 0 {
		cap = defaultEgressCap
	}
	m.RecentEgress = append(m.RecentEgress, ev)
	if len(m.RecentEgress) > cap {
		over := len(m.RecentEgress) - cap
		copy(m.RecentEgress, m.RecentEgress[over:])
		m.RecentEgress = m.RecentEgress[:cap]
	}
}

// RecentEgressSnapshot returns the last N egress events.
func (m *Metrics) RecentEgressSnapshot(n int) []EgressEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n <= 0 || n >= len(m.RecentEgress) {
		out := make([]EgressEvent, len(m.RecentEgress))
		copy(out, m.RecentEgress)
		return out
	}
	out := make([]EgressEvent, n)
	copy(out, m.RecentEgress[len(m.RecentEgress)-n:])
	return out
}

// RecordError bumps the backend-error counter.
func (m *Metrics) RecordError() {
	defer recoverPanic("RecordError")
	m.mu.Lock()
	m.ErrorCount++
	m.mu.Unlock()
}

// RecordBotDetected increments the bot-detected counter and appends an event
// to the recent-bots ring buffer. ip/ua may be empty if the caller does not
// have them handy — the counter still moves.
func (m *Metrics) RecordBotDetected(botName string) {
	m.RecordBotEvent("", "", botName, 0)
}

// RecordBotEvent is the full-fidelity bot recorder.
func (m *Metrics) RecordBotEvent(ip, userAgent, botName string, score int) {
	defer recoverPanic("RecordBotEvent")
	ev := BotEvent{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		UserAgent: truncateString(userAgent, 256),
		BotName:   truncateString(botName, 128),
		Score:     score,
	}
	m.mu.Lock()
	m.BotsDetected++
	cap := m.botCap
	if cap <= 0 {
		cap = defaultBotCap
	}
	m.RecentBots = append(m.RecentBots, ev)
	if len(m.RecentBots) > cap {
		over := len(m.RecentBots) - cap
		copy(m.RecentBots, m.RecentBots[over:])
		m.RecentBots = m.RecentBots[:cap]
	}
	m.mu.Unlock()
}

// RecentBotsSnapshot returns the last N bot events.
func (m *Metrics) RecentBotsSnapshot(n int) []BotEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n <= 0 || n >= len(m.RecentBots) {
		out := make([]BotEvent, len(m.RecentBots))
		copy(out, m.RecentBots)
		return out
	}
	out := make([]BotEvent, n)
	copy(out, m.RecentBots[len(m.RecentBots)-n:])
	return out
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
	statusCounts := make(map[string]uint64, len(m.StatusCounts))
	for k, v := range m.StatusCounts {
		statusCounts[strconvItoa(k)] = v
	}
	statusCodes := make(map[string]uint64, len(m.StatusCodes))
	for k, v := range m.StatusCodes {
		statusCodes[strconvItoa(k)] = v
	}
	methodCounts := make(map[string]uint64, len(m.MethodCounts))
	for k, v := range m.MethodCounts {
		methodCounts[k] = v
	}
	return map[string]interface{}{
		"total_requests":      m.TotalRequests,
		"blocked_requests":    m.BlockedRequests,
		"passed_requests":     m.PassedRequests,
		"total_bytes_in":      m.TotalBytesIn,
		"total_bytes_out":     m.TotalBytesOut,
		"bytes_in_per_sec":    m.CurrentBytesInPS,
		"bytes_out_per_sec":   m.CurrentBytesOutPS,
		"errors":              m.ErrorCount,
		"egress_blocked":      m.EgressBlocked,
		"egress_allowed":      m.EgressAllowed,
		"bots_detected":       m.BotsDetected,
		// "unique_ips" is the lifetime-since-rotation count (legacy
		// behaviour, capped at maxUniqueIPs). "unique_ips_recent" is
		// the rolling-24h cardinality the dashboard wants when it
		// asks "how many unique clients are talking to me right now".
		"unique_ips":          len(m.UniqueIPs),
		"unique_ips_recent":   m.recentUniqueIPCountLocked(),
		"recent_blocks":       recent,
		"traffic_history":     history,
		"status_code_buckets": statusCounts,
		"status_codes":        statusCodes,
		"method_counts":       methodCounts,
	}
}

// PassedPathCountsSnapshot returns a copy of the live passed-traffic
// path map. Used by the /api/network/top-paths handler when the
// caller asks for kind=all|passed — without this the only top-paths
// view came from the persisted blocks table, which is great for
// security but useless for "where are real users hitting".
func (m *Metrics) PassedPathCountsSnapshot() map[string]uint64 {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]uint64, len(m.PassedPathCounts))
	for k, v := range m.PassedPathCounts {
		out[k] = v
	}
	return out
}

// CountersSnapshot returns just the scalar counters (no slices). Useful for
// endpoints that only need totals and not the full recent-blocks payload.
func (m *Metrics) CountersSnapshot() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]uint64{
		"total_requests":   m.TotalRequests,
		"blocked_requests": m.BlockedRequests,
		"passed_requests":  m.PassedRequests,
		"egress_blocked":   m.EgressBlocked,
		"egress_allowed":   m.EgressAllowed,
	}
}

// RuleCountersSnapshot returns a copy of per-rule match counts so callers can
// sort/render without holding the metrics lock.
func (m *Metrics) RuleCountersSnapshot() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]uint64, len(m.RuleCounters))
	for k, v := range m.RuleCounters {
		out[k] = v
	}
	return out
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

// AddTrafficPoint appends a traffic sample for the line graph and
// recomputes the current bandwidth rate (bytes per second) from the
// delta since the last sample. The caller (cmd/waf startTrafficSampler)
// ticks at a fixed interval.
//
// The bytes deltas are derived inside this function from the running
// TotalBytesIn / TotalBytesOut counters so callers don't have to track
// state. Each TrafficPoint stored in TrafficHistory now carries the
// per-bucket bytes — previously the dashboard had to combine the
// in-memory point (req+blocked only) with the separate aggregate
// bytes/sec to render bandwidth-over-time, which produced a flat line
// at low traffic and a misleading spike on the most recent sample.
func (m *Metrics) AddTrafficPoint(reqs, blocked int) {
	defer recoverPanic("AddTrafficPoint")
	now := time.Now().UTC()
	m.mu.Lock()
	// Compute bytes/sec since the last sample plus the raw delta so the
	// persister can store per-bucket traffic volumes for long-term analysis.
	var bytesInDelta, bytesOutDelta uint64
	if !m.lastSampleTime.IsZero() {
		elapsed := now.Sub(m.lastSampleTime).Seconds()
		if m.TotalBytesIn >= m.lastBytesIn {
			bytesInDelta = m.TotalBytesIn - m.lastBytesIn
		}
		if m.TotalBytesOut >= m.lastBytesOut {
			bytesOutDelta = m.TotalBytesOut - m.lastBytesOut
		}
		if elapsed > 0 {
			m.CurrentBytesInPS = uint64(float64(bytesInDelta) / elapsed)
			m.CurrentBytesOutPS = uint64(float64(bytesOutDelta) / elapsed)
		}
	}
	pt := TrafficPoint{
		Time:     now,
		Requests: reqs,
		Blocked:  blocked,
		BytesIn:  bytesInDelta,
		BytesOut: bytesOutDelta,
	}
	m.TrafficHistory = append(m.TrafficHistory, pt)
	if len(m.TrafficHistory) > m.trafficCap {
		over := len(m.TrafficHistory) - m.trafficCap
		copy(m.TrafficHistory, m.TrafficHistory[over:])
		m.TrafficHistory = m.TrafficHistory[:m.trafficCap]
	}
	m.lastSampleTime = now
	m.lastBytesIn = m.TotalBytesIn
	m.lastBytesOut = m.TotalBytesOut
	// Tick the unique-IPs sliding window — every sample we may have
	// crossed an hour boundary; rotateUniqueIPsLocked handles the cheap
	// no-op case when we haven't.
	m.rotateUniqueIPsLocked(now)
	p := m.persister
	m.mu.Unlock()
	if p != nil {
		p.EnqueueTrafficPoint(BlockTrafficPoint{
			Timestamp: pt.Time, Requests: reqs, Blocked: blocked,
			BytesIn: bytesInDelta, BytesOut: bytesOutDelta,
		})
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

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// strconvItoa is a tiny wrapper so Snapshot can render map[int]→map[string]
// without pulling strconv into every callsite of this file.
func strconvItoa(n int) string {
	return strconv.Itoa(n)
}

func recoverPanic(where string) {
	if rec := recover(); rec != nil {
		log.Printf("telemetry: panic in %s: %v", where, rec)
	}
}

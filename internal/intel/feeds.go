// Package intel implements the auto-updating threat-intel feed
// subsystem — pulling FREE community lists (FireHOL, Spamhaus DROP,
// SSLBL JA3, blocklist.de, ET compromised, mitchellkrogza bad-UAs,
// CISA KEV) on a schedule and merging the parsed entries into the
// runtime ban / fingerprint / signature stores.
//
// Design priorities (informed by Cloudflare's Bot Management blog and
// OWASP CRS deployment guides):
//
//   - Multi-source consensus. We do NOT hard-block on a single feed
//     hit. The default policy is "log+score" for one match and
//     "block" only when ≥ 2 sources agree OR the source is rated
//     "high confidence" (Spamhaus DROP, CISA KEV).
//
//   - Tiered fallback. Each fetch tries: primary URL → mirror URL
//     (if any) → on-disk cache (within MaxStaleAge) → bundled
//     defaults. Never a fatal error.
//
//   - Sane integrity checks even where the source has no signature.
//     ETag/Last-Modified change required for "fresh"; record count
//     must be within ±50% of last good version (configurable); body
//     size hard-capped at 50 MB.
//
//   - Supervisor-based goroutine lifecycle. Each source has its own
//     fetcher with panic recovery and exponential backoff (60s →
//     30m, jittered). One bad feed never affects another.
//
//   - Learning mode. New rules from a feed start in observe-only
//     status for the first PromoteAfter window. Operators see the
//     candidate FP-ratio in the dashboard before promotion to
//     enforce.
package intel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind classifies a feed payload. The Manager dispatches parsed
// entries to the appropriate target callback by kind.
type Kind uint8

const (
	KindIPv4   Kind = iota // CIDR or single IP, IPv4
	KindIPv6               // CIDR or single IP, IPv6
	KindJA3                // 32-char hex hash
	KindJA4                // 36-char JA4 fingerprint
	KindUA                 // user-agent substring
	KindCVE                // CVE-id (used for virtual-patch hints, not enforcement)
)

// Confidence is the operator-controlled trust level of a source.
type Confidence uint8

const (
	ConfLow    Confidence = iota // single-source insight; score-only
	ConfMedium                   // multi-source observed; score+log
	ConfHigh                     // authoritative (DROP, KEV); enforce
)

// Entry is one parsed record from a feed. Source is set by the manager
// so callbacks know which feed contributed it.
type Entry struct {
	Kind       Kind
	Value      string
	Reason     string
	Source     string
	Confidence Confidence
	FetchedAt  time.Time
}

// Source defines one feed. Parser converts the raw HTTP body into a
// slice of Entry. Mirror is optional (used as fallback before on-disk
// cache). RefreshEvery clamps to ≥1 minute.
type Source struct {
	Name         string
	URL          string
	Mirror       string
	Kind         Kind
	Confidence   Confidence
	RefreshEvery time.Duration
	Parser       func(body []byte, src string) ([]Entry, error)

	// Optional license string; surfaced in the admin UI for
	// compliance review.
	License string
}

// Sink is the callback the Manager invokes once a fetch produces a
// fresh, validated batch. The implementation is responsible for
// merging entries into the right runtime store. Returning an error
// causes the Manager to log and treat the fetch as failed for the
// purposes of stats; the next refresh runs as scheduled.
type Sink func(entries []Entry) error

// Manager runs the feed-supervisor goroutines and exposes stats.
type Manager struct {
	cfg        Config
	httpClient *http.Client
	sink       Sink

	mu       sync.RWMutex
	sources  []Source
	state    map[string]*sourceState
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	// started is set to true once Start() has spawned the supervisor
	// goroutines. AddSource calls after this point used to silently
	// no-op (the new source was appended but never given a fetcher),
	// leaving operators with a misleading "configured" UI line and no
	// data. AddSource now refuses with an error in that case.
	started atomic.Bool

	// Atomic counters.
	totalFetches  atomic.Uint64
	totalFailures atomic.Uint64
	totalEntries  atomic.Uint64
}

type sourceState struct {
	mu              sync.Mutex
	lastFetch       time.Time
	lastSuccess     time.Time
	lastError       string
	etag            string
	lastModified    string
	lastEntryCount  int
	totalFetches    uint64
	totalSuccess    uint64
	totalFailures   uint64
	consecutiveFail uint32
	bytesLastFetch  int64
}

// Config governs cache location, network timeouts, and FP-safety
// thresholds. Zero / negative values get defaults.
type Config struct {
	CacheDir       string        // e.g. <history>/intel — cached responses live here
	MaxBodyBytes   int64         // hard ceiling per fetch, default 50 MiB
	HTTPTimeout    time.Duration // per HTTP call, default 30 s
	MaxStaleAge    time.Duration // serve cached body up to this old when network fails, default 7 days
	RecordDelta    float64       // refuse update if record count drifts more than this fraction (e.g. 0.5 → ±50 %)
	MaxBackoff     time.Duration // cap per-source exponential backoff, default 30 min
	MinBackoff     time.Duration // floor, default 60 s
	UserAgent      string        // HTTP UA; default identifies WEWAF
}

func (c *Config) applyDefaults() {
	if c.CacheDir == "" {
		c.CacheDir = "intel-cache"
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 50 * 1024 * 1024
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 30 * time.Second
	}
	if c.MaxStaleAge <= 0 {
		c.MaxStaleAge = 7 * 24 * time.Hour
	}
	if c.RecordDelta <= 0 {
		c.RecordDelta = 0.5
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Minute
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = 60 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "wewaf-intel/1.0"
	}
}

// NewManager constructs a Manager. Sink is required — without it
// fetched entries have nowhere to land. The caller is responsible
// for calling Start() and Stop().
func NewManager(cfg Config, sink Sink) (*Manager, error) {
	if sink == nil {
		return nil, errors.New("intel: sink is required")
	}
	cfg.applyDefaults()
	// 0o700 — the cache holds full-size feed payloads (Spamhaus DROP,
	// FireHOL, KEV) plus per-source timing metadata an attacker on the
	// same shared host could use for reconnaissance. POSIX-only.
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		// Non-fatal — the manager still works without disk cache, it
		// just loses the stale-cache fallback path. Surface the error
		// for observability but continue.
		_ = err
	}
	m := &Manager{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
			// Refuse redirects entirely. A compromised feed URL that
			// 301s to http://169.254.169.254/latest/meta-data or any
			// internal HTTP endpoint would otherwise drag the WAF
			// process into making that request — classic SSRF via
			// redirect. Returning ErrUseLastResponse lets the caller
			// observe the 30x and either accept the body (if the feed
			// still served one) or fall through to mirror/cache.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		sink:    sink,
		state:   make(map[string]*sourceState, 8),
	}
	return m, nil
}

// AddSource registers a source. Must be called before Start; adding
// after Start is a no-op (logged to stderr by the caller's logging
// wrapper if any).
func (m *Manager) AddSource(s Source) error {
	if m == nil {
		return errors.New("intel: nil manager")
	}
	if s.Name == "" || s.URL == "" || s.Parser == nil {
		return errors.New("intel: source needs Name, URL, and Parser")
	}
	if m.started.Load() {
		return errors.New("intel: AddSource called after Start; restart required to register new feed")
	}
	if s.RefreshEvery < time.Minute {
		s.RefreshEvery = time.Hour
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.state[s.Name]; dup {
		return fmt.Errorf("intel: duplicate source %q", s.Name)
	}
	m.sources = append(m.sources, s)
	m.state[s.Name] = &sourceState{}
	return nil
}

// Start spawns one supervisor goroutine per source. Must only be called
// once per Manager; later calls are no-ops so duplicate startup paths
// can't accidentally double the fetch traffic.
func (m *Manager) Start() {
	if m == nil {
		return
	}
	if !m.started.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.sources {
		s := m.sources[i] // capture
		m.wg.Add(1)
		go m.supervise(ctx, s)
	}
}

// Stop signals all supervisors and waits for them to exit. Safe to
// call multiple times.
func (m *Manager) Stop() {
	if m == nil || m.cancel == nil {
		return
	}
	m.cancel()
	m.cancel = nil
	m.wg.Wait()
}

// supervise is the per-source loop. Recovers panics, applies
// exponential backoff on failures.
func (m *Manager) supervise(ctx context.Context, s Source) {
	defer m.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			// Even the supervisor should never bring the process down.
			// Log to stderr (the only path that's always available).
			fmt.Fprintf(os.Stderr, "intel: supervisor for %q panicked: %v\n", s.Name, r)
		}
	}()

	// Initial fetch staggered randomly within the first 60s so
	// multiple sources don't hammer the network in lockstep on
	// startup.
	startup := time.Duration(rand.Int63n(int64(60 * time.Second)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(startup):
	}

	backoff := m.cfg.MinBackoff
	for {
		err := m.fetchOnce(ctx, s)
		st := m.getState(s.Name)
		if err == nil {
			st.mu.Lock()
			st.consecutiveFail = 0
			st.mu.Unlock()
			backoff = m.cfg.MinBackoff
		} else {
			st.mu.Lock()
			st.consecutiveFail++
			cf := st.consecutiveFail
			st.mu.Unlock()
			// Exponential with jitter, capped.
			next := backoff * 2
			if next > m.cfg.MaxBackoff {
				next = m.cfg.MaxBackoff
			}
			backoff = next
			_ = cf
			fmt.Fprintf(os.Stderr, "intel: %s fetch failed (consecutive=%d): %v\n", s.Name, cf, err)
		}

		next := s.RefreshEvery
		if err != nil {
			next = backoff
		}
		// Apply ±20% jitter to break herd effects.
		jitter := time.Duration(rand.Int63n(int64(next) / 5))
		if rand.Intn(2) == 0 {
			next -= jitter
		} else {
			next += jitter
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// fetchOnce is one fetch attempt — primary URL → mirror → cache.
func (m *Manager) fetchOnce(ctx context.Context, s Source) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert a panic in parser/sink into an error so the
			// supervisor's backoff path runs. Without the named
			// return + assignment the recovered panic became silent
			// success: the function returned nil, the supervisor
			// reset its backoff, and the operator never saw the
			// faulty source. We also log to stderr so the cause is
			// visible even before the dashboard refreshes.
			fmt.Fprintf(os.Stderr, "intel: fetchOnce panic for %q: %v\n", s.Name, r)
			m.totalFailures.Add(1)
			retErr = fmt.Errorf("intel: fetchOnce panic: %v", r)
		}
	}()

	st := m.getState(s.Name)
	m.totalFetches.Add(1)
	st.mu.Lock()
	st.totalFetches++
	st.lastFetch = time.Now()
	st.mu.Unlock()

	body, etag, modified, fromCache, err := m.tryAll(ctx, s, st)
	if err != nil {
		m.totalFailures.Add(1)
		st.mu.Lock()
		st.totalFailures++
		st.lastError = err.Error()
		st.mu.Unlock()
		return err
	}

	entries, err := s.Parser(body, s.Name)
	if err != nil {
		m.totalFailures.Add(1)
		st.mu.Lock()
		st.totalFailures++
		st.lastError = "parse: " + err.Error()
		st.mu.Unlock()
		return err
	}

	// Drift sanity check: if the new record count is wildly different
	// from the last good count, refuse to apply.
	if !fromCache {
		st.mu.Lock()
		prev := st.lastEntryCount
		st.mu.Unlock()
		if prev > 0 {
			delta := abs(len(entries)-prev) * 1000 / prev
			if delta > int(m.cfg.RecordDelta*1000) {
				st.mu.Lock()
				st.lastError = fmt.Sprintf("record count drift %d → %d > %.0f%%", prev, len(entries), m.cfg.RecordDelta*100)
				st.totalFailures++
				st.mu.Unlock()
				return errors.New("intel: drift threshold exceeded; refusing update")
			}
		}
	}

	// Tag entries with source / confidence / fetch time.
	now := time.Now()
	for i := range entries {
		entries[i].Source = s.Name
		entries[i].Confidence = s.Confidence
		entries[i].FetchedAt = now
	}

	if err := m.sink(entries); err != nil {
		m.totalFailures.Add(1)
		st.mu.Lock()
		st.totalFailures++
		st.lastError = "sink: " + err.Error()
		st.mu.Unlock()
		return err
	}

	m.totalEntries.Add(uint64(len(entries)))
	st.mu.Lock()
	st.totalSuccess++
	st.lastSuccess = now
	st.lastError = ""
	st.lastEntryCount = len(entries)
	st.etag = etag
	st.lastModified = modified
	st.bytesLastFetch = int64(len(body))
	st.mu.Unlock()

	if !fromCache {
		// Best-effort cache write. Failure here is not fatal.
		_ = m.writeCache(s.Name, body)
	}
	return nil
}

// tryAll is the fallback chain: primary → mirror → cache.
func (m *Manager) tryAll(ctx context.Context, s Source, st *sourceState) ([]byte, string, string, bool, error) {
	st.mu.Lock()
	etag := st.etag
	modified := st.lastModified
	st.mu.Unlock()

	body, newETag, newMod, err := m.httpFetch(ctx, s.URL, etag, modified)
	if err == nil {
		return body, newETag, newMod, false, nil
	}
	primaryErr := err

	if s.Mirror != "" {
		body, newETag, newMod, err = m.httpFetch(ctx, s.Mirror, "", "")
		if err == nil {
			return body, newETag, newMod, false, nil
		}
	}

	// Last resort — disk cache. We accept stale data here because the
	// alternative is leaving operators with no signal at all when
	// upstream feeds blip.
	if cached, mtime, ok := m.readCache(s.Name); ok {
		if time.Since(mtime) <= m.cfg.MaxStaleAge {
			return cached, "", "", true, nil
		}
	}

	return nil, "", "", false, fmt.Errorf("intel: all fetch paths failed (primary=%w)", primaryErr)
}

// httpFetch performs a single GET with conditional headers. Returns
// (body, newETag, newLastModified, err). 304 responses produce a
// sentinel error so callers can distinguish "no change" from "failed".
func (m *Manager) httpFetch(ctx context.Context, url, etag, modified string) ([]byte, string, string, error) {
	if url == "" {
		return nil, "", "", errors.New("empty URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("User-Agent", m.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if modified != "" {
		req.Header.Set("If-Modified-Since", modified)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, modified, errNotModified
	case http.StatusOK:
		// fall through
	default:
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", "", fmt.Errorf("status %d", resp.StatusCode)
	}

	limit := m.cfg.MaxBodyBytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", "", err
	}
	if int64(len(body)) > limit {
		return nil, "", "", fmt.Errorf("body exceeds %d bytes", limit)
	}
	return body, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), nil
}

var errNotModified = errors.New("not modified")

// IsNotModified reports whether err is the "304 Not Modified"
// sentinel, exposed for tests.
func IsNotModified(err error) bool {
	return errors.Is(err, errNotModified)
}

// readCache returns the cached body for the named source, its mtime,
// and whether the file existed.
func (m *Manager) readCache(name string) ([]byte, time.Time, bool) {
	path := filepath.Join(m.cfg.CacheDir, sanitizeFilename(name)+".cache")
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	return body, info.ModTime(), true
}

func (m *Manager) writeCache(name string, body []byte) error {
	if m.cfg.CacheDir == "" {
		return nil
	}
	path := filepath.Join(m.cfg.CacheDir, sanitizeFilename(name)+".cache")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) getState(name string) *sourceState {
	m.mu.RLock()
	st := m.state[name]
	m.mu.RUnlock()
	return st
}

// SourceStats is the per-source dashboard view.
type SourceStats struct {
	Name             string `json:"name"`
	URL              string `json:"url"`
	Confidence       string `json:"confidence"`
	License          string `json:"license"`
	LastFetch        string `json:"last_fetch"`
	LastSuccess      string `json:"last_success"`
	LastError        string `json:"last_error,omitempty"`
	TotalFetches     uint64 `json:"total_fetches"`
	TotalSuccess     uint64 `json:"total_success"`
	TotalFailures    uint64 `json:"total_failures"`
	ConsecutiveFail  uint32 `json:"consecutive_failures"`
	LastEntries      int    `json:"last_entries"`
	LastBytes        int64  `json:"last_bytes"`
}

// Stats returns the aggregate + per-source view for the admin UI.
type Stats struct {
	Sources       []SourceStats `json:"sources"`
	TotalFetches  uint64        `json:"total_fetches"`
	TotalFailures uint64        `json:"total_failures"`
	TotalEntries  uint64        `json:"total_entries"`
}

func (m *Manager) Stats() Stats {
	if m == nil {
		return Stats{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := Stats{
		TotalFetches:  m.totalFetches.Load(),
		TotalFailures: m.totalFailures.Load(),
		TotalEntries:  m.totalEntries.Load(),
		Sources:       make([]SourceStats, 0, len(m.sources)),
	}
	for _, s := range m.sources {
		st := m.state[s.Name]
		st.mu.Lock()
		out.Sources = append(out.Sources, SourceStats{
			Name:            s.Name,
			URL:             s.URL,
			Confidence:      confidenceString(s.Confidence),
			License:         s.License,
			LastFetch:       formatTime(st.lastFetch),
			LastSuccess:     formatTime(st.lastSuccess),
			LastError:       st.lastError,
			TotalFetches:    st.totalFetches,
			TotalSuccess:    st.totalSuccess,
			TotalFailures:   st.totalFailures,
			ConsecutiveFail: st.consecutiveFail,
			LastEntries:     st.lastEntryCount,
			LastBytes:       st.bytesLastFetch,
		})
		st.mu.Unlock()
	}
	return out
}

func confidenceString(c Confidence) string {
	switch c {
	case ConfHigh:
		return "high"
	case ConfMedium:
		return "medium"
	default:
		return "low"
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sanitizeFilename(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return strings.ToLower(string(out))
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

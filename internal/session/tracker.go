// Package session tracks per-client sessions across requests so the WAF can
// score anomalous behaviour (request-rate spikes, path churn, UA drift,
// missing human-input beacons, failed browser-integrity challenges).
//
// Design notes:
//
//   - Sessions are keyed by an HMAC-signed cookie (__wewaf_sid). The signing
//     key is generated on first start if the operator hasn't supplied one —
//     this means session IDs survive a reboot only when the operator wires
//     SessionCookieSecret into config. That's deliberate: secret rotation
//     invalidates all sessions, which is what you want during an incident.
//
//   - State lives in-memory with an LRU cap + idle TTL. The cap keeps a
//     malicious client from OOM'ing the daemon by rotating session IDs;
//     the TTL keeps long-lived browser tabs from holding state forever.
//
//   - Scoring is additive. Signals accumulate a "risk score" over the
//     session's lifetime. The proxy reads this score and can elevate a
//     request's priority in the rule engine (e.g. drop the block threshold
//     for a session scoring >60). By default scoring is observe-only —
//     flipping SessionBlockThreshold turns it into real enforcement.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// CookieName is the session ID cookie. The value is "<id>.<hmac>".
	CookieName = "__wewaf_sid"
	// ChallengeCookieName is the cookie set after a successful browser
	// integrity challenge. Value is "<timestamp>.<hmac>".
	ChallengeCookieName = "__wewaf_bc"
	// Max number of distinct paths tracked per session. Bounds memory for
	// legit users with big single-page apps while still giving enough
	// signal for scoring.
	maxPathsPerSession = 64
	// Max session ID length accepted from a cookie. Cookies over this are
	// rejected and a fresh one issued. Defensive against oversized inputs.
	maxCookieLen = 256
)

// Session captures the state we track for a single logical client.
// Fields written by multiple goroutines are behind Tracker.mu; the
// atomic counters are hot-path friendly (every request touches RequestCount).
type Session struct {
	ID              string
	FirstSeen       time.Time
	LastSeen        time.Time
	RequestCount    uint64
	BlockCount      uint64
	UserAgents      map[string]int // distinct UAs seen (capped)
	Paths           map[string]int // path → hit count (capped)
	IPs             map[string]int // distinct source IPs (capped)
	MouseEvents     uint64         // reported by beacon
	KeyEvents       uint64         // reported by beacon
	TimeOnPageMs    uint64         // cumulative, reported by beacon
	BeaconCount     uint64         // how many beacons received
	ChallengePassed bool           // set when browser-integrity cookie validates
	ChallengeAt     time.Time
	RiskScore       int
	LastScoreBump   time.Time

	// JA3 fingerprint observed for this session (32-char hash). Carried
	// through scoring so the admin UI can render "session was flagged due
	// to ja3=… (curl)" without an extra lookup. JA3Verdict is "good",
	// "bad", or empty.
	JA3        string
	JA3Verdict string
	JA3Reason  string

	// PoW state. PowPassedAt non-zero means the proof-of-work gate was
	// cleared and the session is allowed through even at high score.
	PowPassedAt time.Time
}

// Snapshot returns a copy safe to expose over the admin API.
func (s *Session) Snapshot() SessionView {
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	uas := make([]string, 0, len(s.UserAgents))
	for ua := range s.UserAgents {
		uas = append(uas, ua)
	}
	ips := make([]string, 0, len(s.IPs))
	for ip := range s.IPs {
		ips = append(ips, ip)
	}
	return SessionView{
		ID:              s.ID,
		FirstSeen:       s.FirstSeen,
		LastSeen:        s.LastSeen,
		RequestCount:    s.RequestCount,
		BlockCount:      s.BlockCount,
		Paths:           paths,
		UserAgents:      uas,
		IPs:             ips,
		MouseEvents:     s.MouseEvents,
		KeyEvents:       s.KeyEvents,
		TimeOnPageMs:    s.TimeOnPageMs,
		BeaconCount:     s.BeaconCount,
		ChallengePassed: s.ChallengePassed,
		RiskScore:       s.RiskScore,
		JA3:             s.JA3,
		JA3Verdict:      s.JA3Verdict,
		PowPassed:       !s.PowPassedAt.IsZero(),
	}
}

// SessionView is the JSON-safe representation.
type SessionView struct {
	ID              string    `json:"id"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	RequestCount    uint64    `json:"request_count"`
	BlockCount      uint64    `json:"block_count"`
	Paths           []string  `json:"paths"`
	UserAgents      []string  `json:"user_agents"`
	IPs             []string  `json:"ips"`
	MouseEvents     uint64    `json:"mouse_events"`
	KeyEvents       uint64    `json:"key_events"`
	TimeOnPageMs    uint64    `json:"time_on_page_ms"`
	BeaconCount     uint64    `json:"beacon_count"`
	ChallengePassed bool      `json:"challenge_passed"`
	RiskScore       int       `json:"risk_score"`
	JA3             string    `json:"ja3,omitempty"`
	JA3Verdict      string    `json:"ja3_verdict,omitempty"`
	PowPassed       bool      `json:"pow_passed"`
}

// Tracker owns all live sessions.
type Tracker struct {
	mu          sync.RWMutex
	secret      []byte
	sessions    map[string]*Session
	maxSessions int
	idleTTL     time.Duration
	stopCh      chan struct{}
	stopOnce    sync.Once
	enabled     atomic.Bool

	// Scoring thresholds — exposed so the admin API can tune without a
	// restart. Read on the hot path, so they're atomic.
	requestRateCeiling atomic.Int64 // reqs/min above this starts scoring
	pathCountCeiling   atomic.Int64 // distinct paths above this starts scoring

	// trustXFF mirrors the proxy-level TrustXFF flag. When false the
	// tracker ignores X-Forwarded-For / X-Real-Ip so hostile clients
	// can't spoof source IPs past the per-session IP-drift check.
	trustXFF atomic.Bool
}

// Config holds tracker tuning. Zero/empty fields fall back to sane defaults.
type Config struct {
	Secret             string        // HMAC key for cookie signing; auto-generated if empty
	MaxSessions        int           // hard cap on live sessions (default 200 000)
	IdleTTL            time.Duration // evict sessions idle longer than this (default 30 min)
	Enabled            bool          // if false, GetOrCreate still works but signals are skipped
	RequestRateCeiling int           // per-minute threshold that starts scoring
	PathCountCeiling   int           // distinct-path threshold that starts scoring
	TrustXFF           bool          // if true, parse X-Forwarded-For / X-Real-Ip; otherwise RemoteAddr only
}

// NewTracker returns a Tracker with a cleanup goroutine started.
func NewTracker(cfg Config) *Tracker {
	secret := []byte(cfg.Secret)
	if len(secret) == 0 {
		// Auto-generate if the operator hasn't supplied one. This means
		// sessions don't persist across restarts, which is actually what
		// you want during an incident — an attacker can't re-use a stolen
		// session ID after the daemon restarts.
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			// crypto/rand Read is documented never to fail on supported
			// platforms; fall back to a time-seeded value so we at least
			// don't ship with a hardcoded secret.
			seed := fmt.Sprintf("wewaf-%d", time.Now().UnixNano())
			h := sha256.Sum256([]byte(seed))
			secret = h[:]
		}
	}
	maxSessions := cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = 200_000
	}
	idleTTL := cfg.IdleTTL
	if idleTTL <= 0 {
		idleTTL = 30 * time.Minute
	}
	t := &Tracker{
		secret:      secret,
		sessions:    make(map[string]*Session, 1024),
		maxSessions: maxSessions,
		idleTTL:     idleTTL,
		stopCh:      make(chan struct{}),
	}
	t.enabled.Store(cfg.Enabled)
	t.trustXFF.Store(cfg.TrustXFF)
	if cfg.RequestRateCeiling > 0 {
		t.requestRateCeiling.Store(int64(cfg.RequestRateCeiling))
	} else {
		t.requestRateCeiling.Store(600) // 10 rps sustained is very high for a single session
	}
	if cfg.PathCountCeiling > 0 {
		t.pathCountCeiling.Store(int64(cfg.PathCountCeiling))
	} else {
		t.pathCountCeiling.Store(40)
	}
	go t.cleanupLoop()
	return t
}

// Stop halts the cleanup goroutine. Safe to call multiple times.
func (t *Tracker) Stop() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

// SetEnabled flips the tracker on/off at runtime. When disabled,
// GetOrCreate still returns a session (so cookies round-trip) but no
// scoring work happens on the hot path.
func (t *Tracker) SetEnabled(on bool) { t.enabled.Store(on) }

// SetTrustXFF updates whether the tracker parses X-Forwarded-For /
// X-Real-Ip when extracting client IPs for drift scoring. Mirrors the
// proxy-level flag so both layers agree on source-IP truth.
func (t *Tracker) SetTrustXFF(on bool) { t.trustXFF.Store(on) }

// Enabled reports whether scoring is active. The proxy checks this to
// decide whether to invoke the tracker at all.
func (t *Tracker) Enabled() bool { return t.enabled.Load() }

// SetThresholds updates the scoring thresholds at runtime.
func (t *Tracker) SetThresholds(reqRate, pathCount int) {
	if reqRate > 0 {
		t.requestRateCeiling.Store(int64(reqRate))
	}
	if pathCount > 0 {
		t.pathCountCeiling.Store(int64(pathCount))
	}
}

// EnsureSession reads the session cookie from r, verifies its HMAC, and
// returns the matching Session. If no valid cookie is present a new
// session is minted and a Set-Cookie header is written to w. Returns nil
// if the tracker is disabled entirely (no cookie work at all).
//
// This is the hot path, called on every request. We keep it cheap:
//   - HMAC verify is SHA-256 on ~24 bytes (nanoseconds)
//   - Map lookup + update under the write lock (microseconds)
//   - No allocation on cache hits
func (t *Tracker) EnsureSession(w http.ResponseWriter, r *http.Request) *Session {
	if t == nil {
		return nil
	}
	var id string
	if c, err := r.Cookie(CookieName); err == nil && c != nil {
		if len(c.Value) <= maxCookieLen {
			if rid, ok := t.verifyCookie(c.Value); ok {
				id = rid
			}
		}
	}
	if id == "" {
		// Fresh session.
		id = randomID()
		if w != nil {
			t.setCookie(w, id)
		}
	}
	s := t.touchSession(id, r)
	return s
}

// touchSession upserts the session and updates per-request signals.
func (t *Tracker) touchSession(id string, r *http.Request) *Session {
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[id]
	if !ok {
		if len(t.sessions) >= t.maxSessions {
			// Bounded random-drop — same pattern as bruteforce/limits.
			// Go's map iteration is randomised, so dropping ~1% is an
			// unbiased eviction sample.
			dropBudget := t.maxSessions / 100
			if dropBudget < 64 {
				dropBudget = 64
			}
			for k := range t.sessions {
				delete(t.sessions, k)
				dropBudget--
				if dropBudget <= 0 {
					break
				}
			}
		}
		s = &Session{
			ID:         id,
			FirstSeen:  now,
			UserAgents: make(map[string]int, 2),
			Paths:      make(map[string]int, 8),
			IPs:        make(map[string]int, 2),
		}
		t.sessions[id] = s
	}
	s.LastSeen = now
	s.RequestCount++
	if r != nil {
		if ua := r.UserAgent(); ua != "" {
			if len(s.UserAgents) < 8 || s.UserAgents[ua] > 0 {
				s.UserAgents[ua]++
			}
		}
		if p := r.URL.Path; p != "" {
			if len(s.Paths) < maxPathsPerSession || s.Paths[p] > 0 {
				s.Paths[p]++
			}
		}
		if ip := t.clientIP(r); ip != "" {
			if len(s.IPs) < 8 || s.IPs[ip] > 0 {
				s.IPs[ip]++
			}
		}
	}
	return s
}

// RecordBlock increments the block counter for a session. Called by the
// proxy when a request matching this session is blocked.
func (t *Tracker) RecordBlock(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		s.BlockCount++
	}
	t.mu.Unlock()
}

// RecordJA3 attaches a JA3 fingerprint and detector verdict to the session.
// Idempotent: writing the same hash twice is a no-op so this is cheap to
// call on every request. Verdict and reason are overwritten on each call
// so a list reload by the operator takes effect for in-flight sessions.
func (t *Tracker) RecordJA3(id, hash, verdict, reason string) {
	if t == nil || id == "" || hash == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		s.JA3 = hash
		s.JA3Verdict = verdict
		s.JA3Reason = reason
	}
	t.mu.Unlock()
}

// RecordPowPass marks the session as having cleared the proof-of-work
// gate. After this point Score() caps the returned value so a high-risk
// session that solved the challenge isn't immediately re-challenged on
// the next request.
func (t *Tracker) RecordPowPass(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		s.PowPassedAt = time.Now().UTC()
	}
	t.mu.Unlock()
}

// RecordChallengePass marks a session as having passed the browser
// integrity challenge and zeroes the "no-browser" risk contribution.
func (t *Tracker) RecordChallengePass(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		s.ChallengePassed = true
		s.ChallengeAt = time.Now().UTC()
	}
	t.mu.Unlock()
}

// RotateSession moves an existing session under a freshly minted ID and
// issues a replacement Set-Cookie on w. It's the textbook defence against
// session fixation: if an attacker tricked a victim into loading a page
// that pre-seeded __wewaf_sid, rotating after the browser proves itself
// legitimate (challenge pass) means the attacker's captured ID is dead
// weight. Returns the new ID, or oldID unchanged if rotation isn't
// possible (unknown id / nil writer / tracker disabled).
func (t *Tracker) RotateSession(w http.ResponseWriter, oldID string) string {
	if t == nil || oldID == "" || w == nil {
		return oldID
	}
	newID := randomID()
	t.mu.Lock()
	s, ok := t.sessions[oldID]
	if !ok {
		t.mu.Unlock()
		return oldID
	}
	delete(t.sessions, oldID)
	s.ID = newID
	t.sessions[newID] = s
	t.mu.Unlock()
	t.setCookie(w, newID)
	return newID
}

// RecordBeacon is called when the client-side beacon posts an update.
// Values are additive (deltas since the last beacon), so legitimate
// clients accumulate event counts proportional to real use.
func (t *Tracker) RecordBeacon(id string, mouseDelta, keyDelta, timeOnPageDeltaMs uint64) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		// Defensive caps so a hostile client can't overflow our counters.
		if mouseDelta > 100_000 {
			mouseDelta = 100_000
		}
		if keyDelta > 10_000 {
			keyDelta = 10_000
		}
		if timeOnPageDeltaMs > 5*60*1000 {
			timeOnPageDeltaMs = 5 * 60 * 1000
		}
		s.MouseEvents += mouseDelta
		s.KeyEvents += keyDelta
		s.TimeOnPageMs += timeOnPageDeltaMs
		s.BeaconCount++
	}
	t.mu.Unlock()
}

// Lookup returns the session with the given ID, or nil if none. Used by
// the admin API to render per-session detail.
func (t *Tracker) Lookup(id string) *Session {
	if t == nil || id == "" {
		return nil
	}
	t.mu.RLock()
	s := t.sessions[id]
	t.mu.RUnlock()
	return s
}

// List returns a snapshot of every active session, most-recent first.
func (t *Tracker) List(limit int) []SessionView {
	if t == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	t.mu.RLock()
	out := make([]SessionView, 0, len(t.sessions))
	for _, s := range t.sessions {
		out = append(out, s.Snapshot())
	}
	t.mu.RUnlock()
	// O(n log n) instead of the previous nested-loop bubble sort — at
	// 200k sessions the old path was pathological (~40B comparisons).
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Count returns the number of live sessions.
func (t *Tracker) Count() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

func (t *Tracker) cleanupLoop() {
	defer func() { _ = recover() }()
	ticker := time.NewTicker(t.idleTTL / 3)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.sweep()
		}
	}
}

func (t *Tracker) sweep() {
	cutoff := time.Now().UTC().Add(-t.idleTTL)
	t.mu.Lock()
	for k, s := range t.sessions {
		if s.LastSeen.Before(cutoff) {
			delete(t.sessions, k)
		}
	}
	t.mu.Unlock()
}

// --- Cookie signing -----------------------------------------------------

func (t *Tracker) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    t.signCookie(id),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((t.idleTTL * 2).Seconds()),
	})
}

func (t *Tracker) signCookie(id string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(id))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	return id + "." + sig
}

// verifyCookie returns (id, true) if the signature is valid.
func (t *Tracker) verifyCookie(value string) (string, bool) {
	dot := strings.IndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return "", false
	}
	id := value[:dot]
	expect := t.signCookie(id)
	// Constant-time compare.
	if len(expect) != len(value) {
		return "", false
	}
	if !hmac.Equal([]byte(expect), []byte(value)) {
		return "", false
	}
	return id, true
}

// IssueChallengeCookie returns a signed cookie value proving a browser
// challenge was passed at a given time. The caller writes it via
// http.SetCookie with the ChallengeCookieName name.
func (t *Tracker) IssueChallengeCookie() (*http.Cookie, string) {
	nowSec := time.Now().UTC().Unix()
	payload := fmt.Sprintf("%d", nowSec)
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte("challenge:"))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	value := payload + "." + sig
	return &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: false, // readable by JS so the beacon can avoid re-challenging
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	}, value
}

// VerifyChallengeCookie returns (timestamp, true) if the cookie value is
// valid and signed by this tracker. A false return should be treated as
// "challenge not yet passed" rather than an error.
func (t *Tracker) VerifyChallengeCookie(value string) (time.Time, bool) {
	if value == "" || len(value) > maxCookieLen {
		return time.Time{}, false
	}
	dot := strings.IndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return time.Time{}, false
	}
	payload := value[:dot]
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte("challenge:"))
	mac.Write([]byte(payload))
	expectSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	if !hmac.Equal([]byte(expectSig), []byte(value[dot+1:])) {
		return time.Time{}, false
	}
	sec := int64(0)
	for _, c := range payload {
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
		sec = sec*10 + int64(c-'0')
	}
	return time.Unix(sec, 0).UTC(), true
}

// --- Helpers ------------------------------------------------------------

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a time-seeded ID. Not unique under concurrency
		// but collisions on the hot path are re-keyed by the cookie.
		n := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(n >> (uint(i) * 8))
		}
	}
	return hex.EncodeToString(b)
}

// clientIP extracts the best-guess client IP for this request. When the
// operator has set TrustXFF we consult X-Forwarded-For / X-Real-Ip first
// (stripping port numbers and whitespace). Otherwise we fall back to the
// TCP-layer RemoteAddr so a client can't spoof the source IP by adding a
// header. Using net.SplitHostPort handles IPv6 correctly (the previous
// LastIndexByte shortcut broke on `[::1]:12345`).
func (t *Tracker) clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if t != nil && t.trustXFF.Load() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Left-most value is the original client per RFC 7239.
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

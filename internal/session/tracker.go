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
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wewaf/internal/clientip"
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
// All fields are guarded by Tracker.mu — they are written under the write
// lock (touchSession/RecordBlock/RecordBeacon/…) and must only be read while
// holding the lock (see Tracker.View / Tracker.List). Snapshot() copies the
// maps, so it too must run under the lock.
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
	//
	// FirstJA3 is the hash captured on the FIRST request of the session.
	// JA3Drifts counts how many distinct JA3 hashes we've seen on this
	// session ID since then — a non-zero count is the cleanest signal we
	// have for cookie sharing / theft (the same session ID arriving with
	// a different TLS stack means the cookie is in someone else's
	// browser). Score() weights this aggressively.
	JA3        string
	JA3Verdict string
	JA3Reason  string
	FirstJA3   string
	JA3Drifts  int

	// UAAnomalyBump is the highest UA↔TLS-fingerprint disagreement score this
	// session has shown (e.g. a UA claiming Chrome while the JA3/JA4 is curl).
	// A disagreement between two independent signals is a strong, low-FP
	// automation tell; the bump is folded into the risk score. UAAnomalyReason
	// records the matched tags for the admin UI.
	UAAnomalyBump   int
	UAAnomalyReason string

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
	// challengeTTLSec is how long a successful browser challenge is
	// honoured by the scoring path. After this many seconds, the
	// missing-challenge bump re-applies and the session must re-run
	// the challenge to re-suppress it. Stored as int64 seconds for
	// atomic load/store.
	challengeTTLSec atomic.Int64
	// scoreDecayPerMin is how many score points fade per quiet
	// minute. 0 disables decay (legacy monotonic). Stored atomic so
	// the admin API can re-tune at runtime.
	scoreDecayPerMin atomic.Int64

	// ipExtractor encapsulates the trust_xff + trusted_proxies policy
	// shared with the proxy layer. Held behind an atomic.Pointer so
	// SetClientIPExtractor can swap the policy on hot-reload without
	// taking a lock on the per-request hot path. Nil is tolerated and
	// degrades to RemoteAddr-only — exactly the safe default.
	ipExtractor atomic.Pointer[clientip.Extractor]
}

// Config holds tracker tuning. Zero/empty fields fall back to sane defaults.
type Config struct {
	Secret             string              // HMAC key for cookie signing; auto-generated if empty
	MaxSessions        int                 // hard cap on live sessions (default 200 000)
	IdleTTL            time.Duration       // evict sessions idle longer than this (default 30 min)
	Enabled            bool                // if false, GetOrCreate still works but signals are skipped
	RequestRateCeiling int                 // per-minute threshold that starts scoring
	PathCountCeiling   int                 // distinct-path threshold that starts scoring
	IPExtractor        *clientip.Extractor // shared trust-policy resolver; required for IP drift scoring
	// ChallengeTTL bounds how long a successful browser challenge
	// is honoured by Score() before the missing-challenge bump
	// re-applies. Defaults to 24 h. <=0 means "never expire" but
	// that defeats the cookie-replay-detection class of bot — use
	// only for development.
	ChallengeTTL time.Duration
	// ScoreDecayPerMin is how many score points fade per minute of
	// quiet time. 0 keeps the legacy monotonic behaviour.
	ScoreDecayPerMin int
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
	if cfg.IPExtractor != nil {
		t.ipExtractor.Store(cfg.IPExtractor)
	}
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
	if cfg.ChallengeTTL > 0 {
		t.challengeTTLSec.Store(int64(cfg.ChallengeTTL.Seconds()))
	} else {
		t.challengeTTLSec.Store(int64(24 * time.Hour.Seconds()))
	}
	if cfg.ScoreDecayPerMin > 0 {
		t.scoreDecayPerMin.Store(int64(cfg.ScoreDecayPerMin))
	}
	go t.cleanupLoop()
	return t
}

// SetChallengeTTL updates the challenge-pass freshness window at
// runtime. Atomic — safe to call from the admin API hot path.
func (t *Tracker) SetChallengeTTL(d time.Duration) {
	if t == nil {
		return
	}
	if d <= 0 {
		t.challengeTTLSec.Store(0)
		return
	}
	t.challengeTTLSec.Store(int64(d.Seconds()))
}

// SetScoreDecayPerMin updates the per-minute score decay rate.
// 0 disables decay (legacy monotonic behaviour); positive values
// cap at 50 so a typo can't make all sessions look benign.
func (t *Tracker) SetScoreDecayPerMin(rate int) {
	if t == nil {
		return
	}
	if rate < 0 {
		rate = 0
	}
	if rate > 50 {
		rate = 50
	}
	t.scoreDecayPerMin.Store(int64(rate))
}

// Stop halts the cleanup goroutine. Safe to call multiple times.
func (t *Tracker) Stop() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

// SetEnabled flips the tracker on/off at runtime. When disabled,
// GetOrCreate still returns a session (so cookies round-trip) but no
// scoring work happens on the hot path.
func (t *Tracker) SetEnabled(on bool) { t.enabled.Store(on) }

// SetClientIPExtractor swaps in a new trust policy at runtime. Pass
// nil to fall back to RemoteAddr-only behaviour. The extractor is
// shared with the proxy layer so both agree on the same source-IP
// truth — config hot-reload calls this on the same instance both
// layers reference, so a single Update() suffices for the whole WAF.
func (t *Tracker) SetClientIPExtractor(ipx *clientip.Extractor) {
	if t == nil {
		return
	}
	t.ipExtractor.Store(ipx)
}

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
			t.setCookie(w, id, t.requestIsTLS(r))
		}
	}
	s := t.touchSession(id, r)
	return s
}

// requestIsTLS reports whether the request was received over a TLS
// channel — either directly (r.TLS != nil) or via a trusted edge proxy
// announcing the original scheme. Used to gate the Cookie Secure flag.
//
// Forwarding-header trust is delegated to the same *clientip.Extractor
// the proxy uses for client-IP decisions. Without that gate an attacker
// who reached the WAF directly could send X-Forwarded-Proto: https,
// receive a Secure cookie, and then capture it on the next plaintext
// hop because the browser sees no contradiction. With the gate, only
// peers in the trusted_proxies CIDR set can announce TLS.
func (t *Tracker) requestIsTLS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if t == nil {
		return false
	}
	return t.ipExtractor.Load().IsTLSRequest(r)
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
// Idempotent on a steady fingerprint: writing the same hash twice is a
// no-op so this is cheap to call on every request. Verdict and reason are
// overwritten on each call so a list reload by the operator takes effect
// for in-flight sessions.
//
// FIRST-SEEN tracking: the first non-empty hash for a session is stored
// in FirstJA3 and never overwritten. Subsequent calls with a different
// hash bump JA3Drifts — the per-session count Score() weights heavily.
// This is the cleanest tell we have for cookie sharing / theft, since
// a stolen __wewaf_sid replayed from a different machine carries a
// different TLS stack and produces a different JA3.
func (t *Tracker) RecordJA3(id, hash, verdict, reason string) {
	if t == nil || id == "" || hash == "" {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		if s.FirstJA3 == "" {
			s.FirstJA3 = hash
		} else if s.FirstJA3 != hash && s.JA3 != hash {
			// Drift only when this hash differs from BOTH the
			// first-seen and the most-recent. The "different from
			// most-recent" guard keeps a NAT-induced flap (rare but
			// possible across mobile-network reconnects) from
			// counting twice.
			s.JA3Drifts++
		}
		s.JA3 = hash
		s.JA3Verdict = verdict
		s.JA3Reason = reason
	}
	t.mu.Unlock()
}

// RecordUAAnomaly folds a UA↔TLS-fingerprint disagreement into the session.
// We keep the HIGHEST bump observed (not a sum) so repeated requests from the
// same anomalous client don't runaway-inflate the score, while a single strong
// disagreement still contributes its full weight. A zero/negative bump is a
// no-op so the caller can pass the AnomalyResult straight through.
func (t *Tracker) RecordUAAnomaly(id string, bump int, reason string) {
	if t == nil || id == "" || bump <= 0 {
		return
	}
	t.mu.Lock()
	if s, ok := t.sessions[id]; ok {
		if bump > s.UAAnomalyBump {
			s.UAAnomalyBump = bump
			s.UAAnomalyReason = reason
		}
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
//
// `secure` controls whether the replacement cookie carries the Secure
// flag — pass true when the originating request arrived over TLS so the
// rotated cookie keeps the same transport guarantees as the original.
func (t *Tracker) RotateSession(w http.ResponseWriter, oldID string, secure bool) string {
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
	t.setCookie(w, newID, secure)
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
// View returns a locked snapshot of one session by ID. The read lock is held
// across Snapshot() so the map iteration inside it (Paths/UserAgents/IPs)
// cannot race a concurrent touchSession() write — that race is a FATAL
// "concurrent map iteration and map write", not a recoverable error, so it
// would crash the whole process. Callers must use this rather than reading
// fields off a bare *Session pointer.
func (t *Tracker) View(id string) (SessionView, bool) {
	if t == nil || id == "" {
		return SessionView{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.sessions[id]
	if !ok {
		return SessionView{}, false
	}
	return s.Snapshot(), true
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

func (t *Tracker) setCookie(w http.ResponseWriter, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    t.signCookie(id),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((t.idleTTL * 2).Seconds()),
	})
}

func (t *Tracker) signCookie(id string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(id))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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

// IssueChallengeCookie returns the `__wewaf_bc` cookie set after a
// successful browser challenge. It is a CLIENT-SIDE hint only: the
// challenge JS reads it (it is HttpOnly:false) to avoid re-running the
// passive probe on every page, and it is NOT trusted server-side for any
// enforcement decision. The authoritative, session-bound pass state lives
// in Session.ChallengePassed (set by RecordChallengePass) and the
// single-use gate nonce (IssueChallengeNonce) — neither of which a
// replayable bearer cookie could satisfy. The cookie's value is a signed
// timestamp purely so the client can reason about its own freshness.
//
// `secure` should be true when the originating request arrived over
// TLS so the cookie is never sent over plaintext after a successful
// challenge.
func (t *Tracker) IssueChallengeCookie(secure bool) (*http.Cookie, string) {
	nowSec := time.Now().UTC().Unix()
	payload := fmt.Sprintf("%d", nowSec)
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte("challenge:"))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	value := payload + "." + sig
	return &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: false, // readable by JS so the beacon can avoid re-challenging
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	}, value
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

// clientIP extracts the best-guess client IP for this request,
// honouring the shared trust_xff + trusted_proxies policy. When no
// extractor is wired we degrade to RemoteAddr-only — a safe default
// that never accepts a client-supplied forwarding header.
func (t *Tracker) clientIP(r *http.Request) string {
	if t == nil {
		return ""
	}
	return t.ipExtractor.Load().ClientIP(r)
}

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wewaf/internal/session"
)

// powCookieName mirrors the constant in internal/web/handlers_session.go.
// We duplicate it (rather than import from web) because importing web
// would create a cycle (web → proxy → web). The two constants are
// covered by a cross-package test in proxy/pow_gate_test.go that imports
// both and asserts they match.
const powCookieName = "__wewaf_pow"

// hasValidPoWCookie returns true when the request carries a __wewaf_pow
// cookie that validates against the configured secret AND was issued
// within PoWCookieTTLSec. Constant-time on signature compare.
func (wp *WAFProxy) hasValidPoWCookie(r *http.Request) bool {
	if wp == nil || wp.cfg == nil || !wp.cfg.PoWEnabled || wp.cfg.PoWSecret == "" {
		return false
	}
	c, err := r.Cookie(powCookieName)
	if err != nil || c == nil || c.Value == "" || len(c.Value) > 256 {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return false
	}
	body := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(wp.cfg.PoWSecret))
	mac.Write([]byte(body))
	// Full SHA-256 digest — must match handlers_session.go:signPowCookie.
	// The previous truncation to 12 bytes provided no security benefit
	// and was the one footgun shared across all our cookie signers.
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return false
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	ttl := time.Duration(wp.cfg.PoWCookieTTLSec) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	if time.Since(time.Unix(ts, 0)) > ttl {
		return false
	}
	return true
}

// shouldGateWithPoW returns true if the proxy should serve the PoW page
// for this request. Requires: PoW enabled, an issuer attached, the
// session score above the configured trigger, and no valid pass cookie.
func (wp *WAFProxy) shouldGateWithPoW(r *http.Request, score int) bool {
	if wp == nil || wp.pow == nil || !wp.cfg.PoWEnabled {
		return false
	}
	trigger := wp.cfg.PoWTriggerScore
	if trigger <= 0 {
		trigger = 60
	}
	if score < trigger {
		return false
	}
	return !wp.hasValidPoWCookie(r)
}

// servePoWChallenge renders the PoW gate page for the given request. The
// caller is responsible for stopping the request pipeline after this
// returns. Always returns nil — errors render an empty 503 rather than
// leaking page state.
//
// A per-IP issuance rate-limit guards against an attacker grinding the
// gate to burn server CPU on token signing. Limit is 10 issuances per
// minute per source IP; bursts above that get a 429 with a Retry-After
// header. The state lives in a small in-memory ring keyed by IP.
func (wp *WAFProxy) servePoWChallenge(w http.ResponseWriter, r *http.Request, score int) {
	if wp == nil || wp.pow == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	ip := wp.ipExtractor.ClientIP(r)
	if !wp.allowPoWIssuance(ip) {
		// Rate-limited — record as a log-only event so operators see
		// the abuse pattern.
		wp.metrics.RecordBlockWithCategory(ip, r.Method, r.URL.Path,
			"POW-RATE-LIMIT", "pow", "pow issuance rate-limited", 0)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	difficulty := wp.pow.SuggestDifficulty(score)
	tok, ser, err := wp.pow.Issue(difficulty)
	if err != nil {
		// RNG failure is the only documented Issue() error; fail open
		// rather than blocking the user on it.
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	saltB64 := base64.RawURLEncoding.EncodeToString(tok.Salt)
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusServiceUnavailable)
	// Use JSON-safe JS string literals — Go's %q would leave "</script>"
	// in `next` (request-controlled) intact, breaking out of the script
	// tag and reflecting an XSS into the gate page.
	tokenJS, saltJS, nextJS := session.PoWPageInjectValues(ser, saltB64, next)
	fmt.Fprintf(w, session.PoWPageHTML, tokenJS, saltJS, difficulty, nextJS)
	wp.powIssued.Add(1)
	// Log-only history event so operators can see PoW activity in the
	// dashboard timeline.
	wp.metrics.RecordBlockWithCategory(ip, r.Method, r.URL.Path,
		"POW-ISSUED", "pow",
		fmt.Sprintf("pow gate fired (difficulty=%d score=%d)", difficulty, score), 0)
}

// allowPoWIssuance decides whether ip is permitted another challenge
// issuance right now. It uses a fixed-window counter: at most
// powIssueLimit issues in the rolling powIssueWindow. Single map
// guarded by a Mutex — operations are O(1) amortised, and the map's
// entries are only as large as the recent attacker fan-out.
func (wp *WAFProxy) allowPoWIssuance(ip string) bool {
	if wp == nil || ip == "" {
		return true
	}
	wp.powIssueMu.Lock()
	defer wp.powIssueMu.Unlock()
	if wp.powIssueCounters == nil {
		wp.powIssueCounters = make(map[string]*powIssueCounter, 256)
	}
	now := time.Now()
	ent, ok := wp.powIssueCounters[ip]
	if !ok || now.Sub(ent.windowStart) > powIssueWindow {
		// Drop a few stale entries opportunistically so the map can't
		// grow unbounded under a sustained attack with rotating IPs.
		if len(wp.powIssueCounters) > 4096 {
			drop := 64
			for k := range wp.powIssueCounters {
				delete(wp.powIssueCounters, k)
				drop--
				if drop <= 0 {
					break
				}
			}
		}
		wp.powIssueCounters[ip] = &powIssueCounter{
			windowStart: now,
			count:       1,
		}
		return true
	}
	if ent.count >= powIssueLimit {
		return false
	}
	ent.count++
	return true
}

const (
	// powIssueLimit is the per-IP cap on PoW issuances per
	// powIssueWindow. Set conservatively: a real user only sees the gate
	// when their session is high-risk, and even pathological retries
	// (page reload during solve, multi-tab) shouldn't exceed 10/min.
	powIssueLimit  = 10
	powIssueWindow = time.Minute
)

// powIssueCounter is a fixed-window counter — much simpler than a
// proper sliding window, which we don't need at this resolution.
type powIssueCounter struct {
	windowStart time.Time
	count       int
}

// scoreFor reads the session's current risk score, or returns 0 if the
// tracker isn't present / the session ID is empty. Wraps the lookup so
// the call site reads cleanly.
func scoreFor(wp *WAFProxy, sessID string) int {
	if wp == nil || wp.sessions == nil || sessID == "" {
		return 0
	}
	return wp.sessions.Score(sessID)
}

// isPoWBypassPath returns true for URLs the PoW gate must never block.
// These are the assets/endpoints the gate page itself depends on, plus
// any internal admin paths a gated client might still need to reach.
func isPoWBypassPath(p string) bool {
	switch p {
	case "/api/pow.js",
		"/api/pow/verify",
		"/api/browser-challenge.js",
		"/api/browser-beacon.js",
		"/api/browser-challenge/verify",
		"/api/session/beacon":
		return true
	}
	// Anything under /api/ is admin surface; we don't gate the admin port.
	// (The proxy and admin port are different listeners, but in single-port
	// or test setups some operators expose both — this keeps them working.)
	return false
}


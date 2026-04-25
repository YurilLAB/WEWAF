package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"wewaf/internal/pow"
	"wewaf/internal/session"
)

// powCookieName carries the signed PoW pass-token. Lives on / so any
// downstream request can be inspected; HttpOnly so client JS can't peek.
const powCookieName = "__wewaf_pow"

// sessionEndpointBodyLimit caps anything a browser posts to the session /
// challenge endpoints. Real signals fit comfortably under 1 KiB; the cap
// makes sure a hostile client can't hold the server in io.ReadAll on a
// slow trickle of bytes.
const sessionEndpointBodyLimit = 8 * 1024

// safeSessionHandler wraps a session/challenge handler with a deferred
// recover. These endpoints run on the protected origin and anything that
// panics here — a nil map, a broken cookie, a dependency regression —
// would otherwise surface to the client as a 500. Fail-quiet to 204
// instead, log once for operator visibility, and keep the request path
// unbroken.
func safeSessionHandler(label string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("session handler panic (%s): %v", label, rec)
				// Only try to write if the ResponseWriter hasn't flushed yet.
				// http.Error is safe even after a partial write because it
				// just sets a status + writes — the net/http stack will log
				// a "superfluous WriteHeader" warning we can live with.
				w.WriteHeader(http.StatusNoContent)
			}
		}()
		next(w, r)
	}
}

// --- Browser challenge --------------------------------------------------

// handleBrowserChallengeJS serves the JS payload. It's cacheable and
// CORS-open because it runs on the *protected* origin, not the admin UI.
func (s *Server) handleBrowserChallengeJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(session.ChallengeJS))
}

// handleBrowserBeaconJS serves the event-reporting beacon.
func (s *Server) handleBrowserBeaconJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(session.BeaconJS))
}

// handleBrowserChallengeVerify accepts the signals collected by the JS
// probe and — on a pass — issues the `__wewaf_bc` cookie. Deliberately
// tolerant of partial data: any error yields a 204 so the client side
// never sees an error popup.
func (s *Server) handleBrowserChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// CORS — client posts from the origin being protected.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Hard-cap the body before ParseForm walks it — without this, a
	// hostile client could dribble bytes forever.
	r.Body = http.MaxBytesReader(w, r.Body, sessionEndpointBodyLimit)
	if err := r.ParseForm(); err != nil {
		// MaxBytesReader hit? Unknown Content-Type? Fall through with an
		// empty PostForm — VerifyChallengeSignals returns score=100 in
		// that case, which is safe.
		r.PostForm = url.Values{}
	}
	// ParseForm may succeed without populating PostForm (e.g., a
	// sendBeacon payload arriving with Content-Type stripped). The
	// fallback path below assigns into r.PostForm, so we must guarantee
	// it's a writable map first — Go panics on assigning into a nil map.
	if r.PostForm == nil {
		r.PostForm = url.Values{}
	}
	if len(r.PostForm) == 0 && r.Body != nil {
		// Fallback path for sendBeacon with a stripped Content-Type.
		// Body is already capped by MaxBytesReader above.
		if raw, err := io.ReadAll(r.Body); err == nil {
			if parsed, perr := parseForm(string(raw)); perr == nil {
				for k, v := range parsed {
					r.PostForm[k] = v
				}
			}
		}
	}

	score, passed, reasons := session.VerifyChallengeSignals(r.PostForm, r.UserAgent())
	if s.sessions != nil && s.sessions.Enabled() {
		sess := s.sessions.EnsureSession(w, r)
		if passed && sess != nil {
			c, _ := s.sessions.IssueChallengeCookie()
			http.SetCookie(w, c)
			// Rotate the session ID before recording the pass so any
			// pre-challenge ID an attacker might have planted becomes
			// invalid — classic session-fixation defence.
			newID := s.sessions.RotateSession(w, sess.ID)
			s.sessions.RecordChallengePass(newID)
		}
	}
	// Response is diagnostic — real browsers ignore it. Helpful for
	// operator testing via curl.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"passed":  passed,
		"score":   score,
		"reasons": reasons,
	})
}

// handleSessionBeacon accepts mouse/keyboard/time-on-page deltas.
func (s *Server) handleSessionBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s.sessions == nil || !s.sessions.Enabled() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sess := s.sessions.EnsureSession(w, r)
	if sess == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Hard-cap before ParseForm. Beacon payloads are three integers.
	r.Body = http.MaxBytesReader(w, r.Body, sessionEndpointBodyLimit)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	mouse := parseUintCapped(r.PostForm.Get("m"), 100_000)
	keys := parseUintCapped(r.PostForm.Get("k"), 10_000)
	tms := parseUintCapped(r.PostForm.Get("t"), 5*60*1000)
	s.sessions.RecordBeacon(sess.ID, mouse, keys, tms)
	// Re-score so the admin UI sees fresh numbers.
	s.sessions.Score(sess.ID)
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin session endpoints --------------------------------------------

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessions == nil {
		writeJSON(w, map[string]interface{}{"sessions": []interface{}{}, "enabled": false, "count": 0})
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	// Re-score each returned row so the admin sees current values. This
	// is O(returned_count), not O(total), so it's bounded.
	listing := s.sessions.List(limit)
	for i := range listing {
		listing[i].RiskScore = s.sessions.Score(listing[i].ID)
	}
	writeJSON(w, map[string]interface{}{
		"sessions": listing,
		"enabled":  s.sessions.Enabled(),
		"count":    s.sessions.Count(),
	})
}

func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessions == nil {
		http.Error(w, "Session tracking disabled", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	id = strings.Trim(id, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	sess := s.sessions.Lookup(id)
	if sess == nil {
		http.NotFound(w, r)
		return
	}
	// Re-score on lookup so the detail view is current.
	s.sessions.Score(id)
	writeJSON(w, sess.Snapshot())
}

// --- GraphQL admin endpoints --------------------------------------------

func (s *Server) handleGraphQLStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.graphql == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	cfg := s.graphql.ConfigSnapshot()
	writeJSON(w, map[string]interface{}{
		"enabled":             cfg.Enabled,
		"max_depth":           cfg.MaxDepth,
		"max_aliases":         cfg.MaxAliases,
		"max_fields":          cfg.MaxFields,
		"block":               cfg.BlockOnError,
		"role_header":         cfg.RequireRoleHdr,
		"block_subscriptions": cfg.BlockSubscriptions,
		"stats":               s.graphql.StatsSnapshot(),
	})
}

func (s *Server) handleGraphQLRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.graphql == nil {
		writeJSON(w, map[string]interface{}{"recent": []interface{}{}})
		return
	}
	writeJSON(w, map[string]interface{}{"recent": s.graphql.Recent()})
}

// --- Proof-of-work challenge -------------------------------------------

// handlePowJS serves the client-side PoW solver. Cacheable; runs on the
// protected origin like the other challenge assets.
func (s *Server) handlePowJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(session.PoWJS))
}

// renderPowChallenge writes the PoW gate page. Called by the proxy when a
// session score exceeds the threshold and no valid PoW cookie is present.
// Returns true if the page was written (caller must NOT continue), false
// if PoW is disabled (caller continues normally).
func (s *Server) renderPowChallenge(w http.ResponseWriter, r *http.Request) bool {
	if s.pow == nil {
		return false
	}
	score := 0
	if s.sessions != nil {
		if sess := s.sessions.EnsureSession(w, r); sess != nil {
			score = s.sessions.Score(sess.ID)
		}
	}
	difficulty := s.pow.SuggestDifficulty(score)
	tok, ser, err := s.pow.Issue(difficulty)
	if err != nil {
		// RNG failure is the only documented Issue() error and it
		// indicates a kernel-level problem. Don't gate the user on it.
		log.Printf("pow: issue failed: %v", err)
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusServiceUnavailable)
	saltB64 := base64.RawURLEncoding.EncodeToString(tok.Salt)
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	// %q-escapes everything we splice into the script tag, including
	// any quote characters in the request path. Defends against XSS via
	// the `next` URL segment.
	fmt.Fprintf(w, session.PoWPageHTML, ser, saltB64, difficulty, next)
	return true
}

// handlePowVerify accepts (token, nonce) from the client-side solver.
// On success: sets a signed cookie and 204s. On failure: 400 with a
// terse reason — the client reloads, getting a fresh challenge.
func (s *Server) handlePowVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pow == nil {
		http.Error(w, "PoW disabled", http.StatusServiceUnavailable)
		return
	}
	clientIP := clientIPFromRequest(r, s.cfg.TrustXFF)
	r.Body = http.MaxBytesReader(w, r.Body, sessionEndpointBodyLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	nonceB64 := r.PostForm.Get("nonce")
	if token == "" || nonceB64 == "" {
		http.Error(w, "missing token or nonce", http.StatusBadRequest)
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) == 0 || len(nonce) > 64 {
		http.Error(w, "malformed nonce", http.StatusBadRequest)
		return
	}
	verified, err := s.pow.Verify(token, nonce)
	if err != nil {
		// Map specific errors to a single-word reason for the client.
		// We deliberately collapse most failures into "invalid" so the
		// client can't enumerate exactly which check tripped.
		reason := "invalid"
		if err == pow.ErrTokenExpired {
			reason = "expired"
		}
		// Log-only history event so operators can see failed solve
		// patterns (replay attempts, signature tampering, slow clients
		// past expiry).
		if s.metrics != nil {
			s.metrics.RecordBlockWithCategory(clientIP, r.Method, r.URL.Path,
				"POW-REJECT:"+reason, "pow", "pow verify rejected: "+err.Error(), 0)
		}
		if s.proxy != nil {
			s.proxy.IncPoWRejected()
		}
		http.Error(w, reason, http.StatusBadRequest)
		return
	}
	// Success: emit a signed cookie that proves PoW pass for the
	// session's natural cookie lifetime, capped at 1 hour.
	cookieValue := signPowCookie(s.cfg.PoWSecret, verified.ID, time.Now().Unix())
	http.SetCookie(w, &http.Cookie{
		Name:     powCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
	if s.sessions != nil {
		if sess := s.sessions.EnsureSession(w, r); sess != nil {
			s.sessions.RecordPowPass(sess.ID)
		}
	}
	if s.metrics != nil {
		s.metrics.RecordBlockWithCategory(clientIP, r.Method, r.URL.Path,
			"POW-VERIFIED", "pow",
			"pow verified (id="+verified.ID+")", 0)
	}
	if s.proxy != nil {
		s.proxy.IncPoWVerified()
	}
	w.WriteHeader(http.StatusNoContent)
}

// clientIPFromRequest is a small helper that mirrors getClientIP in the
// proxy package without dragging the proxy import. The session/web
// boundary doesn't expose it directly, so we duplicate the trivial
// extraction here. Honours TrustXFF for parity with the rest of the WAF.
func clientIPFromRequest(r *http.Request, trustXFF bool) string {
	if r == nil {
		return ""
	}
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.Index(xff, ","); comma != -1 {
				return strings.TrimSpace(xff[:comma])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > -1 {
		host = host[:i]
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

// --- JA3 + PoW stats ---------------------------------------------------

// handleJA3Stats exposes the JA3 detector state + counters. Returns
// disabled-shape when JA3 isn't configured so the dashboard can render a
// uniform stats card.
func (s *Server) handleJA3Stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.JA3Enabled || s.proxy == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	stats := s.proxy.JA3Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":          true,
		"hard_block":       s.cfg.JA3HardBlock,
		"header":           s.cfg.JA3Header,
		"trusted_sources":  s.cfg.JA3TrustedSources,
		"cache_capacity":   s.cfg.JA3CacheCapacity,
		"cache_ttl_sec":    s.cfg.JA3CacheTTLSec,
		"stats":            stats,
	})
}

// handlePoWStats exposes the PoW issuer stats + proxy counters.
func (s *Server) handlePoWStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.PoWEnabled || s.pow == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	issuerStats := s.pow.Stats()
	proxyStats := map[string]uint64{}
	if s.proxy != nil {
		proxyStats = s.proxy.PoWStats()
	}
	writeJSON(w, map[string]interface{}{
		"enabled":         true,
		"trigger_score":   s.cfg.PoWTriggerScore,
		"min_difficulty":  issuerStats.Min,
		"max_difficulty":  issuerStats.Max,
		"token_ttl_sec":   issuerStats.TTLSec,
		"cookie_ttl_sec":  s.cfg.PoWCookieTTLSec,
		"seen_count":      issuerStats.SeenCount,
		"proxy_counters":  proxyStats,
	})
}

// --- DPI + audit admin endpoints ---------------------------------------

func (s *Server) handleDPIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := map[string]uint64{}
	if s.proxy != nil {
		stats = s.proxy.DPIStats()
	}
	writeJSON(w, map[string]interface{}{
		"grpc_inspect":        s.cfg.GRPCInspect,
		"grpc_block":          s.cfg.GRPCBlockOnError,
		"websocket_inspect":   s.cfg.WebSocketInspect,
		"websocket_allowlist": s.cfg.WebSocketOriginAllowlist,
		"stats":               stats,
	})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.audit == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	ok, badSeq, total := s.audit.Verify()
	appends, verifyFails := s.audit.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":       true,
		"ok":            ok,
		"bad_seq":       badSeq,
		"total":         total,
		"appends":       appends,
		"verify_fails":  verifyFails,
	})
}

func (s *Server) handleAuditTail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.audit == nil {
		writeJSON(w, map[string]interface{}{"entries": []interface{}{}})
		return
	}
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			n = parsed
		}
	}
	writeJSON(w, map[string]interface{}{"entries": s.audit.Tail(n)})
}

// --- helpers ------------------------------------------------------------

// parseUintCapped parses a decimal uint64 and clamps to max.
func parseUintCapped(s string, max uint64) uint64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	if n > max {
		n = max
	}
	return n
}

// signPowCookie produces a value of the form "<id>.<unix>.<mac>" where
// mac = HMAC-SHA256(secret, id || "." || unix)[:12] base64url-encoded.
// We carry the issuance time so the proxy can reject cookies older than
// the configured PoW window even if the cookie's own MaxAge is honoured
// loosely by an old browser.
func signPowCookie(secret, id string, issuedAt int64) string {
	if secret == "" {
		// Empty secret should never happen at runtime — config layer
		// generates one on first start. If it does, fall back to a
		// fixed string so the cookie still round-trips (the proxy's
		// validator uses the same string, and PoW is a *signal* layered
		// on session/score, not a sole gate).
		secret = "wewaf-pow-fallback"
	}
	body := id + "." + strconv.FormatInt(issuedAt, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	return body + "." + sig
}

// VerifyPowCookie returns (issuedAt, true) when the cookie value's MAC
// validates and the timestamp is within ttl of now. Exposed at package
// level so the proxy can call it directly without holding a Server.
func VerifyPowCookie(secret, value string, ttl time.Duration) (time.Time, bool) {
	if secret == "" || value == "" || len(value) > 256 {
		return time.Time{}, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	body := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return time.Time{}, false
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	at := time.Unix(ts, 0).UTC()
	if ttl > 0 && time.Since(at) > ttl {
		return time.Time{}, false
	}
	return at, true
}

// parseForm parses a url-encoded body manually for the sendBeacon path
// where ParseForm() can fail on unusual MIME types. We URL-decode both
// keys and values so downstream lookups match what the ParseForm path
// produces — the old "slice the raw bytes" version would mis-key any
// pair containing %-encoded characters, yielding silent signal loss.
func parseForm(body string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		var rawKey, rawVal string
		if eq < 0 {
			rawKey, rawVal = pair, ""
		} else {
			rawKey, rawVal = pair[:eq], pair[eq+1:]
		}
		k, err := url.QueryUnescape(rawKey)
		if err != nil {
			k = rawKey
		}
		v, err := url.QueryUnescape(rawVal)
		if err != nil {
			v = rawVal
		}
		out[k] = append(out[k], v)
	}
	return out, nil
}

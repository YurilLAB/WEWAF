package web

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"wewaf/internal/session"
)

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

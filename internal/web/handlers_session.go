package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"wewaf/internal/session"
)

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
	// Bound the body — signals should be under 1 KiB.
	_ = r.ParseForm() // also parses a url-encoded body
	if r.ContentLength <= 0 && len(r.PostForm) == 0 {
		// Try reading manually up to a small cap in case the body didn't
		// parse (sendBeacon sets Content-Type correctly but some proxies
		// strip it).
		limited := io.LimitReader(r.Body, 4096)
		if raw, err := io.ReadAll(limited); err == nil {
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
			s.sessions.RecordChallengePass(sess.ID)
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
	_ = r.ParseForm()
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
		"enabled":     cfg.Enabled,
		"max_depth":   cfg.MaxDepth,
		"max_aliases": cfg.MaxAliases,
		"max_fields":  cfg.MaxFields,
		"block":       cfg.BlockOnError,
		"role_header": cfg.RequireRoleHdr,
		"stats":       s.graphql.StatsSnapshot(),
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
// where ParseForm() can fail on unusual MIME types.
func parseForm(body string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			out[pair] = append(out[pair], "")
			continue
		}
		k := pair[:eq]
		v := pair[eq+1:]
		out[k] = append(out[k], v)
	}
	return out, nil
}

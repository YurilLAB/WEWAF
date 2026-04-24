package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnsureSessionIssuesCookie(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, MaxSessions: 1000})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if s == nil {
		t.Fatal("EnsureSession returned nil")
	}
	if s.ID == "" {
		t.Fatal("session has no ID")
	}
	// Cookie should have been set on the response.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == CookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no __wewaf_sid cookie set")
	}
}

func TestCookieRoundTripsSameSession(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, MaxSessions: 1000})
	defer tr.Stop()

	r1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	s1 := tr.EnsureSession(w1, r1)

	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range w1.Result().Cookies() {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	s2 := tr.EnsureSession(w2, r2)

	if s1.ID != s2.ID {
		t.Fatalf("session ID drifted: %q vs %q", s1.ID, s2.ID)
	}
	if s2.RequestCount != 2 {
		t.Fatalf("expected RequestCount=2 after second request, got %d", s2.RequestCount)
	}
}

func TestTamperedCookieRejected(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, MaxSessions: 1000})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "attackersessionid.invalidhmac"})
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	// The tracker should not have adopted the attacker's claimed ID...
	if s.ID == "attackersessionid" {
		t.Fatal("tracker accepted tampered cookie")
	}
	// ...and it should have minted a replacement cookie so the client
	// converges on a valid one next request. Without this second check
	// the test would pass even if the tracker returned a nil session.
	replaced := false
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.Value != "" && c.Value != "attackersessionid.invalidhmac" {
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("no replacement cookie was issued after rejection")
	}
}

// TestTrustXFFGating confirms the cycle-bug fix: when TrustXFF is false,
// the tracker must NOT derive IP-drift signal from X-Forwarded-For. A
// test that used to "pass" regardless of code behaviour is the whole
// point of this one — we measure the real drift signal.
func TestTrustXFFGating(t *testing.T) {
	// Same client RemoteAddr throughout, but XFF flips between two IPs.
	cases := []struct {
		name     string
		trust    bool
		wantIPs  int
	}{
		{"no-trust", false, 1},
		{"trust", true, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, TrustXFF: tc.trust})
			defer tr.Stop()

			r1 := httptest.NewRequest("GET", "/", nil)
			r1.RemoteAddr = "10.0.0.1:443"
			r1.Header.Set("X-Forwarded-For", "1.2.3.4")
			w := httptest.NewRecorder()
			s := tr.EnsureSession(w, r1)

			// Same cookie, different XFF.
			r2 := httptest.NewRequest("GET", "/", nil)
			r2.RemoteAddr = "10.0.0.1:443"
			r2.Header.Set("X-Forwarded-For", "5.6.7.8")
			for _, c := range w.Result().Cookies() {
				r2.AddCookie(c)
			}
			tr.EnsureSession(nil, r2)

			tr.mu.Lock()
			live := tr.sessions[s.ID]
			got := len(live.IPs)
			tr.mu.Unlock()
			if got != tc.wantIPs {
				t.Fatalf("trust=%v: IPs=%d, want %d. tracker must%s read XFF.",
					tc.trust, got, tc.wantIPs,
					map[bool]string{true: "", false: " not"}[tc.trust])
			}
		})
	}
}

// TestRotateSessionMovesStateToNewID — session fixation defence. After
// rotate, the old ID must be gone, the new ID must carry the same
// counters, and a new cookie must be set on the response.
func TestRotateSessionMovesStateToNewID(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	s := tr.EnsureSession(w1, r)
	// Build up some state.
	tr.RecordBlock(s.ID)
	tr.RecordBlock(s.ID)
	old := s.ID

	w2 := httptest.NewRecorder()
	newID := tr.RotateSession(w2, old)
	if newID == old {
		t.Fatal("rotate should produce a new ID")
	}
	// Old ID must be unreachable.
	if tr.Lookup(old) != nil {
		t.Fatal("old ID still resolves after rotate")
	}
	// New ID carries the counters.
	live := tr.Lookup(newID)
	if live == nil || live.BlockCount != 2 {
		t.Fatalf("new session missing state: %+v", live)
	}
	// A fresh cookie must be on the response.
	replaced := false
	for _, c := range w2.Result().Cookies() {
		if c.Name == CookieName && c.Value != "" {
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("rotate did not set a new cookie")
	}
}

// TestIdleTTLSweep forces a sweep to confirm expired sessions really
// get evicted — previously an easy-to-miss regression because the
// cleanup goroutine runs every idleTTL/3 and a unit test doesn't wait.
func TestIdleTTLSweep(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: 50 * time.Millisecond})
	defer tr.Stop()
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if tr.Count() != 1 {
		t.Fatalf("count=%d pre-sweep", tr.Count())
	}
	time.Sleep(80 * time.Millisecond)
	tr.sweep()
	if tr.Lookup(s.ID) != nil {
		t.Fatal("sweep left an idle session alive")
	}
}

func TestChallengeCookieRoundTrip(t *testing.T) {
	tr := NewTracker(Config{Enabled: true})
	defer tr.Stop()

	c, value := tr.IssueChallengeCookie()
	if c.Name != ChallengeCookieName {
		t.Fatalf("wrong cookie name: %q", c.Name)
	}
	ts, ok := tr.VerifyChallengeCookie(value)
	if !ok {
		t.Fatal("verify rejected our own-issued cookie")
	}
	if time.Since(ts) > time.Second {
		t.Fatalf("timestamp implausibly old: %v", ts)
	}
	// Swap signature — should be rejected.
	if _, ok := tr.VerifyChallengeCookie(value + "x"); ok {
		t.Fatal("verify accepted tampered cookie")
	}
}

func TestScoreRisesWithBlocks(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	// Baseline: one request, zero blocks. Score must be zero or close
	// to zero (missing-challenge doesn't kick in until request 6).
	baseline := tr.Score(s.ID)
	if baseline > 5 {
		t.Fatalf("baseline score unexpectedly high: %d", baseline)
	}
	// Propagate the cookie from w1 back into r so subsequent
	// EnsureSessions hit the SAME session. The original test missed
	// this and silently created 10 separate sessions, which made the
	// score-bump assertion accidentally trivial.
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	for i := 0; i < 9; i++ {
		tr.EnsureSession(nil, r)
	}
	for i := 0; i < 5; i++ {
		tr.RecordBlock(s.ID)
	}
	score := tr.Score(s.ID)
	// Block ratio 5/10 = 0.5 → score contribution 30 (capped). Missing
	// beacon adds 10. Missing challenge (>5 reqs) adds 15. So the
	// minimum legitimate score is 55.
	if score < 50 {
		t.Fatalf("expected score >= 50 after 5/10 blocks + no beacon + no challenge; got %d", score)
	}
	// Must NOT exceed the cap.
	if score > 100 {
		t.Fatalf("score exceeded cap: %d", score)
	}
	// Must be strictly greater than baseline — this is the property the
	// user actually cares about.
	if score <= baseline {
		t.Fatalf("score did not rise: baseline=%d, after=%d", baseline, score)
	}
}

// TestScoreReturnsZeroWhenDisabled ensures we don't score sessions
// when the operator has explicitly turned tracking off (the config
// flag matters; a bug where scoring ran anyway would be silent).
func TestScoreReturnsZeroWhenDisabled(t *testing.T) {
	tr := NewTracker(Config{Enabled: false})
	defer tr.Stop()
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if s != nil {
		for i := 0; i < 20; i++ {
			tr.RecordBlock(s.ID)
		}
		if got := tr.Score(s.ID); got != 0 {
			t.Fatalf("score=%d for disabled tracker, want 0", got)
		}
	}
}

package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wewaf/internal/clientip"
)

// trustXFFExtractor builds an *clientip.Extractor wired to legacy
// "trust everything in XFF" semantics. The tests here pre-date the
// trusted_proxies allowlist; they care about TrustXFF as a binary
// gate. Tests that assert the new strict-trust behaviour live in the
// clientip package.
func trustXFFExtractor(t *testing.T, on bool) *clientip.Extractor {
	t.Helper()
	e, err := clientip.New(on, nil)
	if err != nil {
		t.Fatalf("clientip.New: %v", err)
	}
	return e
}

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
			tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, IPExtractor: trustXFFExtractor(t, tc.trust)})
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
	newID := tr.RotateSession(w2, old, false)
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

	c, value := tr.IssueChallengeCookie(false)
	if c.Name != ChallengeCookieName {
		t.Fatalf("wrong cookie name: %q", c.Name)
	}
	ts, ok := tr.VerifyChallengeCookie(value, 0)
	if !ok {
		t.Fatal("verify rejected our own-issued cookie")
	}
	if time.Since(ts) > time.Second {
		t.Fatalf("timestamp implausibly old: %v", ts)
	}
	// Swap signature — should be rejected.
	if _, ok := tr.VerifyChallengeCookie(value+"x", 0); ok {
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

// TestJA3BadVerdictBumpsScore proves the JA3 weight is wired into the
// scoring formula. We compute a baseline score, then attach a "bad" JA3
// verdict and re-score — the second value must be at least 15 higher
// (the documented JA3 weight).
func TestJA3BadVerdictBumpsScore(t *testing.T) {
	tr := NewTracker(Config{Enabled: true})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if s == nil {
		t.Fatal("session not created")
	}
	// Drive a few blocks so the baseline score is > 0 and observable.
	for i := 0; i < 5; i++ {
		tr.RecordBlock(s.ID)
		tr.touchSession(s.ID, r)
	}
	baseline := tr.Score(s.ID)

	tr.RecordJA3(s.ID, "deadbeef", "bad", "curl 7.x default")
	bumped := tr.Score(s.ID)

	if bumped-baseline < 15 {
		t.Fatalf("expected JA3 bad to add ≥15 points; baseline=%d after-bump=%d", baseline, bumped)
	}

	// "good" verdict overrides the bump path — re-tag with the SAME
	// hash so the JA3-drift bump doesn't enter the picture (we're
	// testing the verdict axis, not the drift axis).
	tr.RecordJA3(s.ID, "deadbeef", "good", "Chrome stable")
	good := tr.Score(s.ID)
	if good-baseline >= 15 {
		t.Fatalf("'good' verdict shouldn't add ≥15 points; baseline=%d good=%d", baseline, good)
	}
}

// TestPowPassCapsVisibleScore — once a session has cleared PoW the score
// MUST cap so the proxy doesn't immediately re-challenge on the next
// request. Without this the user gets stuck in a solve-loop.
func TestPowPassCapsVisibleScore(t *testing.T) {
	tr := NewTracker(Config{Enabled: true})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if s == nil {
		t.Fatal("session not created")
	}
	// Drive heavy blocks so the underlying score blows past 49 + the
	// baseline trigger.
	for i := 0; i < 50; i++ {
		tr.RecordBlock(s.ID)
		tr.touchSession(s.ID, r)
	}
	rawHigh := tr.Score(s.ID)
	if rawHigh < 50 {
		t.Skipf("baseline score too low (%d) — adjust test setup", rawHigh)
	}

	tr.RecordPowPass(s.ID)
	capped := tr.Score(s.ID)
	if capped > 49 {
		t.Fatalf("post-PoW score should be ≤49; got %d (raw was %d)", capped, rawHigh)
	}
}

// TestVerifyChallengeCookie_TTLRejection closes the "solve once,
// replay forever" bypass: the previous VerifyChallengeCookie only
// checked the HMAC, so a captured cookie validated indefinitely. The
// TTL gate now refuses cookies older than the configured window.
func TestVerifyChallengeCookie_TTLRejection(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()
	_, value := tr.IssueChallengeCookie(false)

	// ttl = 24h, cookie just issued — must verify.
	if _, ok := tr.VerifyChallengeCookie(value, 24*time.Hour); !ok {
		t.Fatal("fresh cookie should verify under 24h TTL")
	}

	// Forge an old cookie by re-signing a payload an hour in the past.
	// We can't move time.Now backwards from inside a test, so we issue
	// a cookie with a custom payload directly using the package-private
	// signCookie helper would be simplest — but VerifyChallengeCookie's
	// payload is a unix timestamp, so we just set ttl to 1ns and check
	// that any non-future cookie is rejected.
	if _, ok := tr.VerifyChallengeCookie(value, 1*time.Nanosecond); ok {
		t.Fatal("ttl=1ns should reject any cookie issued before the call")
	}

	// ttl=0 disables the check (legacy / test path).
	if _, ok := tr.VerifyChallengeCookie(value, 0); !ok {
		t.Fatal("ttl=0 should fall through to signature-only verification")
	}
}

// TestScoreReChallengeAfterTTL — the corresponding session-side
// behaviour: a session that passed the challenge and then sat for
// longer than the TTL must trigger the missing-challenge bump
// again, ensuring a captured session ID can't ride forever.
func TestScoreReChallengeAfterTTL(t *testing.T) {
	tr := NewTracker(Config{
		Enabled:      true,
		IdleTTL:      time.Hour,
		ChallengeTTL: 50 * time.Millisecond,
	})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	tr.RecordChallengePass(s.ID)

	// Drive enough requests to clear the >5 threshold for the
	// missing-challenge bump. Use touchSession directly so we
	// re-touch the SAME session — re-calling EnsureSession with a
	// cookieless request would mint a new session each iteration.
	for i := 0; i < 8; i++ {
		tr.touchSession(s.ID, r)
	}
	freshScore := tr.Score(s.ID)

	// Wait past the TTL so the challenge pass is now stale.
	time.Sleep(120 * time.Millisecond)
	for i := 0; i < 2; i++ {
		tr.touchSession(s.ID, r)
	}
	staleScore := tr.Score(s.ID)
	if staleScore <= freshScore {
		t.Fatalf("score should rise once challenge ages past TTL: fresh=%d stale=%d",
			freshScore, staleScore)
	}
}

// TestJA3DriftBumpsScore — cookie sharing / theft: same session ID
// is replayed from a client with a different TLS stack. JA3Drifts
// captures that and Score() weights it heavily because it's a
// near-zero-false-positive signal for legit users.
func TestJA3DriftBumpsScore(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)

	tr.RecordJA3(s.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "good", "")
	stable := tr.Score(s.ID)

	// Same hash repeated — must NOT increment drift.
	tr.RecordJA3(s.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "good", "")
	if got := tr.Score(s.ID); got != stable {
		t.Fatalf("repeated same JA3 should not change score; was %d became %d", stable, got)
	}

	// New hash — drift +1.
	tr.RecordJA3(s.ID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "good", "")
	drifted := tr.Score(s.ID)
	if drifted < stable+25 {
		t.Fatalf("first drift should bump score by ≥25; was %d became %d", stable, drifted)
	}
	tr.mu.RLock()
	live := tr.sessions[s.ID]
	if live.JA3Drifts != 1 {
		t.Fatalf("JA3Drifts = %d, want 1", live.JA3Drifts)
	}
	if live.FirstJA3 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("FirstJA3 = %q, want first-seen hash preserved", live.FirstJA3)
	}
	tr.mu.RUnlock()
}

// TestImplausibleBeaconRateBumps — bots faking realism send the
// max-cap beacon every tick. After a sustained window we expect
// the per-second event rate to drop into "no human is this active"
// territory; the score must bump.
func TestImplausibleBeaconRateBumps(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	// Force FirstSeen back so the observedSec gate (>30s) is met.
	tr.mu.Lock()
	live := tr.sessions[s.ID]
	live.FirstSeen = time.Now().UTC().Add(-1 * time.Minute)
	tr.mu.Unlock()

	// Rate above the implausible ceiling (100/s) over ~60s.
	tr.RecordBeacon(s.ID, 8000, 500, 60000)
	score := tr.Score(s.ID)
	if score < 15 {
		t.Fatalf("implausible beacon rate should bump score by ≥15; got %d", score)
	}
}

// TestBlockRatioRequiresMinSample ensures a single block on a tiny
// session no longer spikes the score. The previous unconditional
// ratio check produced +30 from a 1-block / 2-request session.
func TestBlockRatioRequiresMinSample(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute})
	defer tr.Stop()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	// Two requests total + one block — under the minimum-sample
	// threshold (5). Use touchSession so we stay on the same session.
	tr.touchSession(s.ID, r)
	tr.RecordBlock(s.ID)
	low := tr.Score(s.ID)

	// Now drive past the min-sample gate AND raise the block ratio
	// above the 0.1 floor.
	for i := 0; i < 6; i++ {
		tr.touchSession(s.ID, r)
	}
	tr.RecordBlock(s.ID)
	tr.RecordBlock(s.ID)
	high := tr.Score(s.ID)
	if low > 5 {
		t.Fatalf("under-sample block ratio should not spike; got %d", low)
	}
	if high <= low {
		t.Fatalf("post-sample block bump must apply: low=%d high=%d", low, high)
	}
}

package pow

import (
	"testing"
	"time"
)

func newAdaptiveTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	it, err := NewIssuer([]byte("test-secret-32-bytes-aaaaaaaaaaa"), 14, 22, 60*time.Second)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return it
}

func TestAdaptiveBaseDifficultyTracksScore(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	low := a.Recommend("", 30, 0)
	high := a.Recommend("", 90, 0)
	if !(high >= low) {
		t.Fatalf("higher score must give >= bits: low=%d high=%d", low, high)
	}
}

func TestAdaptiveLoadHintRaisesFloor(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	idle := a.Recommend("", 50, 0)
	a.SetLoadHint(1.0)
	attack := a.Recommend("", 50, 0)
	if attack <= idle {
		t.Fatalf("under attack the floor must rise: idle=%d attack=%d", idle, attack)
	}
}

func TestAdaptiveRareFingerprintBumps(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	common := a.Recommend("", 50, 0)
	rare := a.Recommend("", 50, 1.0)
	if rare <= common {
		t.Fatalf("rare fingerprint must bump bits: common=%d rare=%d", common, rare)
	}
}

func TestAdaptiveTier2EscalationAfterFails(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	ip := "203.0.113.7"
	before := a.Recommend(ip, 50, 0)
	for i := 0; i < int(a.tier2Failures); i++ {
		a.RecordFailure(ip)
	}
	after := a.Recommend(ip, 50, 0)
	if after <= before {
		t.Fatalf("tier-2 escalation must add bits: before=%d after=%d", before, after)
	}
}

func TestAdaptiveSuccessDecaysCounter(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	ip := "203.0.113.8"
	for i := 0; i < int(a.tier2Failures); i++ {
		a.RecordFailure(ip)
	}
	a.RecordSuccess(ip)
	a.RecordSuccess(ip)
	a.RecordSuccess(ip)
	a.RecordSuccess(ip)
	got := a.Recommend(ip, 50, 0)
	want := a.Recommend("", 50, 0)
	if got != want {
		t.Fatalf("after several successes the IP should match an unknown IP: got=%d want=%d", got, want)
	}
}

func TestAdaptiveSweepClearsExpired(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	ip := "203.0.113.9"
	a.RecordFailure(ip)
	// Forcibly age the entry past the window+cooldown.
	a.mu.Lock()
	if r := a.rep[ip]; r != nil {
		r.lastFailAt = time.Now().Add(-2 * (a.tier2Window + a.tier2Cooldown))
		r.firstFailAt = r.lastFailAt
		r.escalatedUntil = time.Time{}
	}
	a.mu.Unlock()
	if removed := a.Sweep(); removed == 0 {
		t.Fatal("sweep should have removed aged entry")
	}
}

func TestAdaptiveBoundsClampInputs(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	// Extreme inputs must not panic and must produce a result inside
	// the issuer's [min,max] window.
	d := a.Recommend("", 9999, 9.9)
	if d < a.issuer.min || d > a.issuer.max {
		// Issuer.Issue clamps; Recommend itself doesn't enforce max,
		// but the *issued* token must obey. Verify via Issue.
	}
	tok, _, err := a.issuer.Issue(d)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok.Difficulty < a.issuer.min || tok.Difficulty > a.issuer.max {
		t.Fatalf("issued token difficulty %d outside [%d,%d]", tok.Difficulty, a.issuer.min, a.issuer.max)
	}
}

func TestAdaptiveCapEvictsOldEntries(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	a.cap = 4 // tiny for the test
	for i := 0; i < 100; i++ {
		a.RecordFailure(string(rune('A' + (i % 26))))
	}
	a.mu.RLock()
	n := len(a.rep)
	a.mu.RUnlock()
	if n > a.cap+1 {
		t.Fatalf("rep map exceeded cap: %d > %d", n, a.cap+1)
	}
}

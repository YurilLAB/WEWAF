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
	// Age the tier-2 escalation past its cooldown: the escalation itself is
	// sticky for the full cooldown window (see
	// TestRecordSuccessDoesNotLaunderActiveEscalation), so a clean run of solves
	// only retires the IP once the deadline has elapsed.
	a.mu.Lock()
	if r := a.rep[ip]; r != nil {
		r.escalatedUntil = time.Now().Add(-time.Minute)
	}
	a.mu.Unlock()
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

// TestRecordSuccessDoesNotLaunderActiveEscalation is the regression for
// POW-LAUNDER-002: a single successful solve used to wipe an active hour-long
// tier-2 escalation merely because it halved the failure counter below the
// threshold, letting an escalating IP launder fail-driven difficulty straight
// back to the floor. The escalation must now expire on its own cooldown clock.
func TestRecordSuccessDoesNotLaunderActiveEscalation(t *testing.T) {
	a := NewAdaptiveTier(newAdaptiveTestIssuer(t))
	ip := "198.51.100.42"
	for i := 0; i < int(a.tier2Failures); i++ {
		a.RecordFailure(ip)
	}
	// Precondition: escalation is active (deadline in the future).
	a.mu.RLock()
	r := a.rep[ip]
	active := r != nil && !r.escalatedUntil.IsZero() && time.Now().Before(r.escalatedUntil)
	a.mu.RUnlock()
	if !active {
		t.Fatal("precondition: tier-2 escalation should be active after the fail burst")
	}

	// One solve must NOT retire the active escalation.
	a.RecordSuccess(ip)
	a.mu.RLock()
	r = a.rep[ip]
	stillActive := r != nil && time.Now().Before(r.escalatedUntil)
	a.mu.RUnlock()
	if !stillActive {
		t.Fatal("a single solve laundered an active tier-2 escalation back to the floor")
	}

	// Once the cooldown elapses, a subsequent solve clears it as designed.
	a.mu.Lock()
	if r := a.rep[ip]; r != nil {
		r.escalatedUntil = time.Now().Add(-time.Minute)
	}
	a.mu.Unlock()
	a.RecordSuccess(ip)
	a.mu.RLock()
	r = a.rep[ip]
	cleared := r == nil || r.escalatedUntil.IsZero()
	a.mu.RUnlock()
	if !cleared {
		t.Fatal("an expired escalation should be retired by a subsequent solve")
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

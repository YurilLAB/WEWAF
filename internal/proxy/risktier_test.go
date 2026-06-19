package proxy

import (
	"context"
	"testing"
	"time"

	"wewaf/internal/config"
)

// TestRiskTierBands walks the ordered ladder throttle<challenge<block and the
// disabled-band cases. If this regresses, the graduated policy silently picks
// the wrong enforcement action for a session.
func TestRiskTierBands(t *testing.T) {
	const (
		throttleAt  = 30
		challengeAt = 60
		blockAt     = 90
	)
	cases := []struct {
		score int
		want  RiskAction
	}{
		{0, RiskAllow},
		{29, RiskAllow},
		{30, RiskThrottle},
		{59, RiskThrottle},
		{60, RiskChallenge},
		{89, RiskChallenge},
		{90, RiskBlock},
		{100, RiskBlock},
		{1000, RiskBlock},
	}
	for _, c := range cases {
		if got := riskTier(c.score, throttleAt, challengeAt, blockAt); got != c.want {
			t.Errorf("riskTier(%d) = %v, want %v", c.score, got, c.want)
		}
	}
}

// TestRiskTierDisabledBands confirms a threshold <= 0 disables its band.
func TestRiskTierDisabledBands(t *testing.T) {
	// Throttle off, challenge at 60, block off: only the challenge band acts.
	if got := riskTier(40, 0, 60, 0); got != RiskAllow {
		t.Errorf("throttle disabled: riskTier(40) = %v, want allow", got)
	}
	if got := riskTier(70, 0, 60, 0); got != RiskChallenge {
		t.Errorf("riskTier(70) = %v, want challenge", got)
	}
	// All bands off → always allow regardless of score.
	for _, s := range []int{0, 50, 100, 9999} {
		if got := riskTier(s, 0, 0, 0); got != RiskAllow {
			t.Errorf("all bands off: riskTier(%d) = %v, want allow", s, got)
		}
	}
}

// TestRiskTierFailSecureOnMisorder is the security-relevant property: if an
// operator mis-orders the bands so a stricter band sits below a looser one,
// the result must fail toward the *stricter* action, never silently downgrade.
func TestRiskTierFailSecureOnMisorder(t *testing.T) {
	// Block (50) set BELOW challenge (60). A score of 55 satisfies block;
	// fail-secure means it blocks rather than dropping to a mere challenge.
	if got := riskTier(55, 0, 60, 50); got != RiskBlock {
		t.Fatalf("misordered bands must fail secure: riskTier(55) = %v, want block", got)
	}
	if got := riskTier(65, 0, 60, 50); got != RiskBlock {
		t.Fatalf("misordered bands must fail secure: riskTier(65) = %v, want block", got)
	}
}

// FuzzRiskTier asserts the two contract invariants over arbitrary inputs:
//   1. Totality: the result is always one of the four defined actions.
//   2. Monotonicity: for any fixed bands, severity is non-decreasing in score
//      (raising the score can only escalate, never de-escalate, enforcement).
//
// Run: go test ./internal/proxy -run x -fuzz FuzzRiskTier -fuzztime 30s
func FuzzRiskTier(f *testing.F) {
	f.Add(0, 30, 60, 90)
	f.Add(55, 0, 60, 50)   // misordered
	f.Add(100, 0, 0, 0)    // all bands off
	f.Add(-5, -1, -1, -1)  // negatives
	f.Add(75, 90, 60, 30)  // fully reversed

	f.Fuzz(func(t *testing.T, score, throttleAt, challengeAt, blockAt int) {
		a := riskTier(score, throttleAt, challengeAt, blockAt)
		switch a {
		case RiskAllow, RiskThrottle, RiskChallenge, RiskBlock:
		default:
			t.Fatalf("riskTier returned out-of-range action %d", a)
		}
		// Monotonicity: compare against score-1 with the same bands. The
		// integer values of the actions are their severity ranks (iota
		// order), so a lower score must not yield a higher-severity action.
		if score > -1<<62 { // guard against underflow on extreme inputs
			lower := riskTier(score-1, throttleAt, challengeAt, blockAt)
			if int(lower) > int(a) {
				t.Fatalf("severity decreased as score rose: riskTier(%d)=%v > riskTier(%d)=%v (bands t=%d c=%d b=%d)",
					score-1, lower, score, a, throttleAt, challengeAt, blockAt)
			}
		}
	})
}

// TestThrottleDelayWaits confirms the tarpit actually delays.
func TestThrottleDelayWaits(t *testing.T) {
	start := time.Now()
	waited := throttleDelay(context.Background(), 40)
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("throttleDelay(40ms) returned after only %v", elapsed)
	}
	if waited < 30*time.Millisecond {
		t.Fatalf("throttleDelay reported %v, expected ~40ms", waited)
	}
}

// TestThrottleDelayZeroIsNoop confirms a non-positive delay returns instantly.
func TestThrottleDelayZeroIsNoop(t *testing.T) {
	if d := throttleDelay(context.Background(), 0); d != 0 {
		t.Fatalf("throttleDelay(0) waited %v, want 0", d)
	}
	if d := throttleDelay(context.Background(), -100); d != 0 {
		t.Fatalf("throttleDelay(-100) waited %v, want 0", d)
	}
}

// TestThrottleDelayCancellation is the anti-amplifier property: a cancelled
// context (client disconnected) must abort the tarpit immediately so a slow
// delay cannot be turned into a connection-holding resource sink.
func TestThrottleDelayCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	start := time.Now()
	// Even with the max delay, this must return almost immediately.
	throttleDelay(ctx, throttleMaxDelayMs)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled context did not abort tarpit: waited %v", elapsed)
	}
}

// TestRiskActionForWiring confirms the proxy maps configured bands correctly
// and that the challenge band is gated on PoW being enabled.
func TestRiskActionForWiring(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:               true,
		PoWTriggerScore:          60,
		SessionThrottleThreshold: 30,
		SessionBlockThreshold:    90,
	}}
	checks := []struct {
		score int
		want  RiskAction
	}{
		{10, RiskAllow},
		{30, RiskThrottle},
		{60, RiskChallenge},
		{90, RiskBlock},
	}
	for _, c := range checks {
		if got := wp.riskActionFor(c.score); got != c.want {
			t.Errorf("riskActionFor(%d) = %v, want %v", c.score, got, c.want)
		}
	}

	// With PoW disabled the challenge band must vanish: a score that would
	// have challenged now falls through to the next lower active band.
	wp.cfg.PoWEnabled = false
	if got := wp.riskActionFor(60); got != RiskThrottle {
		t.Errorf("PoW off: riskActionFor(60) = %v, want throttle (challenge band inactive)", got)
	}
	if got := wp.riskActionFor(95); got != RiskBlock {
		t.Errorf("PoW off: riskActionFor(95) = %v, want block", got)
	}
}

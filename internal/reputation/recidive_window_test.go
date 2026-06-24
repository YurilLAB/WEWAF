package reputation

import (
	"math/bits"
	"testing"
	"time"
)

// TestRecidiveWindowResetsStaleConsensus is the regression for REP-S3-001: the
// subsystem bitmask used to only ever grow, so flags set far apart in time
// accumulated into a permanent recidive-ban consensus that re-banned a
// now-quiet/shared IP on a single later block. With RecidiveWindow, a quiet gap
// between flags resets the stale consensus — recidive must require CONCURRENT
// multi-subsystem hostility.
func TestRecidiveWindowResetsStaleConsensus(t *testing.T) {
	e := testEngine(t, Config{
		Enabled:           true,
		Window:            time.Hour,
		Threshold:         100, // high so the windowed trigger can't fire here
		BaseDuration:      600 * time.Second,
		Factor:            2.0,
		MaxDuration:       30 * 24 * time.Hour,
		Recidive:          true,
		RecidiveThreshold: 3,
		RecidiveBan:       7 * 24 * time.Hour,
		RecidiveWindow:    2 * time.Millisecond, // a gap between flags is "stale"
	})
	ip := "203.0.113.77"

	// Three DISTINCT subsystems, each separated by a gap LONGER than the window:
	// every flag resets the prior consensus, so it never reaches the threshold.
	if d := e.RecordBlock(ip, "engine", "xss"); d.Ban {
		t.Fatal("1 subsystem should not ban")
	}
	time.Sleep(6 * time.Millisecond)
	if d := e.RecordBlock(ip, "ddos", "flood"); d.Ban {
		t.Fatal("stale flag should have reset; 2nd subsystem alone must not ban")
	}
	time.Sleep(6 * time.Millisecond)
	d := e.RecordBlock(ip, "bruteforce", "login")
	if d.Ban || d.Recidive {
		t.Fatalf("flags spread across quiet gaps must NOT reach recidive consensus, got %+v", d)
	}
	// Only the most recent subsystem bit should remain after the resets.
	if n := bits.OnesCount16(e.Consult(ip).Subsystems); n != 1 {
		t.Fatalf("expected 1 subsystem bit after window resets, got %d", n)
	}
}

// TestRecidiveDefaultWindowStillConsenses guards the common case: with the
// default window (tied to OffenseWindow, 24h) three distinct subsystems fired
// in quick succession still reach consensus — the fix must not weaken genuine
// concurrent multi-subsystem detection.
func TestRecidiveDefaultWindowStillConsenses(t *testing.T) {
	e := testEngine(t, Config{
		Enabled:           true,
		Threshold:         100,
		Recidive:          true,
		RecidiveThreshold: 3,
		RecidiveBan:       time.Hour,
		// RecidiveWindow unset -> defaults to OffenseWindow (24h).
	})
	ip := "203.0.113.78"
	e.RecordBlock(ip, "engine", "xss")
	e.RecordBlock(ip, "ddos", "flood")
	d := e.RecordBlock(ip, "session", "risk")
	if !d.Ban || !d.Recidive {
		t.Fatalf("3 rapid distinct subsystems should still consensus-ban, got %+v", d)
	}
}

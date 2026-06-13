package ddos

import "testing"

// TestVolumetricStreakCountsSecondsNotRequests is the regression guard for the
// per-request streak bug. spikeStreak must advance at most once per elapsed
// second, so a burst of requests inside a single hot second cannot trip
// under_attack on its own — the design requires SpikeWindowsRequired
// consecutive spiking SECONDS. Before the fix the streak advanced on every
// request, so a handful of requests in one second flipped under_attack
// instantly (a global 503 load-shed on a benign micro-burst).
func TestVolumetricStreakCountsSecondsNotRequests(t *testing.T) {
	d := New(Config{
		VolumetricBaseline:   1,
		VolumetricSpike:      2,
		MinAbsoluteRPS:       1,
		SpikeWindowsRequired: 3,
		WarmupSeconds:        0,
		CoolDownSeconds:      60,
	})
	// Fire a large sub-second burst from a single source. The volumetric
	// average easily clears the (deliberately low) spike threshold, but
	// because every request lands in the same wall-clock second the streak
	// must not reach SpikeWindowsRequired.
	for i := 0; i < 500; i++ {
		d.RecordRequest("203.0.113.9", "/")
	}
	if d.IsUnderAttack() {
		t.Fatal("a sub-second burst must not trip volumetric under_attack; the streak must count seconds, not requests")
	}
}

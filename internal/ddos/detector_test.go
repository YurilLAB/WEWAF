package ddos

import (
	"strconv"
	"testing"
	"time"
)

// TestBotnetDetectionFiresAtThreshold confirms the detector flips
// VerdictBotnet once BotnetUniqueIPThreshold distinct fresh IPs hit a
// sensitive-looking path within the window.
func TestBotnetDetectionFiresAtThreshold(t *testing.T) {
	d := New(Config{BotnetUniqueIPThreshold: 10, BotnetMaxPaths: 16})
	path := "/login"
	// 9 distinct IPs — below threshold.
	for i := 0; i < 9; i++ {
		if v := d.checkBotnet("10.0.0."+strconv.Itoa(i), path); v != VerdictOK {
			t.Fatalf("unexpected verdict %v at IP %d", v, i)
		}
	}
	// 10th IP — must trip.
	if v := d.checkBotnet("10.0.0.10", path); v != VerdictBotnet {
		t.Fatalf("expected VerdictBotnet at threshold; got %v", v)
	}
}

// TestBotnetFreshCountIgnoresStale is the regression test for the
// cycle-ago optimisation: we prune stale entries at a threshold-sized
// cap rather than BotnetUniqueIPThreshold*2, so len(ips) ≈ fresh count.
// This test confirms that stale entries are actively pruned and don't
// accumulate past the threshold.
func TestBotnetFreshCountIgnoresStale(t *testing.T) {
	d := New(Config{BotnetUniqueIPThreshold: 20, BotnetMaxPaths: 16})
	path := "/api/login"
	// Seed the path with 30 IPs with "stale" timestamps — 120s ago.
	d.botMu.Lock()
	ips := make(map[string]int64, 30)
	past := time.Now().Unix() - 120
	for i := 0; i < 30; i++ {
		ips["stale"+strconv.Itoa(i)] = past
	}
	d.botPaths[path] = ips
	d.botMu.Unlock()

	// Now run a fresh IP — the prune branch should activate and trim
	// down to ≈ threshold.
	_ = d.checkBotnet("203.0.113.1", path)
	d.botMu.Lock()
	got := len(d.botPaths[path])
	d.botMu.Unlock()
	// Stale IPs timestamped 120s ago must all be gone now. The map
	// should contain only fresh entries (≤ the one we just added plus
	// any that were already fresh — there were none).
	if got > 5 {
		t.Fatalf("stale entries not pruned: len=%d", got)
	}
}

// TestBotnetToleratesEmptyIP — empty IP string must never trigger a
// false positive (internal requests, monitoring probes).
func TestBotnetToleratesEmptyIP(t *testing.T) {
	d := New(Config{BotnetUniqueIPThreshold: 5})
	if v := d.checkBotnet("", "/login"); v != VerdictOK {
		t.Fatalf("empty IP triggered %v", v)
	}
}

// TestBotnetStaleStillCountsIfFresh — when a previously-seen IP shows
// up again after the window, its timestamp updates and it stays in the
// map. The verdict must still fire at the threshold.
func TestBotnetStaleStillCountsIfFresh(t *testing.T) {
	d := New(Config{BotnetUniqueIPThreshold: 5, BotnetMaxPaths: 16})
	path := "/admin"
	for i := 0; i < 4; i++ {
		d.checkBotnet("10.0.0."+strconv.Itoa(i), path)
	}
	// Same request repeated: should not double-count.
	for i := 0; i < 10; i++ {
		d.checkBotnet("10.0.0.3", path)
	}
	if v := d.checkBotnet("10.0.0.99", path); v != VerdictBotnet {
		t.Fatalf("expected trip at 5th unique IP; got %v", v)
	}
}

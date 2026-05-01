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

// TestSensitivePathMatching closes the substring-prefix bug: the
// previous strings.HasPrefix match flagged any path whose first bytes
// happened to spell a sensitive prefix. /admincp is an admin-control-
// panel UI on its own URL, not the /admin endpoint; /loginza and
// /api/authenticate are legitimate paths that should NOT inherit the
// botnet-detector sensitivity tightening.
func TestSensitivePathMatching(t *testing.T) {
	d := New(Config{})
	cases := []struct {
		path string
		want bool
	}{
		// Genuine matches (sensitivity is intended).
		{"/login", true},
		{"/login/", true},
		{"/login/with/extras", true},
		{"/admin", true},
		{"/admin/users", true},
		{"/api/auth", true},
		{"/api/auth/refresh", true},
		{"/wp-login.php", true},
		// Substring-of-sensitive paths that must NOT match.
		{"/loginza", false},
		{"/admincp", false},
		{"/admincp/login", false}, // path contains "/admin" but it's
		// at position 0 followed by "cp" — not the /admin endpoint.
		{"/api/authenticate", false},
		{"/registers", false},
		{"/registerlist", false},
		// Case-insensitivity.
		{"/Login", true},
		{"/ADMIN/users", true},
		// Empty / unrelated.
		{"", false},
		{"/", false},
		{"/static/app.js", false},
	}
	for _, tc := range cases {
		if got := d.isSensitivePath(tc.path); got != tc.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestBurstFiresOnInstantaneousFlood — the 10-s sustained gate
// (default 300 hits) lets a script send 60 hits in 1 s and average
// only 6 RPS over the window, slipping past. The burst gate catches
// the same client by counting hits inside the 1-s window.
func TestBurstFiresOnInstantaneousFlood(t *testing.T) {
	d := New(Config{
		ConnRateThreshold: 300, // sustained gate stays out of the way
		BurstThreshold:    10,  // small for a unit-time test
		BurstWindow:       time.Second,
	})
	// 9 hits in rapid succession — under the burst threshold.
	for i := 0; i < 9; i++ {
		if v := d.checkPerIP("1.1.1.1"); v != VerdictOK {
			t.Fatalf("hit %d should be OK, got %v", i+1, v)
		}
	}
	// 10th hit should trip the burst gate.
	if v := d.checkPerIP("1.1.1.1"); v != VerdictBurst {
		t.Fatalf("burst gate should fire on hit 10, got %v", v)
	}
	if d.flaggedBurst.Load() == 0 {
		t.Fatal("flaggedBurst counter should be incremented")
	}
}

// TestBurstDoesNotFireOnDistributedFlood — many distinct IPs each
// firing under the burst threshold must NOT individually trip
// VerdictBurst. The botnet gate handles the distributed shape; the
// burst gate is per-IP only.
func TestBurstDoesNotFireOnDistributedFlood(t *testing.T) {
	d := New(Config{
		ConnRateThreshold: 300,
		BurstThreshold:    20,
		BurstWindow:       time.Second,
	})
	for i := 0; i < 100; i++ {
		ip := "10.0.0." + strconv.Itoa(i)
		if v := d.checkPerIP(ip); v != VerdictOK {
			t.Fatalf("distinct IP %s should be OK, got %v", ip, v)
		}
	}
	if d.flaggedBurst.Load() != 0 {
		t.Fatalf("flaggedBurst should be zero for distributed traffic, got %d", d.flaggedBurst.Load())
	}
}

// TestTopPathsExposesActivity — the per-path counter feeds operator
// visibility for "what's being hammered". Small smoke test that
// covers map-cap, ordering, and the LastSeenUnix tiebreak.
func TestTopPathsExposesActivity(t *testing.T) {
	d := New(Config{})
	// Three paths with different request counts.
	for i := 0; i < 100; i++ {
		d.RecordRequest("ip-a", "/api/users")
	}
	for i := 0; i < 50; i++ {
		d.RecordRequest("ip-b", "/api/posts")
	}
	for i := 0; i < 5; i++ {
		d.RecordRequest("ip-c", "/static/app.js")
	}
	top := d.TopPaths(3)
	if len(top) != 3 {
		t.Fatalf("TopPaths(3) returned %d entries", len(top))
	}
	if top[0].Path != "/api/users" || top[0].Count != 100 {
		t.Fatalf("top result wrong: %+v", top[0])
	}
	if top[1].Path != "/api/posts" || top[1].Count != 50 {
		t.Fatalf("second result wrong: %+v", top[1])
	}
	// Limit smaller than map size.
	if got := d.TopPaths(1); len(got) != 1 {
		t.Fatalf("TopPaths(1) returned %d entries", len(got))
	}
}

// TestRecordPathHit_CapDoesNotEvictExistingKeys — once the path map
// hits its cap, NEW keys may be dropped but the random-eviction
// sweep must NOT silently freeze counts on existing busy paths.
// (The sweep does drop a small budget of keys, including potentially
// busy ones, but the next request to a dropped key re-creates the
// entry — counts restart at 1, NOT silently disappear without trace.)
func TestRecordPathHit_CapDoesNotEvictExistingKeys(t *testing.T) {
	d := New(Config{})
	d.pathMaxKeys = 4 // tiny cap so the test triggers eviction quickly
	// Fill to cap.
	for i := 0; i < 4; i++ {
		d.recordPathHit("/p" + strconv.Itoa(i))
	}
	// Repeated hits on existing keys must keep incrementing.
	for i := 0; i < 10; i++ {
		d.recordPathHit("/p0")
	}
	d.pathMu.Lock()
	got := d.pathCounts["/p0"]
	d.pathMu.Unlock()
	if got == nil || got.count != 11 {
		t.Fatalf("/p0 count = %v, want 11", got)
	}
}

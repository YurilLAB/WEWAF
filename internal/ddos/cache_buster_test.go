package ddos

import (
	"strconv"
	"testing"
)

// TestCacheBusterFiresAtThreshold proves the detector flags an IP that
// rotates querystrings on a single path past the threshold within the
// window. Each request uses a distinct querystring, simulating a real
// CDN-cache-exhaustion attack pattern.
func TestCacheBusterFiresAtThreshold(t *testing.T) {
	d := New(Config{}) // use defaults
	// Stay just under the threshold first.
	for i := 0; i < cbDistinctThreshold; i++ {
		if v := d.RecordCacheBuster("203.0.113.5", "/api/items", "cb="+strconv.Itoa(i)); v != VerdictOK {
			t.Fatalf("flagged at %d/%d, expected OK below threshold", i, cbDistinctThreshold)
		}
	}
	// One more = trip.
	if v := d.RecordCacheBuster("203.0.113.5", "/api/items", "cb=trip"); v != VerdictCacheBuster {
		t.Fatalf("expected VerdictCacheBuster at threshold+1; got %v", v)
	}
}

// TestCacheBusterIgnoresEmptyQuery — requests without a querystring
// must not be tracked, otherwise normal cached traffic gets flagged.
func TestCacheBusterIgnoresEmptyQuery(t *testing.T) {
	d := New(Config{})
	for i := 0; i < cbDistinctThreshold*2; i++ {
		if v := d.RecordCacheBuster("203.0.113.5", "/static/app.js", ""); v != VerdictOK {
			t.Fatalf("empty-query request was flagged: %v", v)
		}
	}
}

// TestCacheBusterIgnoresRepeatQuery — a real user using the same
// `?page=2` repeatedly must NOT trip. Distinct-count is what we
// measure, not raw request volume.
func TestCacheBusterIgnoresRepeatQuery(t *testing.T) {
	d := New(Config{})
	for i := 0; i < cbDistinctThreshold*3; i++ {
		if v := d.RecordCacheBuster("203.0.113.5", "/search", "q=hello"); v != VerdictOK {
			t.Fatalf("repeat-query was flagged: %v", v)
		}
	}
}

// TestCacheBusterScopedPerIP — two distinct IPs each at half the
// threshold must not combine their counts.
func TestCacheBusterScopedPerIP(t *testing.T) {
	d := New(Config{})
	half := cbDistinctThreshold / 2
	for i := 0; i < half; i++ {
		if v := d.RecordCacheBuster("203.0.113.1", "/api/items", "cb="+strconv.Itoa(i)); v != VerdictOK {
			t.Fatalf("IP A: false positive at %d", i)
		}
		if v := d.RecordCacheBuster("203.0.113.2", "/api/items", "cb="+strconv.Itoa(i)); v != VerdictOK {
			t.Fatalf("IP B: false positive at %d", i)
		}
	}
}

// TestCacheBusterScopedPerPath — same IP rotating querystrings across
// MANY paths at low rates must not trip. Real users explore an SPA
// with diverse paths but a small handful of querystrings each.
func TestCacheBusterScopedPerPath(t *testing.T) {
	d := New(Config{})
	low := cbDistinctThreshold / 4
	for i := 0; i < low; i++ {
		paths := []string{"/a", "/b", "/c", "/d"}
		for _, p := range paths {
			if v := d.RecordCacheBuster("203.0.113.5", p, "cb="+strconv.Itoa(i)); v != VerdictOK {
				t.Fatalf("path %s at %d: false positive", p, i)
			}
		}
	}
}

// TestCacheBusterStatsCount — the flagged_cache_buster counter MUST
// move when the verdict fires, so the dashboard shows it.
func TestCacheBusterStatsCount(t *testing.T) {
	d := New(Config{})
	for i := 0; i <= cbDistinctThreshold; i++ {
		d.RecordCacheBuster("8.8.8.8", "/p", "cb="+strconv.Itoa(i))
	}
	stats := d.StatsSnapshot()
	flagged, _ := stats["flagged_cache_buster"].(uint64)
	if flagged == 0 {
		t.Fatal("flagged_cache_buster did not increment")
	}
}

package telemetry

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestAddTrafficPoint_PerBucketBytesPopulated documents the bug the
// new TrafficPoint shape closes: bandwidth is computed inside
// AddTrafficPoint as a delta since the last sample, but the previous
// in-memory shape stored only Requests + Blocked, so the dashboard's
// per-bucket bandwidth view had nothing to render. With BytesIn /
// BytesOut on each point the live /api/traffic endpoint matches the
// persisted history.TrafficPoint shape and the chart can plot bytes
// alongside requests without a second call.
func TestAddTrafficPoint_PerBucketBytesPopulated(t *testing.T) {
	m := NewMetrics()
	// First sample anchors the bandwidth-rate clock; bytes deltas on
	// this point are zero because there's no prior sample.
	m.RecordRequest("1.2.3.4", 1024)
	m.RecordPassDetailed("GET", "/", 4096, 200)
	m.AddTrafficPoint(1, 0)
	if got := len(m.GetTrafficHistory()); got != 1 {
		t.Fatalf("want 1 point, got %d", got)
	}
	first := m.GetTrafficHistory()[0]
	if first.BytesIn != 0 || first.BytesOut != 0 {
		t.Fatalf("first point bytes should be zero (no prior sample): %+v", first)
	}

	// Second sample — bytes should equal the deltas accumulated since
	// the first AddTrafficPoint call. We sleep long enough for the
	// clock-difference math to be non-zero but not long enough to
	// matter for the test runtime.
	time.Sleep(20 * time.Millisecond)
	m.RecordRequest("5.6.7.8", 2000)
	m.RecordPassDetailed("POST", "/api/x", 1500, 200)
	m.AddTrafficPoint(1, 0)

	hist := m.GetTrafficHistory()
	if len(hist) != 2 {
		t.Fatalf("want 2 points, got %d", len(hist))
	}
	second := hist[1]
	if second.BytesIn != 2000 {
		t.Fatalf("second point BytesIn = %d, want 2000", second.BytesIn)
	}
	if second.BytesOut != 1500 {
		t.Fatalf("second point BytesOut = %d, want 1500", second.BytesOut)
	}
}

// TestRecordPassDetailed_StatusCodePrecision — the previous
// RecordPass only stored 100-bucketed StatusCounts, so the dashboard
// couldn't tell 401s (auth fail) from 429s (rate-limited) from 451s
// (legal): all three rolled up into "400 bucket". The new
// StatusCodes map exposes exact codes side-by-side.
func TestRecordPassDetailed_StatusCodePrecision(t *testing.T) {
	m := NewMetrics()
	for _, code := range []int{200, 200, 401, 401, 401, 429, 503} {
		m.RecordPassDetailed("GET", "/x", 100, code)
	}
	snap := m.Snapshot()
	codes, ok := snap["status_codes"].(map[string]uint64)
	if !ok {
		t.Fatalf("status_codes missing or wrong type: %T", snap["status_codes"])
	}
	if codes["401"] != 3 {
		t.Errorf("401 count = %d, want 3", codes["401"])
	}
	if codes["429"] != 1 {
		t.Errorf("429 count = %d, want 1", codes["429"])
	}
	if codes["200"] != 2 {
		t.Errorf("200 count = %d, want 2", codes["200"])
	}
	// Bucketed view still works for backwards compat — 400-bucket
	// holds 401+429 and 500-bucket holds 503.
	bucketed, _ := snap["status_code_buckets"].(map[string]uint64)
	if bucketed["400"] != 4 {
		t.Errorf("400 bucket = %d, want 4", bucketed["400"])
	}
	if bucketed["500"] != 1 {
		t.Errorf("500 bucket = %d, want 1", bucketed["500"])
	}
}

// TestRecordPassDetailed_StatusCodesMapCapped — a misbehaving (or
// hostile) backend could return a stream of synthetic codes (501,
// 502, … 65535) and bloat the per-code map. The cap prevents
// unbounded growth while letting existing keys keep counting.
func TestRecordPassDetailed_StatusCodesMapCapped(t *testing.T) {
	m := NewMetrics()
	// Send statusCodeMaxKeys + extras codes. The first
	// statusCodeMaxKeys make it into the map; the rest are dropped.
	for i := 0; i < statusCodeMaxKeys+50; i++ {
		m.RecordPassDetailed("GET", "/x", 0, 1000+i)
	}
	if len(m.StatusCodes) > statusCodeMaxKeys {
		t.Fatalf("StatusCodes uncapped: %d entries", len(m.StatusCodes))
	}
	// An existing key must still increment past the cap — otherwise
	// the cap would silently freeze counters during sustained traffic.
	before := m.StatusCodes[1000]
	m.RecordPassDetailed("GET", "/x", 0, 1000)
	if m.StatusCodes[1000] != before+1 {
		t.Fatalf("existing-key increment broke under cap: before=%d after=%d", before, m.StatusCodes[1000])
	}
}

// TestRecordPassDetailed_MethodCounts confirms per-method counters
// populate, normalise case, and cap.
func TestRecordPassDetailed_MethodCounts(t *testing.T) {
	m := NewMetrics()
	for _, mt := range []string{"GET", "get", "Get", "POST", "delete"} {
		m.RecordPassDetailed(mt, "/x", 0, 200)
	}
	if got := m.MethodCounts["GET"]; got != 3 {
		t.Errorf("GET count = %d, want 3 (case-insensitive)", got)
	}
	if got := m.MethodCounts["POST"]; got != 1 {
		t.Errorf("POST count = %d, want 1", got)
	}
	if got := m.MethodCounts["DELETE"]; got != 1 {
		t.Errorf("DELETE count = %d, want 1", got)
	}
	// "get" / "Get" should not appear as separate keys.
	if _, ok := m.MethodCounts["get"]; ok {
		t.Errorf("lowercase method leaked into map")
	}
}

// TestPassedPathCounts_QueryStripped — ?id=42 and ?id=99 must
// collapse into one key so the top-paths view is meaningful (one
// entry per endpoint, not one per visitor).
func TestPassedPathCounts_QueryStripped(t *testing.T) {
	m := NewMetrics()
	m.RecordPassDetailed("GET", "/api/users?id=42", 0, 200)
	m.RecordPassDetailed("GET", "/api/users?id=99", 0, 200)
	m.RecordPassDetailed("GET", "/api/users?id=1#section", 0, 200)
	got := m.PassedPathCountsSnapshot()
	if got["GET /api/users"] != 3 {
		t.Fatalf("query-strip path count = %d, want 3 (got map=%v)",
			got["GET /api/users"], got)
	}
}

// TestRecentUniqueIPs_SlidingWindow verifies the rolling 24h count
// resets when buckets age out. The previous monotonic UniqueIPs map
// only ever grew, so a long-lived daemon's "unique IPs seen" number
// saturated at the cap and stopped reflecting current activity.
func TestRecentUniqueIPs_SlidingWindow(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 5; i++ {
		m.RecordRequest("ip-"+strconv.Itoa(i), 0)
	}
	if got := m.recentUniqueIPCountLocked(); got != 5 {
		t.Fatalf("recent unique IPs = %d, want 5", got)
	}
	// Force the entire window to age out by jumping the clock past
	// the bucket count. rotateUniqueIPsLocked detects the
	// large-step case and clears every bucket in one pass.
	m.mu.Lock()
	m.recentIPCurrentHour -= int64(recentIPBucketCount + 1)
	m.rotateUniqueIPsLocked(time.Now().UTC())
	m.mu.Unlock()
	if got := m.recentUniqueIPCountLocked(); got != 0 {
		t.Fatalf("after window roll, count should be 0; got %d", got)
	}
	// New traffic populates the fresh bucket.
	m.RecordRequest("9.9.9.9", 0)
	if got := m.recentUniqueIPCountLocked(); got != 1 {
		t.Fatalf("after fresh request, count = %d, want 1", got)
	}
}

// TestRecentUniqueIPs_BucketCapDoesNotEvictCounted — the cap stops
// new entries but must NOT remove already-counted ones; otherwise
// the cardinality would lie about the recent window.
func TestRecentUniqueIPs_BucketCapDoesNotEvictCounted(t *testing.T) {
	m := NewMetrics()
	// Add up to the cap.
	for i := 0; i < recentIPBucketCap; i++ {
		m.RecordRequest("ip-"+strconv.Itoa(i), 0)
	}
	got := m.recentUniqueIPCountLocked()
	if got != recentIPBucketCap {
		t.Fatalf("at cap: got %d, want %d", got, recentIPBucketCap)
	}
	// Add 100 more — they should be dropped.
	for i := 0; i < 100; i++ {
		m.RecordRequest("over-"+strconv.Itoa(i), 0)
	}
	if next := m.recentUniqueIPCountLocked(); next != got {
		t.Fatalf("post-cap: count changed (%d -> %d); cap eviction must not drop counted IPs", got, next)
	}
}

// TestSnapshot_ConcurrentReadWrite — the new fields are touched on
// every recorded request; race detector must stay clean when
// admin-API readers sweep Snapshot while RecordRequest /
// RecordPassDetailed run concurrently.
func TestSnapshot_ConcurrentReadWrite(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				m.RecordRequest("1.2.3.4", 100)
				m.RecordPassDetailed("GET", "/x", 100, 200)
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = m.Snapshot()
		}
	}()
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
}

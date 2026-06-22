package telemetry

import "testing"

func TestRecordWouldBlock(t *testing.T) {
	m := NewMetrics()
	m.RecordWouldBlock("203.0.113.5", "GET", "/x", "XSS-001", "xss", "would block", 50)
	m.RecordWouldBlock("203.0.113.6", "GET", "/y", "XSS-001", "xss", "would block", 50)
	m.RecordWouldBlock("203.0.113.7", "GET", "/z", "SQLI-010", "sqli", "would block", 70)

	snap := m.Snapshot()
	if got := snap["would_block"].(uint64); got != 3 {
		t.Errorf("would_block total = %d want 3", got)
	}
	// A would-block must NOT be counted as a real block.
	if got := snap["blocked_requests"].(uint64); got != 0 {
		t.Errorf("would-blocks must not increment blocked_requests; got %d", got)
	}
	byRule := snap["would_block_by_rule"].(map[string]uint64)
	if byRule["XSS-001"] != 2 || byRule["SQLI-010"] != 1 {
		t.Errorf("per-rule tallies wrong: %v", byRule)
	}
	// The snapshot map must be a copy — mutating it can't corrupt live state.
	byRule["XSS-001"] = 999
	if m.Snapshot()["would_block_by_rule"].(map[string]uint64)["XSS-001"] != 2 {
		t.Error("snapshot must return a defensive copy of would_block_by_rule")
	}
}

func TestRecordWouldBlockNilSafe(t *testing.T) {
	var m *Metrics
	// Must not panic on a nil receiver or empty rule ID.
	m.RecordWouldBlock("1.2.3.4", "GET", "/", "", "", "", 0)
	live := NewMetrics()
	live.RecordWouldBlock("1.2.3.4", "GET", "/", "", "", "", 0)
	if live.Snapshot()["would_block"].(uint64) != 1 {
		t.Error("empty rule ID should still count toward the total")
	}
}

// FuzzRecordWouldBlock hammers the recorder with arbitrary strings to prove it
// never panics and the total stays consistent with the number of calls.
func FuzzRecordWouldBlock(f *testing.F) {
	f.Add("1.2.3.4", "GET", "/p", "XSS-001", "xss", "msg", 50)
	f.Add("", "", "", "", "", "", 0)
	f.Fuzz(func(t *testing.T, ip, method, path, ruleID, category, message string, score int) {
		m := NewMetrics()
		m.RecordWouldBlock(ip, method, path, ruleID, category, message, score)
		m.RecordWouldBlock(ip, method, path, ruleID, category, message, score)
		if got := m.Snapshot()["would_block"].(uint64); got != 2 {
			t.Fatalf("would_block total = %d want 2", got)
		}
	})
}

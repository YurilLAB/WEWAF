package telemetry

import "testing"

// TestRecordSecurityEventNotCountedAsBlock is the regression for OBS-1: a
// non-blocking observe-only event (JA3 flag, simulated zero-trust policy,
// throttle, PoW challenge) must NOT inflate BlockedRequests / wewaf_blocked_total
// — the request was not blocked — while still appearing on the dashboard
// timeline and feeding the reputation block hook.
func TestRecordSecurityEventNotCountedAsBlock(t *testing.T) {
	m := NewMetrics()

	// A genuine block counts.
	m.RecordBlock("1.2.3.4", "GET", "/", "XSS-001", "blocked", 100)
	if got := m.CountersSnapshot()["blocked_requests"]; got != 1 {
		t.Fatalf("RecordBlock blocked_requests = %d, want 1", got)
	}

	// Observe-only events must NOT move the block total.
	m.RecordSecurityEvent("5.6.7.8", "GET", "/login", "POW-ISSUED", "pow", "challenge issued", 0)
	m.RecordSecurityEvent("5.6.7.8", "GET", "/x", "ZERO-TRUST-SIM:p1", "zero_trust_simulate", "would deny", 0)
	if got := m.CountersSnapshot()["blocked_requests"]; got != 1 {
		t.Fatalf("observe-only events inflated blocked_requests: got %d, want 1", got)
	}

	// ...but they DO land on the dashboard timeline.
	recent := m.RecentBlocksSnapshot(0)
	if len(recent) != 3 {
		t.Fatalf("timeline rows = %d, want 3 (1 block + 2 events)", len(recent))
	}
	var sawPow bool
	for _, r := range recent {
		if r.RuleID == "POW-ISSUED" {
			sawPow = true
		}
	}
	if !sawPow {
		t.Fatalf("observe-only POW-ISSUED missing from the timeline")
	}
}

// TestRecordSecurityEventFiresHook verifies the reputation block hook still sees
// observe-only signals (so reputation scoring is unchanged) even though they
// are not counted as blocks.
func TestRecordSecurityEventFiresHook(t *testing.T) {
	m := NewMetrics()
	var hookCalls int
	var lastRule string
	m.SetBlockHook(func(ip, method, path, ruleID, category, message string, score int) {
		hookCalls++
		lastRule = ruleID
	})
	m.RecordSecurityEvent("9.9.9.9", "GET", "/", "JA3-FLAG", "ja3", "fingerprint match", 0)
	if hookCalls != 1 {
		t.Fatalf("block hook calls = %d, want 1", hookCalls)
	}
	if lastRule != "JA3-FLAG" {
		t.Fatalf("hook ruleID = %q, want JA3-FLAG", lastRule)
	}
}

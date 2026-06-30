package ja3

import (
	"strconv"
	"testing"
)

// TestMergeBadCapped pins the bad-fingerprint set bound: a compromised/hijacked
// JA3 feed cannot grow the hard-block set without limit. Past maxBadJA3, new
// feed hashes are dropped (the FP-safe direction — never expand the set of
// fingerprints that can 403).
func TestMergeBadCapped(t *testing.T) {
	d := NewDetector()
	base := len(d.bad)

	// Try to merge well past the cap.
	entries := make(map[string]string, maxBadJA3+5000)
	for i := 0; i < maxBadJA3+5000; i++ {
		entries["feedhash-"+strconv.Itoa(i)] = "poison"
	}
	added := d.MergeBad(entries)

	if len(d.bad) > maxBadJA3 {
		t.Fatalf("bad set grew past cap: len=%d max=%d", len(d.bad), maxBadJA3)
	}
	// At least some entries were dropped because we offered more than the cap.
	if base+added > maxBadJA3 {
		t.Fatalf("added beyond cap: base=%d added=%d max=%d", base, added, maxBadJA3)
	}
	if added == 0 {
		t.Fatal("expected some entries to merge below the cap")
	}
}

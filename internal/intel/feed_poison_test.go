package intel

import "testing"

// TestFeedRejectsBanEverything is the regression for the feed-poisoning
// ban-everything class: a compromised/buggy threat feed must not be able to
// smuggle an all-addresses or over-broad range past the dangerous-range guard,
// in particular via the IPv4-mapped-IPv6 disguise (::ffff:0:0/96 = 0.0.0.0/0)
// or an over-broad prefix (0.0.0.0/1).
func TestFeedRejectsBanEverything(t *testing.T) {
	reject := []string{
		"::ffff:0:0/96",     // IPv4-mapped 0.0.0.0/0 disguise — the new gap
		"::ffff:0.0.0.0/96", // same, dotted form
		"0.0.0.0/1",         // half of IPv4 (over-broad)
		"128.0.0.0/2",       // quarter of IPv4
		"0.0.0.0/0",         // classic (already caught, regression guard)
		"::/0",              // IPv6 all
		"::/3",              // huge IPv6 chunk
		"10.0.0.0/8",        // RFC1918 (already caught)
	}
	for _, s := range reject {
		if _, ok := classifyIP(s); ok {
			t.Errorf("classifyIP(%q) accepted; want REJECTED (ban-everything / dangerous)", s)
		}
	}

	// Legitimate specific feed entries must still be accepted.
	accept := []string{
		"1.2.3.0/24",
		"185.220.101.5/32",
		"::ffff:1.2.3.4/128", // IPv4-mapped single host -> 1.2.3.4/32
		"2001:db8:dead::/48",
		"203.0.113.0/24",
	}
	for _, s := range accept {
		if _, ok := classifyIP(s); !ok {
			t.Errorf("classifyIP(%q) rejected; want accepted (legit feed entry)", s)
		}
	}
}

// TestFeedMappedSingleHostCanonicalised verifies an IPv4-mapped single host is
// stored in its true IPv4 form so it matches IPv4 clients in the ban set.
func TestFeedMappedSingleHostCanonicalised(t *testing.T) {
	e, ok := classifyIP("::ffff:1.2.3.4/128")
	if !ok {
		t.Fatal("IPv4-mapped single host rejected")
	}
	if e.Value != "1.2.3.4/32" {
		t.Errorf("mapped host stored as %q, want 1.2.3.4/32", e.Value)
	}
}

package intel

import "testing"

// TestClassifyIP_SafetyGate pins the feed safety policy: a parsed feed entry
// must reference a PUBLIC, globally-routable destination, and must never be a
// non-public, multicast, reserved-martian, or over-broad range — in either
// bare-IP or CIDR form. The fuzzer (FuzzParseLinePerIP) surfaced that a CIDR
// rooted in the reserved 0.0.0.0/8 block (e.g. 0.0.0.0/10, and worse 0.0.0.0/9
// which spans ~2B public addresses) slipped past the /8-threshold breadth guard
// and the exact-/0 dangerous-range list; these cases lock that closed without
// false-rejecting ordinary public feed entries.
func TestClassifyIP_SafetyGate(t *testing.T) {
	mustRefuse := []string{
		// Reserved "this network" (RFC 1122) — the fuzzer-found class.
		"0.0.0.0/10", "0.0.0.0/9", "0.0.0.0/8", "0.1.2.3", "0.255.255.255/32",
		// Universal / over-broad.
		"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/2", "::/3",
		// Loopback / link-local / unspecified.
		"127.0.0.1", "127.0.0.0/8", "::1", "169.254.0.1", "fe80::1", "0.0.0.0", "::",
		// RFC1918 private (bare and CIDR-smuggled).
		"10.0.0.1", "10.5.6.7/32", "192.168.1.0/24", "172.16.0.1", "fc00::1",
		// Multicast (link-local and global) + reserved Class-E + broadcast.
		"224.0.0.1", "225.0.0.1", "239.0.0.1/24", "ff02::1", "ff0e::1", "ff00::/8",
		"240.0.0.1", "255.255.255.255", "240.0.0.0/4",
		// IPv4-mapped IPv6 disguise of 0.0.0.0/0.
		"::ffff:0:0/96",
	}
	for _, s := range mustRefuse {
		if e, ok := classifyIP(s); ok {
			t.Errorf("classifyIP(%q) was ACCEPTED as %q — must be refused (non-public/over-broad)", s, e.Value)
		}
	}

	// No false-rejection: ordinary public attacker hosts/ranges that a real
	// reputation feed lists must still be accepted.
	mustAccept := map[string]string{
		"1.2.3.4":        "1.2.3.4/32",
		"8.8.8.8":        "8.8.8.8/32",
		"45.155.205.0/24": "45.155.205.0/24",
		"203.0.113.7":    "203.0.113.7/32",
		"2.56.0.0/16":    "2.56.0.0/16",
		"2606:4700::1":   "2606:4700::1/128",
		"2001:db8:abcd::/48": "2001:db8:abcd::/48",
	}
	for in, want := range mustAccept {
		e, ok := classifyIP(in)
		if !ok {
			t.Errorf("classifyIP(%q) was REFUSED — legitimate public feed entry, must be accepted", in)
			continue
		}
		if e.Value != want {
			t.Errorf("classifyIP(%q).Value = %q, want %q", in, e.Value, want)
		}
	}
}

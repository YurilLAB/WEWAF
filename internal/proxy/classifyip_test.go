package proxy

import (
	"net"
	"testing"
)

func TestClassifyIPBlocksInternalAndReserved(t *testing.T) {
	blocked := []string{
		// Cloud metadata (direct + IPv4-mapped + NAT64-embedded).
		"169.254.169.254", "100.100.100.200",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe",
		// Loopback / private / link-local (stdlib) — incl. NAT64-embedded.
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"::1", "fe80::1", "fc00::1", "::", "64:ff9b::7f00:1", "64:ff9b::a00:1",
		// Ranges Go's stdlib MISSES — the H6/H7 gaps.
		"100.64.0.1",        // CGNAT (RFC 6598)
		"198.18.0.1",        // benchmarking (RFC 2544)
		"240.0.0.1",         // reserved (class E)
		"192.0.0.1",         // IETF protocol assignments
		"255.255.255.255",   // limited broadcast
		"2001::1",           // Teredo
		"2002:c0a8:0101::1", // 6to4
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: unparseable %q", s)
		}
		if reason := classifyIP(ip); reason == "" {
			t.Errorf("classifyIP(%q) should be BLOCKED but was allowed", s)
		}
	}

	// Genuine public addresses must be allowed (no false positives).
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if reason := classifyIP(ip); reason != "" {
			t.Errorf("classifyIP(%q) should be ALLOWED but was blocked: %s", s, reason)
		}
	}
}

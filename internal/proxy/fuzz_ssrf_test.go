package proxy

import (
	"net"
	"testing"
)

// classifyIP is the load-bearing SSRF gate for outbound (egress) requests — it
// runs at request time AND at dial time (DNS-rebind-proof), so a gap is a
// server-side request forgery to internal services or cloud metadata. The
// destination IP is wholly attacker-influenced (a malicious hostname can resolve
// to anything). This fuzzer asserts no-panic and, crucially, a one-way safety
// invariant: classifyIP must block EVERY address Go's own stdlib considers a
// non-public destination. classifyIP is allowed to be stricter (it also blocks
// metadata, CGNAT, TEST-NETs, NAT64-embedded internals, etc.) — never more
// lenient than the stdlib floor.
//
// Run:  go test ./internal/proxy -run x -fuzz FuzzClassifyIP -fuzztime 30s
// TestClassifyIP_MetadataAndNAT64 regression-guards the egress SSRF gaps the
// 2026 red-team confirmed: Azure WireServer and NAT64-via-local-use-prefix.
func TestClassifyIP_MetadataAndNAT64(t *testing.T) {
	mustBlock := []string{
		"168.63.129.16",          // Azure WireServer (was allowed — public-looking)
		"64:ff9b:1::a9fe:a9fe",   // NAT64 local-use prefix embedding 169.254.169.254
		"64:ff9b::a9fe:a9fe",     // NAT64 well-known prefix (control)
		"169.254.169.254",        // metadata (control)
		"::ffff:169.254.169.254", // IPv4-mapped metadata (control)
	}
	for _, s := range mustBlock {
		if classifyIP(net.ParseIP(s)) == "" {
			t.Errorf("SSRF gap: classifyIP(%s) allowed it (want blocked)", s)
		}
	}
	// Public addresses must still be allowed (no over-block).
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if r := classifyIP(net.ParseIP(s)); r != "" {
			t.Errorf("over-block: classifyIP(%s) = %q (want allowed)", s, r)
		}
	}
}

func FuzzClassifyIP(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"100.64.0.1", "8.8.8.8", "::1", "fe80::1", "::ffff:127.0.0.1",
		"64:ff9b::a9fe:a9fe", "fd00:ec2::254", "0.0.0.0", "224.0.0.1", "255.255.255.255",
	} {
		if ip := net.ParseIP(s); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				f.Add([]byte(v4))
			} else {
				f.Add([]byte(ip.To16()))
			}
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Only 4- and 16-byte slices are valid IPs; others aren't a meaningful
		// destination and net.IP methods are undefined on them.
		if len(raw) != 4 && len(raw) != 16 {
			return
		}
		ip := net.IP(raw)

		reason := classifyIP(ip) // contract 1: never panics

		// Contract 2: classifyIP must be at least as strict as the stdlib for the
		// non-public categories. If the stdlib flags it, classifyIP must block it.
		stdlibBad := ip.IsLoopback() || ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast()
		if stdlibBad && reason == "" {
			t.Fatalf("SSRF gap: classifyIP allowed a stdlib-flagged non-public IP %v (raw %v)", ip, raw)
		}
	})
}

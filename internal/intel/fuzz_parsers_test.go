package intel

import (
	"net"
	"testing"
)

// FuzzClassifyIP fuzzes the feed-entry classifier (which ingests untrusted
// third-party feed lines) for panics and to confirm the dangerous-range /
// over-broad / IPv4-mapped guards never accept an all-addresses or
// private/loopback range.
func FuzzClassifyIP(f *testing.F) {
	seeds := []string{
		"1.2.3.0/24", "0.0.0.0/0", "::ffff:0:0/96", "0.0.0.0/1", "::/0", "::/3",
		"10.0.0.0/8", "::ffff:1.2.3.4/128", "2001:db8::/48", "127.0.0.1",
		"185.220.101.5/32", "garbage", "", "/", "999.999.999.999/33", "::ffff:0.0.0.0/96",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, ok := classifyIP(s) // must never panic
		if !ok {
			return
		}
		// An accepted entry must never be a dangerous or over-broad range.
		if e.Kind == KindIPv4 || e.Kind == KindIPv6 {
			if _, ipnet, err := net.ParseCIDR(e.Value); err == nil {
				if isDangerousRange(ipnet) || feedCIDRTooBroad(ipnet) {
					t.Fatalf("classifyIP(%q) accepted a dangerous/over-broad range: %q", s, e.Value)
				}
			}
		}
	})
}

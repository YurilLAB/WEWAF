package reputation

import (
	"net"
	"testing"
	"time"

	"wewaf/internal/clientip"
)

// FuzzRepKey guards the prefix/injection invariant: repKey must never panic,
// must reject anything that is not a parseable IP, and whenever it accepts an
// input the key it returns must equal clientip.NormalizeIPKey and itself be a
// valid IP — so a reputation decision can never produce a key that diverges
// from the ban key (which would silently fail to match IsBanned) or smuggle
// non-IP garbage toward the firewall sink.
func FuzzRepKey(f *testing.F) {
	for _, s := range []string{
		"", "8.8.8.8", "1.1.1.1", "203.0.113.7", "::1", "fe80::1",
		"2606:4700:4700::1111", "::ffff:1.2.3.4", "10.0.0.1/24",
		"not-an-ip", "999.999.999.999", "; rm -rf /", "  8.8.8.8  ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		k, ok := repKey(in)
		if !ok {
			if k != "" {
				t.Fatalf("repKey(%q) returned key %q with ok=false", in, k)
			}
			return
		}
		if net.ParseIP(k) == nil {
			t.Fatalf("repKey(%q) accepted but key %q is not a valid IP", in, k)
		}
		if k != clientip.NormalizeIPKey(in) {
			t.Fatalf("repKey(%q)=%q diverges from NormalizeIPKey=%q", in, k, clientip.NormalizeIPKey(in))
		}
	})
}

// FuzzEscalatedDuration guards the escalation math against overflow and
// degenerate inputs: the result must always be non-negative, must never exceed
// an explicit max, and the function must never panic regardless of offense
// tier, base, factor (incl. NaN/Inf via the typed inputs), or jitter.
func FuzzEscalatedDuration(f *testing.F) {
	f.Add(1, int64(600_000_000_000), int64(604800_000_000_000), 2.0, int64(0))
	f.Add(50, int64(1), int64(0), 1.5, int64(1_000_000))
	f.Add(-5, int64(-1), int64(-1), 0.0, int64(-1))
	f.Fuzz(func(t *testing.T, offenses int, baseNs, maxNs int64, factor float64, jitterNs int64) {
		base := time.Duration(baseNs)
		max := time.Duration(maxNs)
		jitter := time.Duration(jitterNs)
		got := escalatedDuration(offenses, base, max, factor, jitter)
		if got < 0 {
			t.Fatalf("negative duration %s (offenses=%d base=%d max=%d factor=%g jitter=%d)", got, offenses, baseNs, maxNs, factor, jitterNs)
		}
		if max > 0 && got > max {
			t.Fatalf("duration %s exceeds max %s (offenses=%d factor=%g jitter=%d)", got, max, offenses, factor, jitterNs)
		}
	})
}

package clientip

import (
	"net/http/httptest"
	"testing"
)

// FuzzClientIP feeds arbitrary RemoteAddr + X-Forwarded-For / X-Real-Ip values
// through the trust-aware client-IP resolver. This is security-critical (a
// wrong answer means rate-limit / ban / geofence bypass) and parses fully
// attacker-controlled header bytes, so it must never panic and must always
// return a usable string. Run:
//   go test -run=^$ -fuzz=^FuzzClientIP$ -fuzztime=60s ./internal/clientip/
func FuzzClientIP(f *testing.F) {
	f.Add("1.2.3.4:5678", "10.0.0.1, 1.2.3.4", "")
	f.Add("not-an-addr", "[::1]:8080, , 2001:db8::1", "9.9.9.9")
	f.Add("", "", "")
	f.Add(" ", "", "")  // regression: whitespace RemoteAddr must not yield an empty client IP
	f.Add("[fe80::1%eth0]:80", "%%%, ::ffff:1.2.3.4", "garbage")
	f.Fuzz(func(t *testing.T, remote, xff, realIP string) {
		e, err := New(true, []string{"10.0.0.0/8", "::1/128"})
		if err != nil {
			t.Skip()
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-Ip", realIP)
		// None of these may panic on hostile input; ClientIP must never
		// return empty for a non-nil request.
		if ip := e.ClientIP(r); ip == "" && remote != "" {
			// An empty result for a non-empty RemoteAddr would mean a request
			// with no usable rate-limit / ban key. The resolver promises a
			// RemoteAddr fallback, so this should not happen.
			t.Fatalf("ClientIP returned empty for remote=%q xff=%q", remote, xff)
		}
		_ = e.IsTrustedPeer(r)
		_ = e.IsTLSRequest(r)
	})
}

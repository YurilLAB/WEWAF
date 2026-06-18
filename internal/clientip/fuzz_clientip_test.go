package clientip

import (
	"net/http"
	"testing"
)

// ClientIP runs on every request against attacker-controlled RemoteAddr and
// X-Forwarded-For / X-Real-IP headers. A parse panic there is a per-request
// DoS. Fuzz both trust modes with arbitrary values and assert no panic.
//
// Run:  go test ./internal/clientip -run x -fuzz FuzzClientIP -fuzztime 30s
func FuzzClientIP(f *testing.F) {
	trusting, _ := New(true, []string{"10.0.0.0/8", "192.168.0.0/16"})
	strict, _ := New(false, nil)

	f.Add("1.2.3.4:5678", "203.0.113.9, 10.0.0.1", "198.51.100.2")
	f.Add("[::1]:443", "::1, fe80::1%eth0", "")
	f.Add("garbage", ",,,, ,", "not-an-ip")
	f.Add("", "", "")
	f.Add("10.0.0.1:1", "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4", "[bad")

	f.Fuzz(func(t *testing.T, remote, xff, xrealip string) {
		r := &http.Request{Header: http.Header{}, RemoteAddr: remote}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xrealip != "" {
			r.Header.Set("X-Real-Ip", xrealip)
		}
		// Neither mode may panic on any input.
		_ = trusting.ClientIP(r)
		_ = strict.ClientIP(r)
		_ = trusting.IsTrustedPeer(r)
	})
}

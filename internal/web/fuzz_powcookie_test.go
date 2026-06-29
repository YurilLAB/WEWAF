package web

import (
	"testing"
	"time"
)

// VerifyPowCookie parses an attacker-supplied __wewaf_pow cookie value on the
// hot path. A panic is a per-request DoS; accepting a value the issuer never
// minted is an auth bypass of the PoW gate. This fuzzer asserts no-panic on any
// (secret, value), that an empty secret never validates anything, and that a
// value the verifier accepts carries a real (non-zero) issuance time.
//
// Run:  go test ./internal/web -run x -fuzz FuzzVerifyPowCookie -fuzztime 30s
func FuzzVerifyPowCookie(f *testing.F) {
	// A genuinely-signed cookie as a near-valid seed.
	good := signPowCookie("test-secret", "sess-1", "203.0.113.7", 1750000000)
	f.Add("test-secret", good)
	f.Add("test-secret", "")
	f.Add("", good)
	f.Add("test-secret", "a.b.c")
	f.Add("test-secret", "sess-1.1750000000.deadbeef")
	f.Add("test-secret", good+"x") // tampered tail

	f.Fuzz(func(t *testing.T, secret, value string) {
		at, ok := VerifyPowCookie(secret, value, time.Hour) // never panics

		// An empty secret must NEVER validate — there is no key to authenticate
		// against, so accepting anything would be a universal forgery.
		if secret == "" && ok {
			t.Fatalf("empty secret accepted a cookie: value=%q", value)
		}
		// A verified cookie must carry a real issuance timestamp the caller can
		// trust for the freshness window.
		if ok && at.IsZero() {
			t.Fatalf("VerifyPowCookie returned ok with a zero timestamp: value=%q", value)
		}
	})
}

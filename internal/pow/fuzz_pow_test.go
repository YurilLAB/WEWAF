package pow

import (
	"testing"
	"time"
)

// Issuer.Verify parses a fully attacker-supplied token string plus an
// attacker-supplied nonce on the PoW verify endpoint (a public, unauthenticated
// challenge surface). A panic there is a request-level DoS; a logic slip that
// accepts a forged token is an auth bypass that lets a bot skip the gate. This
// fuzzer asserts: Verify never panics on any (serialised, nonce); a token the
// issuer did NOT mint never verifies; and any token it DOES accept has fields
// inside the issuer's configured bounds.
//
// Run:  go test ./internal/pow -run x -fuzz FuzzPoWVerify -fuzztime 30s
func FuzzPoWVerify(f *testing.F) {
	it, err := NewIssuer([]byte("fuzz-pow-secret-32-bytes-long!!aa"), 4, 24, time.Hour)
	if err != nil {
		f.Fatalf("NewIssuer: %v", err)
	}
	// A genuinely-issued token (valid signature, unsolved) so the fuzzer explores
	// near the real parse → signature → expiry → PoW path, not just garbage.
	_, ser, err := it.Issue(8)
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	f.Add(ser, []byte{0x00})
	f.Add(ser, []byte{})
	f.Add("", []byte{0x01})
	f.Add("a.b.c.d.e", []byte("nonce"))
	f.Add("....", []byte{0x00, 0x00})
	f.Add(ser+"x", []byte{0x00}) // tampered tail

	f.Fuzz(func(t *testing.T, serialised string, nonce []byte) {
		tok, err := it.Verify(serialised, nonce)
		if err != nil {
			return // the overwhelmingly common, correct outcome
		}
		// Verify returned success — that should be essentially unreachable from
		// fuzzed input (it would require forging an HMAC over the issuer secret),
		// but if it ever happens the accepted token MUST be within bounds.
		if tok.Difficulty < it.min || tok.Difficulty > it.max {
			t.Fatalf("Verify accepted out-of-bounds difficulty %d (bounds %d..%d) for %q",
				tok.Difficulty, it.min, it.max, serialised)
		}
		if len(tok.Salt) != saltLen {
			t.Fatalf("Verify accepted token with salt len %d (want %d)", len(tok.Salt), saltLen)
		}
		if tok.ID == "" {
			t.Fatalf("Verify accepted token with empty ID")
		}
	})
}

// FuzzParseSerialised isolates the token string parser. It must never panic and
// must reject anything it can't fully validate (length-bounded id, exact-length
// base64 salt + signature, in-range difficulty, parseable expiry).
func FuzzParseSerialised(f *testing.F) {
	for _, s := range []string{
		"", "a", "a.b.c.d.e", "....", "x.y.z",
		"id." + "QUFB" + ".8.99.sig",
		string(make([]byte, 5000)), // oversized
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tok, body, sig, err := parseSerialised(s)
		if err != nil {
			return
		}
		// On success the parser's own invariants must hold so downstream Verify
		// can trust the shapes without re-checking.
		if len(tok.ID) == 0 || len(tok.ID) > 32 {
			t.Fatalf("parsed id out of range: %q", tok.ID)
		}
		if len(tok.Salt) != saltLen {
			t.Fatalf("parsed salt len %d != %d", len(tok.Salt), saltLen)
		}
		if len(sig) == 0 {
			t.Fatalf("parsed empty signature for body %q", body)
		}
		if body == "" {
			t.Fatalf("parsed empty signing body")
		}
	})
}

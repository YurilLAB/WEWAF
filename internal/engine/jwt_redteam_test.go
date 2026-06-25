package engine

import (
	"strings"
	"testing"
)

// TestJWTEmbeddedJwkDetectedNotBlocked: an embedded "jwk" header (token carries
// its own key — CVE-2018-0114) is now surfaced (JWT-005) but deliberately
// log-level, because RFC 9449 DPoP proof tokens legitimately embed a jwk.
func TestJWTEmbeddedJwkDetectedNotBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	tok := jwtSeg(`{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"a","y":"b"}}`) + "." + jwtSeg(`{"htu":"https://x"}`) + ".sig"
	if !jwtRuleMatched(eng, tok, "JWT-005") {
		t.Error("embedded jwk not detected (JWT-005)")
	}
	if jwtAuthBlocked(eng, tok) {
		t.Error("embedded jwk must be log-level (DPoP uses it), not blocked")
	}
}

// TestJWTDecoyFloodBlocked: burying a malicious token behind a flood of inert
// decoys to push it past the scan cap now trips a flood block (JWT-006) — no
// legitimate request carries this many JWTs.
func TestJWTDecoyFloodBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	decoy := jwtSeg(`{"alg":"HS256","typ":"JWT"}`) + "." + jwtSeg(`{"u":"x"}`) + ".s"
	var b strings.Builder
	for i := 0; i < 33; i++ { // > maxJWTs (32)
		b.WriteString(decoy)
		b.WriteString(",")
	}
	b.WriteString(jwtSeg(`{"alg":"none"}`) + "." + jwtSeg(`{"u":"admin"}`) + ".")
	if !jwtAuthBlocked(eng, b.String()) {
		t.Error("JWT decoy flood (>32 tokens) not blocked (JWT-006)")
	}
}

// TestJWTBuriedMaliciousWithinCapBlocked: a malicious alg:none token hidden
// among decoys but within the scan cap is still inspected and blocked.
func TestJWTBuriedMaliciousWithinCapBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	decoy := jwtSeg(`{"alg":"HS256"}`) + "." + jwtSeg(`{"u":"x"}`) + ".s"
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString(decoy)
		b.WriteString(" ")
	}
	b.WriteString(jwtSeg(`{"alg":"none"}`) + "." + jwtSeg(`{"u":"admin"}`) + ".")
	if !jwtAuthBlocked(eng, b.String()) {
		t.Error("malicious alg:none buried among decoys (within cap) not blocked")
	}
}

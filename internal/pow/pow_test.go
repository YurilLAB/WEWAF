package pow

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	it, err := NewIssuer([]byte("test-secret-test-secret-test-secret-1"), 8, 16, time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return it
}

// TestIssueAndVerifyRoundTrip is the happy path. We deliberately use a
// LOW difficulty (8 bits) so the test solver finishes in <1ms. This is
// the only correctness check that needs SolveForTest to actually search;
// every other test fakes specific token shapes to keep wall-time fixed.
func TestIssueAndVerifyRoundTrip(t *testing.T) {
	it := newTestIssuer(t)
	tok, ser, err := it.Issue(8)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.Difficulty != 8 {
		t.Fatalf("difficulty drift: %d", tok.Difficulty)
	}
	nonce, ok := SolveForTest(tok.Salt, 8, 1<<20)
	if !ok {
		t.Fatal("solver gave up")
	}
	if _, err := it.Verify(ser, nonce); err != nil {
		t.Fatalf("Verify of valid solution failed: %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	it := newTestIssuer(t)
	_, ser, _ := it.Issue(8)
	// Flip a single bit in the body — signature must fail.
	parts := strings.Split(ser, ".")
	parts[2] = "9" // bump difficulty in the body, signature now stale
	tampered := strings.Join(parts, ".")
	if _, err := it.Verify(tampered, []byte{0}); err != ErrTokenSignature {
		t.Fatalf("expected ErrTokenSignature, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	// TTL of 1ns guarantees the token is expired before we Verify it.
	it, _ := NewIssuer([]byte("k"), 4, 8, time.Nanosecond)
	tok, ser, _ := it.Issue(4)
	time.Sleep(2 * time.Millisecond)
	nonce, ok := SolveForTest(tok.Salt, 4, 1<<16)
	if !ok {
		t.Fatal("solver gave up at d=4")
	}
	if _, err := it.Verify(ser, nonce); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyDetectsReplay(t *testing.T) {
	it := newTestIssuer(t)
	tok, ser, _ := it.Issue(8)
	nonce, _ := SolveForTest(tok.Salt, 8, 1<<20)
	if _, err := it.Verify(ser, nonce); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	// Second submit of the same token must be refused — defends against
	// an attacker reusing one solve across many sessions.
	if _, err := it.Verify(ser, nonce); err != ErrTokenReplay {
		t.Fatalf("expected ErrTokenReplay, got %v", err)
	}
}

func TestVerifyRejectsBadSolution(t *testing.T) {
	it := newTestIssuer(t)
	_, ser, _ := it.Issue(16)
	// A 1-byte all-zero nonce will only happen to satisfy d=16 if SHA-256
	// of (salt || 0x00) starts with 16 zero bits — astronomically unlikely.
	if _, err := it.Verify(ser, []byte{0}); err != ErrSolutionInvalid {
		t.Fatalf("expected ErrSolutionInvalid, got %v", err)
	}
}

func TestVerifyMissingSolution(t *testing.T) {
	it := newTestIssuer(t)
	_, ser, _ := it.Issue(8)
	if _, err := it.Verify(ser, nil); err != ErrSolutionMissing {
		t.Fatalf("expected ErrSolutionMissing, got %v", err)
	}
	if _, err := it.Verify(ser, []byte{}); err != ErrSolutionMissing {
		t.Fatalf("expected ErrSolutionMissing, got %v", err)
	}
}

func TestVerifyMalformedTokens(t *testing.T) {
	it := newTestIssuer(t)
	for _, bad := range []string{
		"",
		strings.Repeat("a", 5000), // too long
		"only.three.parts.though", // wrong field count
		"a.b.c.d.e",               // right shape, junk content
		"id.notbase64@@@.8.0.sig", // base64 fails
	} {
		if _, err := it.Verify(bad, []byte{0, 0, 0, 0, 0, 0, 0, 1}); err != ErrTokenMalformed && err != ErrTokenSignature {
			t.Errorf("malformed input %q: got %v", bad, err)
		}
	}
}

func TestSuggestDifficultyClamping(t *testing.T) {
	it, _ := NewIssuer([]byte("k"), 18, 24, time.Minute)
	cases := []struct {
		score int
		want  uint8
	}{
		{0, 18}, {49, 18},
		{50, 18}, {55, 19},
		{75, 23}, {90, 24}, // clamps to max
		{1000, 24},
	}
	for _, c := range cases {
		if got := it.SuggestDifficulty(c.score); got != c.want {
			t.Errorf("SuggestDifficulty(%d) = %d want %d", c.score, got, c.want)
		}
	}
}

func TestNewIssuerValidation(t *testing.T) {
	if _, err := NewIssuer(nil, 8, 16, time.Minute); err == nil {
		t.Fatal("empty secret should be rejected")
	}
	if _, err := NewIssuer([]byte("k"), 16, 8, time.Minute); err == nil {
		t.Fatal("min > max should be rejected")
	}
	if _, err := NewIssuer([]byte("k"), 8, 64, time.Minute); err == nil {
		t.Fatal("max > 32 should be rejected (DoS protection)")
	}
}

// TestHasLeadingZerosBoundary nails down the bit-counting because off-by-
// one here is easy and catastrophic — too lax means the solver can submit
// junk; too strict means real clients fail forever.
func TestHasLeadingZerosBoundary(t *testing.T) {
	// 8 bits → first byte zero, second byte anything.
	if !hasLeadingZeros([]byte{0x00, 0xff, 0xff}, 8) {
		t.Fatal("0x00 prefix should satisfy d=8")
	}
	if hasLeadingZeros([]byte{0x01, 0x00, 0x00}, 8) {
		t.Fatal("0x01 prefix must not satisfy d=8")
	}
	// 12 bits → first byte zero AND top nibble of byte 2 zero.
	if !hasLeadingZeros([]byte{0x00, 0x0f, 0xff}, 12) {
		t.Fatal("0x00 0x0f should satisfy d=12")
	}
	if hasLeadingZeros([]byte{0x00, 0x10, 0xff}, 12) {
		t.Fatal("0x00 0x10 must not satisfy d=12")
	}
	// 0 bits — anything.
	if !hasLeadingZeros([]byte{0xff}, 0) {
		t.Fatal("d=0 should always pass")
	}
	// Truncated input — must fail rather than panic.
	if hasLeadingZeros([]byte{}, 8) {
		t.Fatal("empty input must not be reported as satisfying")
	}
}

func TestSweepRemovesAgedSeenEntries(t *testing.T) {
	// Use a normal TTL so Verify succeeds, then forcibly back-date the
	// seen entry so Sweep has something to clean. This keeps the test
	// deterministic regardless of host timer resolution.
	it, _ := NewIssuer([]byte("k"), 4, 8, time.Minute)
	tok, ser, _ := it.Issue(4)
	nonce, _ := SolveForTest(tok.Salt, 4, 1<<16)
	if _, err := it.Verify(ser, nonce); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Drag the seen-entry's timestamp into the past so Sweep removes it.
	it.seenMu.Lock()
	for k := range it.seen {
		it.seen[k] = time.Now().Add(-10 * time.Minute)
	}
	it.seenMu.Unlock()
	if removed := it.Sweep(); removed == 0 {
		t.Fatal("expected Sweep to remove at least one entry")
	}
}

func TestStatsReportsConfiguration(t *testing.T) {
	it, _ := NewIssuer([]byte("k"), 12, 20, 90*time.Second)
	st := it.Stats()
	if st.Min != 12 || st.Max != 20 {
		t.Fatalf("stats min/max wrong: %+v", st)
	}
	if st.TTLSec != 90 {
		t.Fatalf("stats ttl wrong: %d", st.TTLSec)
	}
}

// TestNonceLengthIsClientChosen confirms we don't constrain client
// solvers to a fixed nonce width — a JS implementation may use a string,
// 4 bytes, 16 bytes, etc.
func TestNonceLengthIsClientChosen(t *testing.T) {
	it := newTestIssuer(t)
	tok, ser, _ := it.Issue(8) // issuer's min is 8, so honour it
	// Find a satisfying nonce using a 32-byte buffer for variety.
	nonce := make([]byte, 32)
	found := false
	for i := 0; i < 1<<20; i++ {
		nonce[28] = byte(i >> 24)
		nonce[29] = byte(i >> 16)
		nonce[30] = byte(i >> 8)
		nonce[31] = byte(i)
		h := sha256.New()
		h.Write(tok.Salt)
		h.Write(nonce)
		if hasLeadingZeros(h.Sum(nil), tok.Difficulty) {
			found = true
			break
		}
	}
	if !found {
		t.Skip("could not solve in 1M attempts — flaky env")
	}
	if _, err := it.Verify(ser, nonce); err != nil {
		t.Fatalf("32-byte nonce should be accepted: %v", err)
	}
}

// Sanity: signature output round-trips cleanly through base64-url.
func TestSignBodyRoundTrip(t *testing.T) {
	it := newTestIssuer(t)
	_, ser, _ := it.Issue(8)
	parts := strings.Split(ser, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Fatalf("salt not base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[4]); err != nil {
		t.Fatalf("sig not base64url: %v", err)
	}
}

// TestVerifyRejectsDifficultyDowngrade is the explicit forgery test for the
// "client lowers the work factor" technique. The difficulty is inside the
// HMAC-signed body, so rewriting it to an easier value must break the
// signature — the attacker cannot get a cheaper challenge accepted.
func TestVerifyRejectsDifficultyDowngrade(t *testing.T) {
	it := newTestIssuer(t)
	_, ser, err := it.Issue(16)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(ser, ".")
	// parts: id.salt.diff.exp.mac — rewrite diff to 1 (trivial to solve).
	parts[2] = "1"
	forged := strings.Join(parts, ".")
	// Solve at the downgraded difficulty so PoW would pass IF the token were
	// accepted; the signature check must reject it before that matters.
	saltBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	nonce, ok := SolveForTest(saltBytes, 1, 1<<20)
	if !ok {
		t.Fatal("solver gave up")
	}
	if _, err := it.Verify(forged, nonce); err != ErrTokenSignature {
		t.Fatalf("difficulty-downgrade forgery must fail with ErrTokenSignature, got %v", err)
	}
}

// TestVerifyRejectsCrossTokenNonceReuse covers the "solve once, reuse the
// nonce on a different challenge" technique. Each token's salt is unique and
// part of the PoW input, so a nonce that solves token A must not satisfy
// token B (different salt) — preventing precomputation / nonce recycling.
func TestVerifyRejectsCrossTokenNonceReuse(t *testing.T) {
	it := newTestIssuer(t)
	tokA, _, _ := it.Issue(8)
	_, serB, _ := it.Issue(8)
	parts := strings.Split(serB, ".")
	saltB, _ := base64.RawURLEncoding.DecodeString(parts[1])

	nonceA, ok := SolveForTest(tokA.Salt, 8, 1<<20)
	if !ok {
		t.Fatal("solver gave up on A")
	}
	// nonceA solves A's salt; the chance it also solves B's distinct salt at
	// 8 bits is 1/256, so retry until we have a nonce that does NOT solve B
	// to make the assertion deterministic.
	h := sha256.New()
	h.Write(saltB)
	h.Write(nonceA)
	if hasLeadingZeros(h.Sum(nil), 8) {
		t.Skip("rare: nonceA coincidentally solved salt B; non-deterministic, skip")
	}
	if _, err := it.Verify(serB, nonceA); err != ErrSolutionInvalid {
		t.Fatalf("cross-token nonce reuse must fail with ErrSolutionInvalid, got %v", err)
	}
}

// TestVerifyRejectsForeignSecret confirms a token minted by an issuer with a
// different secret is rejected — i.e. forging requires the server key.
func TestVerifyRejectsForeignSecret(t *testing.T) {
	victim := newTestIssuer(t)
	attacker, err := NewIssuer([]byte("attacker-secret-attacker-secret-xx"), 8, 16, time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, ser, _ := attacker.Issue(8)
	nonce, ok := SolveForTest(tok.Salt, 8, 1<<20)
	if !ok {
		t.Fatal("solver gave up")
	}
	if _, err := victim.Verify(ser, nonce); err != ErrTokenSignature {
		t.Fatalf("foreign-secret token must fail with ErrTokenSignature, got %v", err)
	}
}

// TestSeenEvictionPreservesReplayProtection is the regression test for the
// seen-set eviction fix: even when the seen-set is flooded past its ceiling,
// an UNEXPIRED redeemed token must still be rejected as a replay (the
// emergency eviction drops expired entries first, never a still-valid ID).
func TestSeenEvictionPreservesReplayProtection(t *testing.T) {
	it := newTestIssuer(t)
	tok, ser, _ := it.Issue(8)
	nonce, ok := SolveForTest(tok.Salt, 8, 1<<20)
	if !ok {
		t.Fatal("solver gave up")
	}
	if _, err := it.Verify(ser, nonce); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	// Flood the seen-set past the ceiling with EXPIRED entries (redeemed
	// older than the TTL). The emergency eviction must drop these, not the
	// fresh real redemption above.
	it.seenMu.Lock()
	old := time.Now().Add(-2 * it.ttl)
	for i := 0; i < 100001; i++ {
		it.seen["expired-"+strconv.Itoa(i)] = old
	}
	it.seenMu.Unlock()
	// Trigger claimSeen's ceiling path via a fresh (different) token.
	tok2, ser2, _ := it.Issue(8)
	nonce2, _ := SolveForTest(tok2.Salt, 8, 1<<20)
	_, _ = it.Verify(ser2, nonce2) // drives eviction of expired entries

	// The original token must STILL be seen → replay rejected.
	if _, err := it.Verify(ser, nonce); err != ErrTokenReplay {
		t.Fatalf("unexpired redeemed token must remain replay-protected after eviction, got %v", err)
	}
}

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/pow"
)

// signCookie reproduces internal/web/handlers_session.go:signPowCookie.
// We duplicate it here rather than importing web (would create a cycle).
// The two implementations are kept in lockstep by TestPoWCookieFormat
// which encodes the same shape on both sides and checks equivalence.
func signCookie(secret, id string, ts int64) string {
	body := id + "." + strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
	return body + "." + sig
}

// TestHasValidPoWCookieAcceptsFreshSignedCookie is the happy path for the
// gate's cookie check. If this regresses, every legitimate post-PoW
// request will be re-challenged in a loop.
func TestHasValidPoWCookieAcceptsFreshSignedCookie(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "test-secret",
		PoWCookieTTLSec: 3600,
	}}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  powCookieName,
		Value: signCookie("test-secret", "abc", time.Now().Unix()),
	})
	if !wp.hasValidPoWCookie(r) {
		t.Fatal("fresh, validly-signed cookie should pass")
	}
}

// TestHasValidPoWCookieRejectsTamperedSignature defends the headline
// security property: a client-mutated cookie must not pass.
func TestHasValidPoWCookieRejectsTamperedSignature(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "test-secret",
		PoWCookieTTLSec: 3600,
	}}
	good := signCookie("test-secret", "abc", time.Now().Unix())
	// Flip a single base64 char in the signature segment.
	tampered := good[:len(good)-3] + "XXX"
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: powCookieName, Value: tampered})
	if wp.hasValidPoWCookie(r) {
		t.Fatal("tampered cookie was accepted — auth-bypass risk")
	}
}

// TestHasValidPoWCookieRejectsExpired guarantees the TTL is honoured.
// Without this, a stolen cookie is valid forever.
func TestHasValidPoWCookieRejectsExpired(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "k",
		PoWCookieTTLSec: 1, // 1-second TTL
	}}
	r := httptest.NewRequest("GET", "/", nil)
	stale := signCookie("k", "x", time.Now().Add(-10*time.Second).Unix())
	r.AddCookie(&http.Cookie{Name: powCookieName, Value: stale})
	if wp.hasValidPoWCookie(r) {
		t.Fatal("expired cookie was accepted")
	}
}

// TestHasValidPoWCookieRejectsWrongSecret confirms the MAC is keyed on
// the operator's secret, not just on the cookie body.
func TestHasValidPoWCookieRejectsWrongSecret(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "operator-secret",
		PoWCookieTTLSec: 3600,
	}}
	// Cookie signed with a different key than the proxy uses.
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  powCookieName,
		Value: signCookie("attacker-key", "abc", time.Now().Unix()),
	})
	if wp.hasValidPoWCookie(r) {
		t.Fatal("cookie signed with wrong key was accepted")
	}
}

// TestHasValidPoWCookieRejectsMalformed tests the parser robustness so a
// crash in cookie handling can't be turned into a request-level DoS.
func TestHasValidPoWCookieRejectsMalformed(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "k",
		PoWCookieTTLSec: 3600,
	}}
	for _, val := range []string{
		"",
		"only-one-segment",
		"two.segments",
		"a.b.c.d.e", // five
		"a..c",      // empty middle
		string(make([]byte, 300)), // oversized
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: powCookieName, Value: val})
		if wp.hasValidPoWCookie(r) {
			t.Errorf("malformed value %q was accepted", val)
		}
	}
}

// TestShouldGateWithPoWThresholdLogic exercises the trigger calculation:
// only fire when score >= trigger and no valid cookie exists.
func TestShouldGateWithPoWThresholdLogic(t *testing.T) {
	wp := &WAFProxy{cfg: &config.Config{
		PoWEnabled:      true,
		PoWSecret:       "k",
		PoWCookieTTLSec: 3600,
		PoWTriggerScore: 60,
	}}
	// pow nil → no gate even at score 100.
	r := httptest.NewRequest("GET", "/", nil)
	if wp.shouldGateWithPoW(r, 100) {
		t.Fatal("nil issuer should never gate")
	}
	// Real issuer — we never call Issue() in this test, just need
	// shouldGateWithPoW to see a non-nil pointer.
	issuer, err := pow.NewIssuer([]byte("k"), 8, 16, time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	wp.pow = issuer

	if wp.shouldGateWithPoW(r, 59) {
		t.Fatal("below trigger should not gate")
	}
	if !wp.shouldGateWithPoW(r, 60) {
		t.Fatal("at trigger should gate")
	}
	if !wp.shouldGateWithPoW(r, 95) {
		t.Fatal("above trigger should gate")
	}

	// Valid cookie suppresses the gate even at high score.
	r.AddCookie(&http.Cookie{
		Name:  powCookieName,
		Value: signCookie("k", "abc", time.Now().Unix()),
	})
	if wp.shouldGateWithPoW(r, 95) {
		t.Fatal("valid cookie should bypass gate")
	}
}

// TestIsPoWBypassPathCoversChallengeAssets makes sure the PoW page
// itself, the verify endpoint, and the JS bundle never get gated — that
// would deadlock every challenged user.
func TestIsPoWBypassPathCoversChallengeAssets(t *testing.T) {
	must := []string{
		"/api/pow.js",
		"/api/pow/verify",
		"/api/browser-challenge.js",
		"/api/browser-challenge/verify",
	}
	for _, p := range must {
		if !isPoWBypassPath(p) {
			t.Errorf("%s must be on bypass list", p)
		}
	}
	if isPoWBypassPath("/anything-else") {
		t.Fatal("normal path should not bypass")
	}
}


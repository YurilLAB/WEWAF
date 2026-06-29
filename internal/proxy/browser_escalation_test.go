package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wewaf/internal/config"
)

// TestBrowserChallengeEscalation pins the escalation's truth table — most
// importantly that the suppressor is the unforgeable, session-bound PoW pass
// cookie (not the client-supplied browser-integrity signals), so a bot cannot
// shed the weight by forging a "real browser" submission.
func TestBrowserChallengeEscalation(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)

	// Block off → never escalate.
	wp := &WAFProxy{cfg: &config.Config{PoWEnabled: true, PoWSecret: "k", PoWCookieTTLSec: 3600}}
	if got := wp.browserChallengeEscalation(r, "s1"); got != 0 {
		t.Fatalf("block off must not escalate; got %d", got)
	}

	// Block on but PoW off → inert (no way for a client to clear the weight).
	wpNoPoW := &WAFProxy{cfg: &config.Config{BrowserChallengeBlock: true, PoWEnabled: false}}
	if got := wpNoPoW.browserChallengeEscalation(r, "s1"); got != 0 {
		t.Fatalf("PoW off must not escalate; got %d", got)
	}

	on := &WAFProxy{cfg: &config.Config{
		BrowserChallengeBlock: true, PoWEnabled: true, PoWSecret: "k", PoWCookieTTLSec: 3600,
	}}

	// Empty session → nothing to bind to.
	if got := on.browserChallengeEscalation(r, ""); got != 0 {
		t.Fatalf("empty session must not escalate; got %d", got)
	}

	// Block on, PoW on, no PoW pass → escalate.
	if got := on.browserChallengeEscalation(r, "s1"); got != BrowserChallengeRiskBump {
		t.Fatalf("un-verified session: want %d, got %d", BrowserChallengeRiskBump, got)
	}

	// The PoW/challenge verify + asset endpoints must NEVER be escalated — the
	// verify POST is how a client obtains its pass cookie, so escalating it could
	// block the request that would clear the gate (solve-loop deadlock).
	for _, p := range []string{"/api/pow/verify", "/api/pow.js", "/api/browser-challenge/verify", "/api/session/beacon"} {
		rb := httptest.NewRequest("POST", p, nil)
		if got := on.browserChallengeEscalation(rb, "s1"); got != 0 {
			t.Fatalf("bypass path %s must not be escalated; got %d", p, got)
		}
	}

	// A valid PoW pass cookie for THIS session suppresses the weight.
	rPass := httptest.NewRequest("GET", "/", nil)
	rPass.AddCookie(&http.Cookie{Name: powCookieName, Value: signCookie("k", "s1", time.Now().Unix())})
	if got := on.browserChallengeEscalation(rPass, "s1"); got != 0 {
		t.Fatalf("a valid PoW pass must suppress the escalation; got %d", got)
	}

	// ...but that same cookie does NOT clear a different session (session-bound).
	if got := on.browserChallengeEscalation(rPass, "s2"); got != BrowserChallengeRiskBump {
		t.Fatalf("a PoW cookie minted for s1 must not clear s2; got %d", got)
	}

	// A forged/garbage PoW cookie does not suppress it.
	rForge := httptest.NewRequest("GET", "/", nil)
	rForge.AddCookie(&http.Cookie{Name: powCookieName, Value: "s1." + time.Now().Format("0102") + ".forged"})
	if got := on.browserChallengeEscalation(rForge, "s1"); got != BrowserChallengeRiskBump {
		t.Fatalf("a forged PoW cookie must not suppress the escalation; got %d", got)
	}
}

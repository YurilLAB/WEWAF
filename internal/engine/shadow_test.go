package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

func newShadowEngine(t testing.TB, shadowIDs []string) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = "active"
	cfg.ShadowRuleIDs = shadowIDs
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	raw := rules.DefaultRules()
	raw = append(raw, rules.CRSRules()...)
	rs, err := rules.NewRuleSet(raw)
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	eng, err := NewEngine(cfg, rs, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// A CRLF header-injection payload — a hard-block (Action=Block) rule fires on a
// single match in the request-headers phase, so it blocks regardless of the
// cumulative score threshold (TestCRLFHeaderInjectionBlocked covers it).
const shadowXSSTarget = "/redirect?url=foo%0d%0aSet-Cookie:%20evil=1"

// TestShadowRuleSuppressesBlock proves the core S2 guarantee: a rule placed in
// shadow mode still matches and is reported as a would-block, but its score is
// excluded from the decision so the request is NOT blocked. It first discovers
// exactly which rules block a known-malicious request, then shadows those and
// asserts the same request now passes while the recorder observes the suppressed
// matches.
func TestShadowRuleSuppressesBlock(t *testing.T) {
	// 1. Baseline: confirm the request blocks, and capture the rule IDs.
	base := newShadowEngine(t, nil)
	intr := base.ProcessRequestHeaders(newReq(shadowXSSTarget))
	if intr == nil {
		t.Fatal("baseline: malicious request should be blocked")
	}
	ids := ruleIDsOf(intr.Matches)
	if len(ids) == 0 {
		t.Fatal("baseline: interruption carried no rule matches to shadow")
	}

	// 2. Shadow exactly those rules; the same request must now pass, and the
	//    recorder must observe every suppressed match.
	var recorded []string
	shadow := newShadowEngine(t, ids)
	shadow.SetShadowRecorder(func(_ *core.Transaction, m core.Match) {
		recorded = append(recorded, m.RuleID)
	})
	if intr2 := shadow.ProcessRequestHeaders(newReq(shadowXSSTarget)); intr2 != nil {
		t.Fatalf("shadowed rules must not block; got interruption with matches %v",
			ruleIDsOf(intr2.Matches))
	}
	if len(recorded) == 0 {
		t.Fatal("shadow recorder never fired for a suppressed would-block")
	}
}

// TestEmptyShadowListIsTransparent confirms shadow mode is zero-impact by
// default: with no shadow rules the malicious request still blocks exactly as
// before.
func TestEmptyShadowListIsTransparent(t *testing.T) {
	eng := newShadowEngine(t, nil)
	if eng.ProcessRequestHeaders(newReq(shadowXSSTarget)) == nil {
		t.Fatal("with no shadow rules the malicious request must still block")
	}
}

// TestShadowDoesNotSuppressOtherRules ensures shadowing one rule does not blunt
// the others: a request that trips BOTH a shadowed rule and an unrelated
// enforcing rule must still be blocked by the enforcing one.
func TestShadowDoesNotSuppressOtherRules(t *testing.T) {
	base := newShadowEngine(t, nil)
	intr := base.ProcessRequestHeaders(newReq(shadowXSSTarget))
	if intr == nil {
		t.Fatal("baseline block expected")
	}
	ids := ruleIDsOf(intr.Matches)
	if len(ids) < 2 {
		t.Skipf("request only trips %d rule(s); need >=2 to test partial shadowing", len(ids))
	}
	// Shadow only the first matched rule, leave the rest enforcing.
	shadow := newShadowEngine(t, ids[:1])
	if shadow.ProcessRequestHeaders(newReq(shadowXSSTarget)) == nil {
		t.Fatal("shadowing one rule must not stop the remaining enforcing rules from blocking")
	}
}

// TestShadowSuppressesBotFingerprint covers audit finding S2-1: the
// BOT-FINGERPRINT pseudo-rule is emitted by DetectBot BEFORE evaluatePhase, so
// shadowing it must still suppress its score contribution (it would otherwise
// bypass the in-evaluatePhase shadow guard entirely).
func TestShadowSuppressesBotFingerprint(t *testing.T) {
	// A request with no Accept / Accept-Language headers trips DetectBot's
	// MissingBrowserHeaders signal (score 20) and nothing else.
	base := newShadowEngine(t, nil)
	txB := newReq("/")
	base.ProcessRequestHeaders(txB)
	baseScore := txB.ScoreSnapshot()
	if baseScore == 0 {
		t.Skip("bot fingerprint not triggered for this request shape")
	}

	var recorded []string
	sh := newShadowEngine(t, []string{"BOT-FINGERPRINT"})
	sh.SetShadowRecorder(func(_ *core.Transaction, m core.Match) {
		recorded = append(recorded, m.RuleID)
	})
	txS := newReq("/")
	sh.ProcessRequestHeaders(txS)
	if txS.ScoreSnapshot() >= baseScore {
		t.Fatalf("shadowing BOT-FINGERPRINT must drop its score: base=%d shadowed=%d",
			baseScore, txS.ScoreSnapshot())
	}
	found := false
	for _, id := range recorded {
		if id == "BOT-FINGERPRINT" {
			found = true
		}
	}
	if !found {
		t.Fatal("shadow recorder did not observe the suppressed BOT-FINGERPRINT match")
	}
}

// TestShadowSuppressesResponseBlock covers the response phase: a rule that
// blocks on the RESPONSE body (CRS-950140, a leaked PEM private key — a real
// hard-block) must be suppressible by shadow mode exactly like a request-phase
// rule, since every phase shares evaluatePhase. Guards against a regression
// where shadow only worked for request phases.
func TestShadowSuppressesResponseBlock(t *testing.T) {
	pem := []byte("oops leaked:\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----\n")

	// Baseline: a PEM private key in the response body is blocked.
	base := newShadowEngine(t, nil)
	if base.ProcessResponseBody(newReq("/"), pem) == nil {
		t.Fatal("baseline: PEM private key in response should be blocked (CRS-950140)")
	}

	// Shadow CRS-950140: the response must no longer block, and the recorder fires.
	var recorded []string
	sh := newShadowEngine(t, []string{"CRS-950140"})
	sh.SetShadowRecorder(func(_ *core.Transaction, m core.Match) {
		recorded = append(recorded, m.RuleID)
	})
	if intr := sh.ProcessResponseBody(newReq("/"), pem); intr != nil {
		t.Fatalf("shadowed response-phase rule must not block; got matches %v", ruleIDsOf(intr.Matches))
	}
	found := false
	for _, id := range recorded {
		if id == "CRS-950140" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shadow recorder did not observe the suppressed response-phase match; got %v", recorded)
	}
}

func newReq(target string) *core.Transaction {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return core.NewTransaction(nil, req, nil)
}

func ruleIDsOf(matches []core.Match) []string {
	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, m := range matches {
		if m.RuleID == "" {
			continue
		}
		if _, ok := seen[m.RuleID]; ok {
			continue
		}
		seen[m.RuleID] = struct{}{}
		out = append(out, m.RuleID)
	}
	return out
}

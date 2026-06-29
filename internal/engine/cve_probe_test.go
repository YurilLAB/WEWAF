package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

func blockedInURI(eng *Engine, rawTarget string) bool {
	req := httptest.NewRequest(http.MethodGet, rawTarget, nil)
	tx := core.NewTransaction(nil, req, nil)
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// TestCVE_2025_29927 closes a confirmed FALSE POSITIVE: the rule used the broad
// "headers" target with a bare-substring `middleware` pattern, so ANY header
// value containing "middleware" (a User-Agent, a Referer to a docs page) was
// blocked with score 100. The pattern is now anchored to the actual exploit
// value shape (a `middleware` path or colon-chain), so it still catches the real
// x-middleware-subrequest forgery but no longer eats benign traffic.
func TestCVE_2025_29927(t *testing.T) {
	eng := newFuzzEngine(t)

	// Real exploit value shapes must still block.
	for _, v := range []string{
		"middleware",
		"src/middleware",
		"pages/_middleware",
		"middleware:middleware:middleware:middleware:middleware",
		"src/middleware:src/middleware",
	} {
		if !blockedInHeader(eng, "X-Middleware-Subrequest", v) {
			t.Errorf("real CVE-2025-29927 value not blocked: x-middleware-subrequest=%q", v)
		}
	}

	// Benign headers that merely contain the word "middleware" must NOT block.
	for _, c := range []struct{ name, value string }{
		{"User-Agent", "AcmeMiddlewareHealthCheck/1.0"},
		{"Referer", "https://example.com/docs/middleware-guide"},
		{"User-Agent", "Mozilla/5.0 (compatible; MiddlewareBot/2.1)"},
		{"X-Custom", "our middleware processed this request"},
	} {
		if blockedInHeader(eng, c.name, c.value) {
			t.Errorf("false positive: benign %s=%q was blocked", c.name, c.value)
		}
	}
}

// TestCVE_2024_4577_Defended documents (and regression-guards) that the REAL
// PHP-CGI argv-injection exploit is caught. The exploit MUST encode the '=' as
// %3D — RFC 3875 only treats the query string as command-line argv when it has
// no unencoded '=', which is what makes the injection work — and that encoded
// form is caught by CRS-933120 (the PHP ini-directive rule). The literal-'='
// forms that slip the CVE-specific pattern are not valid exploits.
func TestCVE_2024_4577_Defended(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, uri := range []string{
		"/index.php?%ADd+allow_url_include%3D1",
		"/index.php?%ADd+auto_prepend_file%3Dphp://input",
		"/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input",
	} {
		if !blockedInURI(eng, uri) {
			t.Errorf("CVE-2024-4577 real exploit not blocked: %q", uri)
		}
	}
}

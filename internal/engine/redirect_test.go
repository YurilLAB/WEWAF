package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"wewaf/internal/core"
)

func redirFlagged(eng *Engine, target string) bool {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	tx := core.NewTransaction(nil, req, nil)
	eng.ProcessRequestHeaders(tx)
	for _, m := range tx.MatchesSnapshot() {
		if m.RuleID == "REDIR-003" {
			return true
		}
	}
	return false
}

// TestOpenRedirectDetection covers REDIR-003: an off-site value in a
// redirect-style query param. REDIR-001/002 never fired on query params (they
// embed the param name in the regex and run against per-arg values, and the
// canonicalizer collapses "//"). Log-level, so legit relative paths and
// non-redirect params must not be flagged.
func TestOpenRedirectDetection(t *testing.T) {
	eng := newFuzzEngine(t)
	flag := []string{
		"/go?next=" + url.QueryEscape("//evil.com"),
		"/go?next=" + url.QueryEscape("/\\evil.com"),
		"/go?next=" + url.QueryEscape("\\/\\/evil.com"),
		"/go?next=" + url.QueryEscape("https://evil.com"),
		"/go?next=" + url.QueryEscape("https:/evil.com"),
		"/go?next=" + url.QueryEscape("http:/\\evil.com"),
		"/go?redirect_uri=" + url.QueryEscape("//evil.com/cb"),
		"/go?dest=" + url.QueryEscape("https://trusted.com@evil.com"),
		"/go?next=%2f%2fevil.com",                        // single-encoded protocol-relative
		"/go?url=" + url.QueryEscape("https://evil。com"), // ideographic-dot host
	}
	for _, u := range flag {
		u := u
		t.Run("flag", func(t *testing.T) {
			if !redirFlagged(eng, u) {
				t.Errorf("open redirect not flagged: %q", u)
			}
		})
	}
	noflag := []string{
		"/go?next=" + url.QueryEscape("/dashboard"), // relative
		"/go?next=" + url.QueryEscape("/account/settings"),
		"/go?redirect=" + url.QueryEscape("/home?tab=1"),
		"/go?next=profile",                          // relative, no slash
		"/go?q=" + url.QueryEscape("//search term"), // not a redirect param
		"/go?id=123",
	}
	for _, u := range noflag {
		u := u
		t.Run("noflag", func(t *testing.T) {
			if redirFlagged(eng, u) {
				t.Errorf("legit/non-redirect wrongly flagged: %q", u)
			}
		})
	}
}

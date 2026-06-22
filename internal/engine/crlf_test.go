package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

func crlfBlocked(eng *Engine, target string) bool {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil
}

// TestCRLFHeaderInjectionBlocked guards the response-splitting coverage. The
// canonicalizer URL-decodes "%0d%0a" and normalises the CR/LF to spaces, so
// CRLF-002 inspects the RAW request target instead. Every payload here injects
// a header after a CR/LF and must be blocked.
func TestCRLFHeaderInjectionBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"/redirect?url=foo%0d%0aSet-Cookie:%20evil=1",
		"/redirect?url=foo%0a%0dSet-Cookie:%20evil=1",
		"/page?next=x%0d%0aLocation:%20http://evil.com",
		"/page?next=x%250d%250aSet-Cookie:%20evil=1", // double-encoded
		"/api?cb=data%0d%0aContent-Length:%200",
		"/p?x=a%0d%0a%20%20Set-Cookie:%20b", // padded with encoded spaces
	}
	for _, u := range attacks {
		u := u
		t.Run(u, func(t *testing.T) {
			if !crlfBlocked(eng, u) {
				t.Errorf("CRLF header injection not blocked: %q", u)
			}
		})
	}
}

// TestCRLFNoFalsePositive confirms legitimate request targets — including
// multi-line text submitted via a GET parameter and params that merely
// contain a colon — are not blocked by the CRLF rule.
func TestCRLFNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"/search?q=cat+videos",
		"/comment?text=line1%0d%0aline2", // multi-line text, no injected header
		"/comment?text=Hello%0AWorld",    // single LF
		"/note?body=Re%3a%20hello",       // colon but no CR/LF
		"/redirect?url=https://app.example.com/dashboard",
		"/t?time=12%3a30",
	}
	for _, u := range legit {
		u := u
		t.Run(u, func(t *testing.T) {
			if crlfBlocked(eng, u) {
				t.Errorf("legitimate request target wrongly blocked as CRLF: %q", u)
			}
		})
	}
}

// TestNullByteInjection covers the NUL-byte technique (CWE-158): the
// canonicalizer strips NUL before rules run, so NULL-001 inspects the raw
// request target. Attacks must block; a literal "%25" (percent sign) must not.
func TestNullByteInjection(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"/x?f=shell.php%00.jpg",
		"/a?b=%00%00admin",
		"/d?file=passwd%2500", // double-encoded NUL
	}
	for _, u := range attacks {
		u := u
		t.Run("block_"+u, func(t *testing.T) {
			if !crlfBlocked(eng, u) {
				t.Errorf("NUL-byte injection not blocked: %q", u)
			}
		})
	}
	legit := []string{
		"/t?n=100%25",  // literal percent sign, not a NUL
		"/p?v=00abc",   // bare "00" digits, no percent
		"/q?s=a%2520b", // double-encoded space, not NUL
	}
	for _, u := range legit {
		u := u
		t.Run("allow_"+u, func(t *testing.T) {
			if crlfBlocked(eng, u) {
				t.Errorf("legitimate target wrongly blocked as NUL byte: %q", u)
			}
		})
	}
}

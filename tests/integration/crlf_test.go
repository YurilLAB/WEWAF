package integration_test

import (
	"io"
	"net/http"
	"testing"
)

// TestCRLFQueryInjectionBlockedE2E confirms the proxy blocks HTTP
// response-splitting delivered through a query parameter, end to end.
func TestCRLFQueryInjectionBlockedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	// Raw target with an encoded CRLF + injected Set-Cookie header.
	resp, err := http.Get(frontend.URL + "/redirect?url=foo%0d%0aSet-Cookie:%20evil=1")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CRLF query injection should be blocked (403), got %d: %s", resp.StatusCode, out)
	}
}

// TestCRLFLegitMultilineAllowedE2E confirms a legitimate multi-line GET
// parameter is not blocked by the CRLF rule.
func TestCRLFLegitMultilineAllowedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	resp, err := http.Get(frontend.URL + "/comment?text=line1%0d%0aline2")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("legitimate multi-line GET param wrongly blocked as CRLF")
	}
}

package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

// fireBody runs a body payload (with an optional Content-Type) through both
// phases and reports blocked.
func fireBody(eng *Engine, body []byte, contentType string) bool {
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", body)
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// TestBypassVerify_UTF7 confirms the engine's UTF-7 defense works for the only
// case that could actually execute (a request that declares charset=utf-7,
// which a charset-sniffing backend would decode). Without that declaration the
// payload is inert in every modern browser, so it is not a real bypass.
func TestBypassVerify_UTF7(t *testing.T) {
	eng := probeEngine(t)
	utf7XSS := []byte("+ADw-script+AD4-alert(document.cookie)+ADw-/script+AD4-")
	if !fireBody(eng, utf7XSS, "text/html; charset=utf-7") {
		t.Errorf("UTF-7 XSS declared as charset=utf-7 must be decoded and blocked")
	}
}

// TestBypassVerify_OpenRedirect confirms open-redirect DETECTION works on the
// redirect param names it targets. REDIR-003 is intentionally ActionLog/score
// 40 (not a block): legitimate apps redirect off-site constantly (OAuth, SSO,
// share links), so blocking every off-site redirect would be unusable — this is
// visibility for the operator, not enforcement. So we assert the MATCH is
// recorded, not that the request is blocked.
func TestBypassVerify_OpenRedirect(t *testing.T) {
	eng := probeEngine(t)
	cases := map[string]string{
		"protorel":  "url=//evil.example/path",
		"backslash": "redirect=/\\evil.example",
	}
	for name, q := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.RawQuery = q
		tx := core.NewTransaction(nil, req, nil)
		eng.ProcessRequestHeaders(tx)
		found := false
		for _, m := range tx.MatchesSnapshot() {
			if m.RuleID == "REDIR-003" {
				found = true
			}
		}
		if !found {
			t.Errorf("open redirect in redirect-param %q should be DETECTED (REDIR-003): %s", name, q)
		}
	}
}

// TestBypassVerify_DeserRaw probes whether RAW binary Java/.NET serialization
// (the actual magic bytes, not the base64/hex text form) is detected. The
// existing DESER rules match rO0AB / aced0005 (base64/hex) but a raw-binary body
// to a deserialization endpoint carries the magic bytes verbatim.
func TestBypassVerify_DeserRaw(t *testing.T) {
	eng := probeEngine(t)
	// base64 form (should already block via DESER-001).
	if !fireBody(eng, []byte("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"), "application/x-java-serialized-object") {
		t.Errorf("base64 Java serialization (rO0AB...) should block")
	}
	// RAW magic bytes: 0xAC 0xED 0x00 0x05 0x73 0x72 ("..sr").
	raw := []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x11}
	blocked := fireBody(eng, raw, "application/x-java-serialized-object")
	t.Logf("raw-binary Java serialization (0xACED0005) blocked=%v", blocked)
}

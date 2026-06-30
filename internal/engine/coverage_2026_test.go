package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// Empirical coverage tests for the 2026 red-team round: each new signature must
// FIRE on the real attack payload AND stay silent on representative benign
// traffic. Verified against the full default+CRS rule set via newFuzzEngine.

// covFired runs both request phases and returns the set of rule IDs that matched.
func covFired(eng *Engine, tx *core.Transaction) map[string]bool {
	eng.ProcessRequestHeaders(tx)
	eng.ProcessRequestBody(tx)
	out := make(map[string]bool)
	for _, m := range tx.MatchesSnapshot() {
		out[m.RuleID] = true
	}
	return out
}

// covBlocked reports whether either request phase interrupts the transaction.
// Needed for body-phase rules (XPATH-001/XQUERY-001 etc.) whose Block decision
// lands in ProcessRequestBody, which the proxy always runs but blockedInArg
// (header-phase only) does not.
func covBlocked(eng *Engine, tx *core.Transaction) bool {
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

func covArgTx(payload string) *core.Transaction {
	req := httptest.NewRequest(http.MethodGet, "/probe?x="+url.QueryEscape(payload), nil)
	return core.NewTransaction(nil, req, nil)
}

func covURITx(rawTarget string) *core.Transaction {
	req := httptest.NewRequest(http.MethodGet, rawTarget, nil)
	return core.NewTransaction(nil, req, nil)
}

func covRawBodyTx(payload string) *core.Transaction {
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(payload))
	return tx
}

func covJSONTx(payload string) *core.Transaction {
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(payload))
	return tx
}

// TestXQueryInjectionCoverage — XQUERY-001 catches the MarkLogic/eXist function
// vocabulary that RCE-006's bare eval(/exec( misses, without eating benign dotted
// .execute( or bare value(.
func TestXQueryInjectionCoverage(t *testing.T) {
	eng := newFuzzEngine(t)

	attacks := []string{
		"' or xdmp:value(xdmp:get-request-field('c')) or '",
		"x or xdmp:spawn('/backdoor.xqy')",
		"a or xdmp:invoke('/x.xqy')",
		"q or xdmp:http-get('http://169.254.169.254/')",
		"foo or process:execute('/bin/sh','-c','id')",
		"util:eval('1+1')",
		"system:exec('id')",
	}
	for _, a := range attacks {
		if !covBlocked(eng, covArgTx(a)) {
			t.Errorf("XQuery payload not blocked: %q", a)
		}
		if !covFired(eng, covArgTx(a))["XQUERY-001"] {
			t.Errorf("XQUERY-001 did not fire on: %q", a)
		}
	}

	// Benign: dotted .execute( (Java/JS), bare value(, prose — must NOT match
	// XQUERY-001 (the colon-namespace prefix is required).
	for _, b := range []string{
		"process.execute(report)",
		"order.value(total)",
		"please process my execute request",
	} {
		if covFired(eng, covArgTx(b))["XQUERY-001"] {
			t.Errorf("XQUERY-001 false-positive on benign: %q", b)
		}
	}
}

// TestBodyHeaderInjectionCoverage — CRLF-003 catches CRLF-injected mail and
// internal-redirect headers in urlencoded AND JSON bodies, but not benign
// multi-line text.
func TestBodyHeaderInjectionCoverage(t *testing.T) {
	eng := newFuzzEngine(t)

	// urlencoded body: only the CRLF is encoded, the header name+colon is literal.
	urlenc := []string{
		"email=bob@site.com%0d%0aBcc:spam1@a.com,spam2@b.com",
		"name=Bob%0d%0aReply-To:attacker@evil.com",
		"c=hi%0d%0aX-Accel-Redirect:/internal/secret-config",
		"u=x%0a%0aX-Sendfile:/etc/passwd",
	}
	for _, p := range urlenc {
		if !blockedInRawBody(eng, p) {
			t.Errorf("urlencoded body header injection not blocked: %q", p)
		}
		if !covFired(eng, covRawBodyTx(p))["CRLF-003"] {
			t.Errorf("CRLF-003 did not fire on: %q", p)
		}
	}

	// JSON body: \r\n escapes (raw view literal, json-decoded view real CR/LF).
	jsonAttacks := []string{
		`{"email":"bob@site.com\r\nBcc: spam@a.com"}`,
		`{"to":"x@y.com\r\nReturn-Path: attacker@evil.com"}`,
	}
	for _, p := range jsonAttacks {
		if !blockedInJSONBody(eng, p) {
			t.Errorf("JSON body header injection not blocked: %q", p)
		}
	}

	// Benign multi-line bodies — a CRLF NOT followed by a targeted header name.
	for _, b := range []string{
		"feedback=Great product%0d%0aWould recommend it to a friend",
		"message=line one%0d%0aline two please reply when free",
	} {
		if covFired(eng, covRawBodyTx(b))["CRLF-003"] {
			t.Errorf("CRLF-003 false-positive on benign body: %q", b)
		}
	}
	if covFired(eng, covJSONTx(`{"msg":"hello there\r\nsecond line of the note"}`))["CRLF-003"] {
		t.Error("CRLF-003 false-positive on benign JSON body")
	}
}

// TestWebCacheDeceptionCoverage — WCD-001 (Log-level) flags a matrix-param/
// static-extension path-confusion suffix on a dynamic path, but not legit static
// assets, the Java jsessionid form, or query-string semicolons.
func TestWebCacheDeceptionCoverage(t *testing.T) {
	eng := newFuzzEngine(t)

	for _, a := range []string{
		"/api/users/me;cache_deception.css",
		"/account/profile;x.js",
		"/wallet;a.png",
	} {
		if !covFired(eng, covURITx(a))["WCD-001"] {
			t.Errorf("WCD-001 did not fire on cache-deception probe: %q", a)
		}
	}

	for _, b := range []string{
		"/static/app.css",            // legit static asset
		"/assets/main.js?v=2",        // legit with query
		"/file.css;jsessionid=ABC123", // Java rewriting: ext BEFORE ';'
		"/app;jsessionid=ABC/main.css", // matrix on segment, '/' before ext
		"/search?files=a.png;thumb.png", // ';' in the QUERY string, not path
	} {
		if covFired(eng, covURITx(b))["WCD-001"] {
			t.Errorf("WCD-001 false-positive on benign URI: %q", b)
		}
	}
}

// TestSharePointToolShellCoverage — CVE-2025-53770 blocks the ToolPane edit-mode
// auth-bypass chain (DisplayMode=Edit + a=/ToolPane self-ref) but not legitimate
// authenticated page editing.
func TestSharePointToolShellCoverage(t *testing.T) {
	eng := newFuzzEngine(t)

	for _, a := range []string{
		"/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx",
		"/_layouts/16/toolpane.aspx?a=/toolpane.aspx&displaymode=edit",
	} {
		if !blockedInURI(eng, a) {
			t.Errorf("ToolShell exploit not blocked: %q", a)
		}
		if !covFired(eng, covURITx(a))["CVE-2025-53770"] {
			t.Errorf("CVE-2025-53770 did not fire on: %q", a)
		}
	}

	// Legit SharePoint page editing has DisplayMode=Edit but NOT the a=/ self-ref.
	for _, b := range []string{
		"/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
		"/_layouts/15/start.aspx",
	} {
		if covFired(eng, covURITx(b))["CVE-2025-53770"] {
			t.Errorf("CVE-2025-53770 false-positive on legit SharePoint URI: %q", b)
		}
	}
}

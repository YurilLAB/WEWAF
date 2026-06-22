package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

// hdrBlocked sends a GET with the given headers and reports whether the
// request-header phase blocked it.
func hdrBlocked(eng *Engine, hdrs map[string]string) bool {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil
}

// hdrMatched reports whether any rule (block or log) matched.
func hdrMatched(eng *Engine, hdrs map[string]string) bool {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	tx := core.NewTransaction(nil, req, nil)
	eng.ProcessRequestHeaders(tx)
	return tx.MatchCount() > 0
}

// TestShellshockVariantsBlocked covers the *technique* (the "() {" env-var
// function-definition prelude) rather than the canonical "() { :; };" payload,
// so variants with arbitrary bodies and the CVE-2014-7169 form are all caught,
// in whichever header carries them.
func TestShellshockVariantsBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	cases := []map[string]string{
		{"User-Agent": "() { :; }; echo vuln"},
		{"User-Agent": "() {:;};echo"},
		{"Referer": "() { ignored; }; /usr/bin/id"},
		{"Cookie": "() { _; } >_[$($())] { echo; }"},
		{"X-Api-Version": "() { :; }; /bin/bash -c id"},
	}
	for _, h := range cases {
		if !hdrBlocked(eng, h) {
			t.Errorf("shellshock not blocked: %v", h)
		}
	}
	// A legitimate JS-ish value with a NAMED function must not match.
	if hdrBlocked(eng, map[string]string{"X-Debug": "function() { return 1 }", "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en"}) {
		t.Errorf("named function() in header wrongly flagged as shellshock")
	}
}

// TestForwardedHostPoisoningBlocked covers X-Forwarded-Host / X-Host pointing
// at an internal, loopback, or metadata host (cache / password-reset
// poisoning, SSRF), and confirms a normal external host is allowed.
func TestForwardedHostPoisoningBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	bad := []map[string]string{
		{"X-Forwarded-Host": "localhost"},
		{"X-Forwarded-Host": "127.0.0.1"},
		{"X-Forwarded-Host": "169.254.169.254"},
		{"X-Forwarded-Host": "internal-admin.corp.internal"},
		{"X-Host": "192.168.1.10"},
	}
	for _, h := range bad {
		if !hdrBlocked(eng, h) {
			t.Errorf("forwarded-host poisoning not blocked: %v", h)
		}
	}
	good := map[string]string{"X-Forwarded-Host": "app.example.com", "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en"}
	if hdrBlocked(eng, good) {
		t.Errorf("legitimate X-Forwarded-Host wrongly blocked")
	}
}

// TestURLOverrideBypassBlocked covers the X-Original-URL / X-Rewrite-URL
// access-control bypass technique.
func TestURLOverrideBypassBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, k := range []string{"X-Original-URL", "X-Rewrite-URL", "X-Original-URI", "X-Override-URL", "X-Forwarded-Prefix"} {
		if !hdrBlocked(eng, map[string]string{k: "/admin"}) {
			t.Errorf("URL-override header %q not blocked", k)
		}
	}
}

// TestSpoofedClientIPLogged covers source-IP spoofing via private IPs in
// client-IP forwarding headers (log-level — recorded, not blocked).
func TestSpoofedClientIPLogged(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, k := range []string{"True-Client-IP", "X-Real-IP", "X-Client-IP", "X-Cluster-Client-IP"} {
		if !hdrMatched(eng, map[string]string{k: "10.0.0.1", "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en"}) {
			t.Errorf("spoofed client-IP header %q not detected", k)
		}
	}
	// A public IP in X-Real-IP (the normal case for an edge proxy) is fine.
	if hdrMatched(eng, map[string]string{"X-Real-IP": "203.0.113.9", "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en"}) {
		t.Errorf("public X-Real-IP wrongly flagged as spoof")
	}
}

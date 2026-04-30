package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/config"
)

// TestHSTSEmittedOnlyForHTTPSBackends confirms the Strict-Transport-Security
// header:
//   - appears when backend is https AND hsts_enabled=true
//   - is silent on http backends (spec-noncompliant to emit)
//   - includes subdomains + preload per config
func TestHSTSEmittedOnlyForHTTPSBackends(t *testing.T) {
	cases := []struct {
		name      string
		backend   string
		enabled   bool
		wantHSTS  bool
	}{
		{"https-on", "https://upstream:443", true, true},
		{"https-off", "https://upstream:443", false, false},
		{"http-on", "http://upstream:80", true, false}, // refusing to mis-advertise TLS
		{"http-off", "http://upstream:80", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			back, _ := url.Parse(tc.backend)
			wp := &WAFProxy{
				cfg: &config.Config{
					SecurityHeadersEnabled: true,
					HSTSEnabled:            tc.enabled,
					HSTSMaxAgeSec:          31536000,
					HSTSIncludeSubdoms:     true,
					HSTSPreload:            true,
				},
				backend: back,
			}
			// Fabricate a minimal response to pass through modifyResponse.
			r, _ := http.NewRequest("GET", "/", nil)
			resp := &http.Response{
				Header:     http.Header{},
				StatusCode: 200,
				Request:    r,
			}
			// modifyResponse reads from proxy fields for HSTS; call a
			// narrow helper that mirrors the real emitter.
			wp.applyHeadersForTest(resp)

			got := resp.Header.Get("Strict-Transport-Security")
			if tc.wantHSTS {
				if got == "" {
					t.Fatalf("expected HSTS header, got none")
				}
				if !strings.Contains(got, "max-age=31536000") {
					t.Fatalf("missing max-age: %q", got)
				}
				if !strings.Contains(got, "includeSubDomains") {
					t.Fatalf("includeSubDomains missing: %q", got)
				}
				if !strings.Contains(got, "preload") {
					t.Fatalf("preload missing: %q", got)
				}
			} else if got != "" {
				t.Fatalf("unexpected HSTS header: %q", got)
			}
		})
	}

	// Smoke: the other security headers still go out regardless.
	back, _ := url.Parse("https://u")
	wp := &WAFProxy{cfg: &config.Config{SecurityHeadersEnabled: true}, backend: back}
	r, _ := http.NewRequest("GET", "/", nil)
	resp := &http.Response{Header: http.Header{}, Request: r}
	wp.applyHeadersForTest(resp)
	for _, h := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		// Defence-in-depth additions — once they're in, never let a
		// future refactor silently drop them.
		"X-DNS-Prefetch-Control",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Opener-Policy",
	} {
		if resp.Header.Get(h) == "" {
			t.Fatalf("%s missing — base security headers regressed", h)
		}
	}
	// Smoke: recorder round-trip.
	rec := httptest.NewRecorder()
	rec.Header().Set("Foo", "bar")
	if rec.Header().Get("Foo") != "bar" {
		t.Fatal("testing framework broke itself")
	}
}

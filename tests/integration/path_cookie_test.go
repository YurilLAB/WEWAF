package integration_test

import (
	"io"
	"net/http"
	"testing"
)

func TestPathEmbeddedSSRFBlockedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()
	resp, err := http.Get(frontend.URL + "/proxy/http://169.254.169.254/latest/meta-data/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("path-embedded SSRF should be blocked (403), got %d: %s", resp.StatusCode, out)
	}
}

func TestPathExternalURLAllowedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()
	resp, err := http.Get(frontend.URL + "/cache/http://cdn.example.com/a.png")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("path with external URL wrongly blocked")
	}
}

func TestCookieXSSBlockedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()
	req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/", nil)
	req.Header.Set("Cookie", "pref=<script>alert(1)</script>")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("XSS in cookie should be blocked (403), got %d: %s", resp.StatusCode, out)
	}
}

func TestLegitCookieAllowedE2E(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()
	req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/", nil)
	req.Header.Set("Cookie", "session=abc123; theme=dark; jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc+def/ghi==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("legitimate cookie wrongly blocked")
	}
}

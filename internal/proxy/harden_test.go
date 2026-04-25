package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHardenSmugglingTECL ensures the most dangerous request-smuggling
// shape (Content-Length AND Transfer-Encoding both present) is refused.
// This is the textbook "TE.CL" / "CL.TE" desync prerequisite — letting
// it through would mean a downstream that picks one and a WAF that
// inspects the other can disagree on where one request ends.
func TestHardenSmugglingTECL(t *testing.T) {
	r := httptest.NewRequest("POST", "/login", strings.NewReader("x"))
	r.Header.Set("Content-Length", "1")
	r.Header.Set("Transfer-Encoding", "chunked")
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-SMUGGLE-TE-CL" {
		t.Fatalf("expected smuggling rejection; got %+v", v)
	}
	if v.Status != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", v.Status)
	}
}

func TestHardenMultiValuedTransferEncoding(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Add("Transfer-Encoding", "chunked")
	r.Header.Add("Transfer-Encoding", "chunked")
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-SMUGGLE-TE-MULTI" {
		t.Fatalf("expected multi-TE rejection; got %+v", v)
	}
}

func TestHardenWeirdTransferEncodingRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Transfer-Encoding", "xchunked")
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-SMUGGLE-TE-BAD" {
		t.Fatalf("expected bad-TE rejection; got %+v", v)
	}
}

func TestHardenChunkedTransferEncodingAllowed(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Transfer-Encoding", "chunked")
	v := evaluateHardening(r)
	if v.Reject {
		t.Fatalf("legitimate chunked TE rejected: %+v", v)
	}
}

func TestHardenCRLFInHeaderValueRejected(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	// Bypass net/http's outbound header validation by writing the raw
	// values via the underlying map.
	r.Header["X-Test"] = []string{"value\r\nSet-Cookie: evil=1"}
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-CRLF-HEADER" {
		t.Fatalf("expected CRLF rejection; got %+v", v)
	}
}

func TestHardenDoubleEncodedTraversalRejected(t *testing.T) {
	cases := []string{
		"/files/%2e%2e/%2e%2e/etc/passwd",   // single-decoded ../../etc/passwd
		"/files/%252e%252e/etc/passwd",       // double-encoded ../etc/passwd
		"/api/%2e%2e/%2e%2e/admin",
	}
	for _, p := range cases {
		r := httptest.NewRequest("GET", p, nil)
		v := evaluateHardening(r)
		if !v.Reject || v.RuleID != "HARDEN-PATH-TRAVERSAL" {
			t.Errorf("%s: expected traversal rejection; got %+v", p, v)
		}
	}
}

func TestHardenLegitimatePathsAllowed(t *testing.T) {
	cases := []string{
		"/",
		"/api/users/123",
		"/static/app.css",
		"/search?q=hello", // querystring is fine
		"/files/foo.bar.baz", // dots OK as long as not /../
	}
	for _, p := range cases {
		r := httptest.NewRequest("GET", p, nil)
		v := evaluateHardening(r)
		if v.Reject {
			t.Errorf("%s should be allowed; got %+v", p, v)
		}
	}
}

func TestHardenDangerousMethodsRejected(t *testing.T) {
	for _, m := range []string{"TRACE", "TRACK", "DEBUG", "CONNECT"} {
		r := httptest.NewRequest(m, "/", nil)
		v := evaluateHardening(r)
		if !v.Reject || v.RuleID != "HARDEN-METHOD" {
			t.Errorf("method %s: expected reject; got %+v", m, v)
		}
	}
}

func TestHardenStandardMethodsAllowed(t *testing.T) {
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		r := httptest.NewRequest(m, "/", nil)
		v := evaluateHardening(r)
		if v.Reject {
			t.Errorf("method %s should be allowed; got %+v", m, v)
		}
	}
}

func TestHardenEmptyHostRejected(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = ""
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-HOST-MISSING" {
		t.Fatalf("expected host-missing reject; got %+v", v)
	}
}

func TestHardenControlCharInHostRejected(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "example.com\x00.evil"
	v := evaluateHardening(r)
	if !v.Reject || v.RuleID != "HARDEN-HOST-CTL" {
		t.Fatalf("expected host-ctl reject; got %+v", v)
	}
}

func TestHardenPassesNormalRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/health", nil)
	r.Header.Set("User-Agent", "test/1.0")
	v := evaluateHardening(r)
	if v.Reject {
		t.Fatalf("ordinary request was rejected: %+v", v)
	}
}

package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWithAuthKeyComparison covers the admin API-key gate: the correct key
// passes, any wrong key (including one of a DIFFERENT length than the real key,
// which guards the constant-time-compare length-oracle fix) is 401, a missing
// key is 401, and every failure increments the observability counter.
func TestWithAuthKeyComparison(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // 32 bytes
	t.Setenv("WAF_API_KEY", key)
	t.Setenv("WAF_ALLOW_NO_AUTH", "")

	s := &Server{}
	called := 0
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	do := func(hdr string, setHeader bool) int {
		r := httptest.NewRequest("GET", "/api/health", nil)
		if setHeader {
			r.Header.Set("X-API-Key", hdr)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := do(key, true); code != http.StatusOK {
		t.Fatalf("correct key should pass, got %d", code)
	}
	if code := do("wrong", true); code != http.StatusUnauthorized { // shorter than real key
		t.Fatalf("short wrong key should 401, got %d", code)
	}
	if code := do("0123456789abcdef0123456789abcdeZ", true); code != http.StatusUnauthorized { // same length
		t.Fatalf("same-length wrong key should 401, got %d", code)
	}
	if code := do("", false); code != http.StatusUnauthorized {
		t.Fatalf("missing key should 401, got %d", code)
	}
	if called != 1 {
		t.Fatalf("next handler should run exactly once (valid key only), ran %d", called)
	}
	if got := s.adminAuthFailures.Load(); got != 3 {
		t.Fatalf("expected 3 recorded auth failures, got %d", got)
	}
}

// TestWithAuthFailsClosedWhenNoKey confirms the admin API refuses to serve
// (503) when no key is configured and the dev escape hatch is off.
func TestWithAuthFailsClosedWhenNoKey(t *testing.T) {
	t.Setenv("WAF_API_KEY", "")
	t.Setenv("WAF_ALLOW_NO_AUTH", "")
	s := &Server{}
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no key + no escape hatch should fail closed (503), got %d", w.Code)
	}
}

// TestWithAuthNoAuthEscapeHatch confirms WAF_ALLOW_NO_AUTH=1 passes requests
// through unauthenticated (the local-dev path that main.go restricts to a
// loopback bind).
func TestWithAuthNoAuthEscapeHatch(t *testing.T) {
	t.Setenv("WAF_API_KEY", "")
	t.Setenv("WAF_ALLOW_NO_AUTH", "1")
	s := &Server{}
	passed := false
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !passed || w.Code != http.StatusOK {
		t.Fatalf("WAF_ALLOW_NO_AUTH=1 should pass through, got code=%d passed=%v", w.Code, passed)
	}
}

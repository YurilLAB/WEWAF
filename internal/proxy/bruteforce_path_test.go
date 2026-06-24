package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsLoginRequestPathEvasion is the regression for the brute-force
// path-normalisation evasion: the credential-attempt counter hangs entirely
// off isLoginRequest, so a login path the predicate fails to recognise is
// never counted. A servlet matrix param (/login;jsessionid=x) and an
// unenumerated API version (/api/v3/login) both routed to the real login
// handler while evading detection.
func TestIsLoginRequestPathEvasion(t *testing.T) {
	mustMatch := []string{
		"/login",
		"/login/",
		"/login;jsessionid=ABC123",  // Tomcat matrix param — was evading
		"/login/;jsessionid=ABC123", // matrix param + trailing slash
		"/api/login;jsessionid=x",   // matrix param on a listed path
		"/api/v3/login",             // version beyond the v1/v2 list — was evading
		"/api/v10/auth",             // generalised version + verb
		"/v5/login",                 // version without /api prefix
		"/api/v2/login",             // still-listed version
		"/AUTH",                     // case-insensitive
	}
	for _, p := range mustMatch {
		r := httptest.NewRequest(http.MethodPost, p, nil)
		if !isLoginRequest(r) {
			t.Errorf("isLoginRequest(POST %q) = false, want true (brute-force evasion)", p)
		}
	}

	// Non-login paths and non-POST methods must NOT be treated as login.
	mustNotMatch := []struct {
		method, path string
	}{
		{http.MethodGet, "/login"},            // GET is not a credential attempt
		{http.MethodPost, "/loginhistory"},    // substring, not the login endpoint
		{http.MethodPost, "/api/v3/loginlog"}, // version + non-login verb
		{http.MethodPost, "/products"},        // ordinary endpoint
		{http.MethodPost, "/v3/dashboard"},    // versioned non-login
	}
	for _, c := range mustNotMatch {
		r := httptest.NewRequest(c.method, c.path, nil)
		if isLoginRequest(r) {
			t.Errorf("isLoginRequest(%s %q) = true, want false (false positive)", c.method, c.path)
		}
	}
}

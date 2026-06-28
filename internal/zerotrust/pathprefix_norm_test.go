package zerotrust

import (
	"net/http/httptest"
	"testing"
)

// TestPathPrefixSelectorNormalized is the regression for ZT-NORM-002: the
// PathPrefix selector was only lowercased, not canonicalized like the request
// path (lower(normalizePath(...))) and like PathExact. So an operator prefix in
// natural directory form ("/admin/") stayed "/admin/" while a request to the
// prefix ROOT canonicalized to "/admin" — HasPrefix("/admin","/admin/") is
// false, leaving the root served WITHOUT the policy's mTLS/IP checks.
func TestPathPrefixSelectorNormalized(t *testing.T) {
	e := NewEngine(nil)
	if err := e.SetPolicies([]*Policy{{ID: "admin-mtls", PathPrefix: "/admin/", RequireMTLS: true}}); err != nil {
		t.Fatal(err)
	}
	// The prefix root + case/slash/matrix variants must ALL be gated and denied
	// (mTLS header absent).
	for _, p := range []string{"/admin", "/admin/", "/Admin", "/admin/users", "/admin;jsessionid=x", "//admin"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if d, _, _ := e.Evaluate(r, "203.0.113.9"); d != DecisionDeny {
			t.Errorf("PathPrefix:/admin/ — path %q: decision=%s, want deny (prefix root left unprotected)", p, d)
		}
	}
	// Unrelated paths must not match (no false positive).
	for _, p := range []string{"/public", "/api/health", "/dashboard"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if d, _, _ := e.Evaluate(r, "203.0.113.9"); d == DecisionDeny {
			t.Errorf("path %q unexpectedly denied (false positive)", p)
		}
	}
}

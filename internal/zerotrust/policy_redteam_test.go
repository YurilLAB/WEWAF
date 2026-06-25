package zerotrust

import (
	"net/http/httptest"
	"testing"
)

// TestPathNormalizationGate is the regression for the zero-trust path-
// normalization bypass class: matrix params, duplicate/trailing slashes,
// trailing dots, and case variants all evaded a PathExact/PathPrefix mTLS
// policy while the backend still routed to the protected resource. The gate
// must now match the canonical path the origin sees.
func TestPathNormalizationGate(t *testing.T) {
	e := NewEngine(nil)
	if err := e.SetPolicies([]*Policy{{ID: "admin-mtls", PathPrefix: "/admin", RequireMTLS: true}}); err != nil {
		t.Fatal(err)
	}
	// Every variant must MATCH the policy and be DENIED (mTLS header absent).
	evade := []string{
		"/admin", "/admin/", "/admin;jsessionid=x", "//admin", "/admin//users",
		"/admin/secret", "/admin/secret/", "/Admin/secret", "/ADMIN", "/admin.",
		"/admin/users//delete", "/admin/users/delete;x",
	}
	for _, p := range evade {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if d, _, _ := e.Evaluate(r, "203.0.113.9"); d != DecisionDeny {
			t.Errorf("path %q: decision=%s, want deny (mTLS gate evaded)", p, d)
		}
	}
	// Unrelated paths must NOT match the policy (no false positives).
	for _, p := range []string{"/public", "/api/health", "/dashboard", "/billing"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if d, _, _ := e.Evaluate(r, "203.0.113.9"); d == DecisionDeny {
			t.Errorf("path %q: unexpectedly denied (false positive)", p)
		}
	}
}

// TestPathExactNormalization covers the PathExact selector specifically.
func TestPathExactNormalization(t *testing.T) {
	e := NewEngine(nil)
	if err := e.SetPolicies([]*Policy{{ID: "exact", PathExact: "/admin/users/delete", RequireMTLS: true}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/admin/users/delete", "/admin/users/delete/", "/admin/users//delete",
		"/admin/users/delete;x", "/Admin/Users/Delete", "/admin/users/delete.",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		if d, _, _ := e.Evaluate(r, "203.0.113.9"); d != DecisionDeny {
			t.Errorf("PathExact %q: decision=%s, want deny", p, d)
		}
	}
	// A different exact path must not match.
	r := httptest.NewRequest("GET", "/", nil)
	r.URL.Path = "/admin/users/list"
	if d, _, _ := e.Evaluate(r, "203.0.113.9"); d == DecisionDeny {
		t.Errorf("/admin/users/list should not match PathExact:/admin/users/delete")
	}
}

// TestIPv6BlockFullPrecision is the regression for the IPv6 >/64 fail-open:
// a /128 BlockedCIDR must actually block when the gate is fed the full client
// IP (as the proxy now passes via ClientIPRaw).
func TestIPv6BlockFullPrecision(t *testing.T) {
	e := NewEngine(nil)
	if err := e.SetPolicies([]*Policy{{ID: "v6", PathPrefix: "/", BlockedCIDRs: []string{"2001:db8::dead:beef:0:1/128"}}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/x", nil)
	if d, _, _ := e.Evaluate(r, "2001:db8::dead:beef:0:1"); d != DecisionDeny {
		t.Errorf("full /128 IP should be blocked by the /128 rule, got %s", d)
	}
	// A different /128 in the same /64 must NOT be blocked (precise matching).
	if d, _, _ := e.Evaluate(r, "2001:db8::dead:beef:0:2"); d == DecisionDeny {
		t.Errorf("a different /128 must not be blocked by a /128 rule")
	}
}

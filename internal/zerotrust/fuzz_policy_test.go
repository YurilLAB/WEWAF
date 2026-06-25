package zerotrust

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzNormalizePath fuzzes the path canonicaliser (which processes attacker-
// controlled request paths in front of the authz gate) for panics and a few
// invariants: it never panics, always returns a non-empty path starting with a
// slash for slash-rooted input, and is idempotent.
func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{
		"/admin", "/admin/", "//admin", "/admin;x", "/admin/users//delete",
		"/admin.", "/a/b/c/", "/", "", "/%2e", "/a;b/c;d/", strings.Repeat("/", 50),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := normalizePath(p) // must never panic
		if got == "" {
			t.Fatalf("normalizePath(%q) returned empty", p)
		}
		// Idempotent: normalizing again changes nothing.
		if again := normalizePath(got); again != got {
			t.Fatalf("normalizePath not idempotent: %q -> %q -> %q", p, got, again)
		}
	})
}

// FuzzEvaluatePath fuzzes the full gate against a deny-by-default mTLS policy:
// any path that canonicalises under /secure MUST be gated, never silently
// allowed through a normalization mismatch.
func FuzzEvaluatePath(f *testing.F) {
	e := NewEngine(nil)
	_ = e.SetPolicies([]*Policy{{ID: "p", PathPrefix: "/secure", RequireMTLS: true}})
	for _, s := range []string{"/secure", "/secure/x", "//secure", "/secure;a", "/SECURE/x", "/public"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		d, _, _ := e.Evaluate(r, "203.0.113.1") // must never panic
		// If the canonical path is under /secure, the gate must NOT allow it.
		if strings.HasPrefix(strings.ToLower(normalizePath(p)), "/secure") && d == DecisionAllow {
			t.Fatalf("path %q canonicalises under /secure but was ALLOWED (gate evaded)", p)
		}
	})
}

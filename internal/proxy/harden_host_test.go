package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHardenHostSyntax covers the Host authority-syntax check: a Host is
// host[:port] (or [v6]:port), so injection/smuggling characters in it are
// rejected. Defense-in-depth against Host-header injection / absolute-URI
// smuggling / deceptive-userinfo tricks.
func TestHardenHostSyntax(t *testing.T) {
	bad := []string{
		"evil.com/reset",  // absolute-URI / path in Host
		"a@evil.com",      // deceptive userinfo
		"evil.com victim", // space
		"evil.com;x=1",    // matrix/param
		"host\\path",      // backslash
		"a,b",             // multiple hosts
		"evil.com?x",      // query in Host
		"evil.com#frag",   // fragment in Host
	}
	for _, h := range bad {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = h
		v := evaluateHardening(r)
		if !v.Reject || v.RuleID != "HARDEN-HOST-SYNTAX" {
			t.Errorf("Host %q: reject=%v rule=%q, want reject HARDEN-HOST-SYNTAX", h, v.Reject, v.RuleID)
		}
	}
	good := []string{
		"example.com",
		"example.com:8443",
		"192.0.2.1:80",
		"[2001:db8::1]:443",
		"sub.api.example.com",
		"host_name", // underscore is tolerated (some internal hosts use it)
	}
	for _, h := range good {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = h
		if v := evaluateHardening(r); v.Reject {
			t.Errorf("legit Host %q rejected: %s (%s)", h, v.Reason, v.RuleID)
		}
	}
}

package setup

import (
	"context"
	"net"
	"testing"
)

func TestGuardProbeDomain(t *testing.T) {
	cases := map[string]bool{ // input -> should be rejected
		"":                true,
		"example.com":     false,
		"sub.example.org": false,
		"127.0.0.1":       true, // literal IP rejected
		"10.0.0.5":        true,
		"169.254.169.254": true,
		"[::1]":           true,
		"2606:4700::1111": true,
	}
	for in, reject := range cases {
		if got := guardProbeDomain(in) != ""; got != reject {
			t.Errorf("guardProbeDomain(%q): rejected=%v, want %v", in, got, reject)
		}
	}
}

func TestIsInternalIP(t *testing.T) {
	internal := []string{
		"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "::1", "fd00::1", "0.0.0.0",
	}
	external := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5", "2606:4700:4700::1111"}
	for _, s := range internal {
		if !isInternalIP(net.ParseIP(s)) {
			t.Errorf("%s should be classified internal", s)
		}
	}
	for _, s := range external {
		if isInternalIP(net.ParseIP(s)) {
			t.Errorf("%s should be classified external", s)
		}
	}
	if !isInternalIP(nil) {
		t.Errorf("nil IP should be treated as internal (fail closed)")
	}
}

// TestCheckDNSRejectsSSRFTargets confirms the DNS setup check refuses literal
// IP targets and domains that resolve to internal addresses, closing the SSRF
// oracle on the authenticated /api/setup/checks/dns endpoint.
func TestCheckDNSRejectsSSRFTargets(t *testing.T) {
	c := &Checker{}
	if r := c.CheckDNS(context.Background(), "169.254.169.254", ""); r.Status != StatusFail {
		t.Fatalf("literal metadata IP should fail, got %v (%s)", r.Status, r.Message)
	}
	// localhost resolves to loopback -> internal -> must fail (and must not
	// reflect the resolved addresses).
	r := c.CheckDNS(context.Background(), "localhost", "")
	if r.Status != StatusFail {
		t.Fatalf("localhost should fail as internal, got %v (%s)", r.Status, r.Message)
	}
	if _, ok := r.Detail["resolved"]; ok {
		t.Fatalf("internal-resolving domain must not reflect resolved addresses")
	}
}

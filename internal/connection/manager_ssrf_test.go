package connection

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTargetDisallowed is the core of the CONN-SSRF-001 fix: cloud-metadata
// endpoints are always blocked; private/loopback/link-local are blocked only
// when the operator opts in (so the common localhost/RFC1918 backend keeps
// working by default); public IPs are always allowed.
func TestTargetDisallowed(t *testing.T) {
	metadata := []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"}
	for _, s := range metadata {
		if targetDisallowed(net.ParseIP(s), false) == "" {
			t.Errorf("metadata IP %s must be blocked even when private targets are allowed", s)
		}
		if targetDisallowed(net.ParseIP(s), true) == "" {
			t.Errorf("metadata IP %s must be blocked when private targets are blocked", s)
		}
	}

	// blockPrivate=false: only metadata is blocked; a local/private backend is OK.
	for _, s := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.10", "::1", "fd00::1", "8.8.8.8"} {
		if reason := targetDisallowed(net.ParseIP(s), false); reason != "" {
			t.Errorf("with blockPrivate=false, %s should be allowed, got %q", s, reason)
		}
	}

	// blockPrivate=true: internal ranges blocked, public still allowed.
	blocked := []string{"127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "::1", "fd00::1", "169.254.0.1"}
	for _, s := range blocked {
		if targetDisallowed(net.ParseIP(s), true) == "" {
			t.Errorf("with blockPrivate=true, %s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if reason := targetDisallowed(net.ParseIP(s), true); reason != "" {
			t.Errorf("public IP %s should be allowed even with blockPrivate=true, got %q", s, reason)
		}
	}
}

func TestValidBackendURL(t *testing.T) {
	for _, s := range []string{"http://x", "https://example.com", "https://10.0.0.1:8080/health"} {
		if !validBackendURL(s) {
			t.Errorf("%q should be a valid backend URL", s)
		}
	}
	for _, s := range []string{"", "file:///etc/passwd", "gopher://x", "ftp://x", "not a url", "://nohost", "http://"} {
		if validBackendURL(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
}

// TestUpdateConfigRejectsNonHTTPScheme proves the admin/ypanel config path can't
// point the probe at a file:// (or other non-http) target.
func TestUpdateConfigRejectsNonHTTPScheme(t *testing.T) {
	m := NewManager(Config{BackendURL: "http://good.example", TimeoutMs: 500})
	m.UpdateConfig(Config{BackendURL: "file:///etc/passwd"})
	if got := m.ConfigSnapshot().BackendURL; got != "http://good.example" {
		t.Fatalf("non-http backend_url should have been rejected; BackendURL=%q", got)
	}
	// A valid http(s) patch still applies.
	m.UpdateConfig(Config{BackendURL: "https://new.example"})
	if got := m.ConfigSnapshot().BackendURL; got != "https://new.example" {
		t.Fatalf("valid backend_url should apply; BackendURL=%q", got)
	}
}

// TestProbeGuardBlocksLoopbackWhenPolicySet proves the dial guard is wired and
// policy-gated: a reachable loopback backend is refused when blockPrivate is on,
// and reached when it is off.
func TestProbeGuardBlocksLoopbackWhenPolicySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager(Config{BackendURL: srv.URL, TimeoutMs: 2000})

	// Policy ON: the loopback target is blocked at dial time → not connected,
	// even though the server is up.
	m.SetSSRFPolicy(true)
	if st := m.Probe(context.Background()); st.Connected {
		t.Fatal("loopback probe should be blocked when blockPrivate is set (CONN-SSRF-001)")
	}

	// Policy OFF (default): a local backend is legitimately reachable.
	m.SetSSRFPolicy(false)
	if st := m.Probe(context.Background()); !st.Connected {
		t.Fatal("loopback backend should be reachable when blockPrivate is off (local-backend use case)")
	}
}

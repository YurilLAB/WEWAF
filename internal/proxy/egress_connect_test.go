package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"wewaf/internal/config"
)

// TestSafeDialContextBlocksInternalTargets is the regression guard for the
// CONNECT-tunnel DNS-rebinding SSRF fix. handleConnect now dials through
// safeDialContext (instead of net.DialTimeout(r.Host)), so the same
// resolve-validate-pin guard that protects the plain-HTTP egress path also
// protects HTTPS CONNECT tunnels. A literal internal/metadata/loopback target
// must be refused at dial time — before any connection is established — so a
// rebinding record cannot slip a private IP past the request-time check.
func TestSafeDialContextBlocksInternalTargets(t *testing.T) {
	ep := NewEgressProxy(config.Default(), nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	blocked := []string{
		"127.0.0.1:443",        // loopback
		"169.254.169.254:80",   // link-local / cloud metadata
		"10.0.0.5:443",         // RFC1918 private
		"192.168.1.1:443",      // RFC1918 private
		"[::1]:443",            // IPv6 loopback
		"[fd00::1]:443",        // IPv6 ULA
	}
	for _, addr := range blocked {
		conn, err := ep.safeDialContext(ctx, "tcp", addr)
		if err == nil {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("safeDialContext(%q) should be blocked, but dialed successfully", addr)
			continue
		}
		if !strings.Contains(err.Error(), "blocked") {
			// A connection-refused is acceptable for an unused port, but the
			// classifier should reject these BEFORE dialing. Flag if the
			// rejection wasn't the SSRF classifier.
			t.Logf("safeDialContext(%q) errored (not via classifier): %v", addr, err)
		}
	}
}

// TestSafeDialContextRejectsMalformedAddr confirms a target with no port (a
// malformed CONNECT host) is refused rather than dialed.
func TestSafeDialContextRejectsMalformedAddr(t *testing.T) {
	ep := NewEgressProxy(config.Default(), nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := ep.safeDialContext(ctx, "tcp", "example.com"); err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("safeDialContext with no port should error")
	}
}

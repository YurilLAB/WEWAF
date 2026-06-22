package proxy

import (
	"context"
	"net"
	"strings"
	"testing"

	"wewaf/internal/config"
)

// TestSafeDialBlocksInternalAtDialTime is the regression for the egress
// DNS-rebinding SSRF: the dial now re-classifies the exact IP it connects to,
// so an internal / metadata destination is refused at dial time regardless of
// what an earlier resolution returned. Uses literal IPs so resolution is
// deterministic and no external network is needed.
func TestSafeDialBlocksInternalAtDialTime(t *testing.T) {
	ep := NewEgressProxy(&config.Config{EgressBlockPrivateIPs: true}, nil, nil, nil)
	blocked := []string{
		"169.254.169.254:80", // cloud metadata
		"127.0.0.1:80",       // loopback
		"10.0.0.5:80",        // private
		"192.168.1.1:443",    // private
		"[::1]:80",           // loopback v6
	}
	for _, addr := range blocked {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			conn, err := ep.safeDial(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				t.Fatalf("safeDial connected to internal address %s (SSRF guard bypassed)", addr)
			}
			if !strings.Contains(err.Error(), "blocked dial") {
				t.Fatalf("expected a block error for %s, got: %v", addr, err)
			}
		})
	}
}

// TestSafeDialAllowsValidatedPublicTarget confirms the pinned dialer still
// connects to a legitimate destination — modelled with a local listener and
// EgressBlockPrivateIPs off (the operator opted out of IP classification), so
// the loopback listener stands in for any reachable host.
func TestSafeDialAllowsValidatedPublicTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			c.Close()
		}
	}()

	ep := NewEgressProxy(&config.Config{EgressBlockPrivateIPs: false}, nil, nil, nil)
	conn, err := ep.safeDial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("safeDial to legitimate target failed: %v", err)
	}
	conn.Close()
}

// TestSafeDialPrivateAllowedWhenClassificationOff confirms that with
// EgressBlockPrivateIPs off, safeDial does not reject a private IP (it only
// pins the dial) — preserving the operator's opt-out.
func TestSafeDialPrivateAllowedWhenClassificationOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, e := ln.Accept(); e == nil {
			c.Close()
		}
	}()
	ep := NewEgressProxy(&config.Config{EgressBlockPrivateIPs: false}, nil, nil, nil)
	conn, err := ep.safeDial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("safeDial should allow loopback when classification is off: %v", err)
	}
	conn.Close()
}

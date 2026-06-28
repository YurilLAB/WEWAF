package proxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestHardenHTTP2ConfiguresServer asserts the explicit HTTP/2 limits are
// installed (P4c): ConfigureServer registers the h2 protocol handler in
// TLSNextProto, which is what stops net/http from auto-configuring HTTP/2 with
// unowned runtime defaults.
func TestHardenHTTP2ConfiguresServer(t *testing.T) {
	srv := &http.Server{TLSConfig: &tls.Config{}, IdleTimeout: 0}
	if err := HardenHTTP2(srv, 64); err != nil {
		t.Fatalf("HardenHTTP2: %v", err)
	}
	if srv.TLSNextProto["h2"] == nil {
		t.Fatal("expected h2 handler registered in TLSNextProto after HardenHTTP2")
	}

	// Default path (0 -> DefaultH2MaxConcurrentStreams) must also succeed.
	srv2 := &http.Server{TLSConfig: &tls.Config{}}
	if err := HardenHTTP2(srv2, 0); err != nil {
		t.Fatalf("HardenHTTP2 default: %v", err)
	}
	if srv2.TLSNextProto["h2"] == nil {
		t.Fatal("expected h2 handler registered with default stream cap")
	}
}

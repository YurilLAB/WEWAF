package clientip

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func newReq(remoteAddr string, xff, xri string) *http.Request {
	r := &http.Request{
		Header:     make(http.Header),
		RemoteAddr: remoteAddr,
	}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xri != "" {
		r.Header.Set("X-Real-Ip", xri)
	}
	return r
}

// TestTrustXFFOff documents that with trust_xff=false the extractor
// always returns the TCP peer, regardless of any spoofed headers.
func TestTrustXFFOff(t *testing.T) {
	e, err := New(false, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("203.0.113.10:54321", "1.2.3.4, 5.6.7.8", "9.9.9.9")
	if got := e.ClientIP(r); got != "203.0.113.10" {
		t.Fatalf("trustXFF=false should return peer, got %q", got)
	}
}

// TestLegacyMode confirms that trust_xff=true with no trusted_proxies
// preserves left-most behaviour for backwards compatibility.
func TestLegacyMode(t *testing.T) {
	e, err := New(true, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("203.0.113.10:54321", "1.2.3.4, 5.6.7.8", "")
	if got := e.ClientIP(r); got != "1.2.3.4" {
		t.Fatalf("legacy mode should return left-most, got %q", got)
	}
	r2 := newReq("203.0.113.10:54321", "", "9.9.9.9")
	if got := e.ClientIP(r2); got != "9.9.9.9" {
		t.Fatalf("legacy mode should fall back to X-Real-Ip, got %q", got)
	}
}

// TestUntrustedPeerSpoof — the key bug. Attacker bypasses the CDN and
// connects directly with a forged XFF. Extractor must return the
// attacker's actual peer IP, NOT the spoofed value.
func TestUntrustedPeerSpoof(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("198.51.100.55:44444", "1.2.3.4", "9.9.9.9")
	if got := e.ClientIP(r); got != "198.51.100.55" {
		t.Fatalf("untrusted peer must not honour XFF, got %q", got)
	}
}

// TestTrustedPeerSingleHop — peer is a CDN egress IP, real client sits
// in XFF.
func TestTrustedPeerSingleHop(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:54321", "203.0.113.50", "")
	if got := e.ClientIP(r); got != "203.0.113.50" {
		t.Fatalf("trusted peer should return XFF entry, got %q", got)
	}
}

// TestTrustedPeerMultiHopForgeryAttempt — attacker sends through the
// CDN with a forged left-most XFF entry. The CDN appends its own
// upstream IP to XFF as it forwards. We must skip the CDN hop and
// return the actual untrusted entry, not the attacker's forgery.
func TestTrustedPeerMultiHopForgeryAttempt(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// XFF from forged-leftmost (attacker injected) to closest hop:
	//   "evil-spoof, real-client, internal-proxy"
	// where internal-proxy and the peer are both inside trusted CIDRs.
	r := newReq("172.16.5.5:54321", "1.2.3.4, 203.0.113.99, 10.0.0.7", "")
	if got := e.ClientIP(r); got != "203.0.113.99" {
		t.Fatalf("multi-hop: should return rightmost-untrusted, got %q", got)
	}
}

// TestTrustedPeerAllHopsTrusted — health checker / internal traffic
// that genuinely originated inside the trusted set.
func TestTrustedPeerAllHopsTrusted(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:54321", "10.0.0.99, 10.0.0.7", "")
	if got := e.ClientIP(r); got != "10.0.0.99" {
		t.Fatalf("all-trusted hops: should fall back to left-most, got %q", got)
	}
}

// TestIPv6Peer covers the IPv6 SplitHostPort path that the previous
// hand-rolled LastIndexByte parsers got wrong.
func TestIPv6Peer(t *testing.T) {
	e, err := New(true, []string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("[2001:db8::1]:54321", "203.0.113.77", "")
	if got := e.ClientIP(r); got != "203.0.113.77" {
		t.Fatalf("IPv6 trusted peer: %q", got)
	}
	// Same peer, no XFF — should return the bracketed IPv6 sans port.
	r2 := newReq("[2001:db8::1]:54321", "", "")
	if got := e.ClientIP(r2); got != "2001:db8::1" {
		t.Fatalf("IPv6 peer without XFF: %q", got)
	}
}

// TestBareIPInTrustedProxies — operators commonly configure a single
// proxy IP without thinking about CIDR suffixes; the parser should
// promote it to a /32 (or /128) automatically.
func TestBareIPInTrustedProxies(t *testing.T) {
	e, err := New(true, []string{"10.0.0.5", "2001:db8::1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:1234", "203.0.113.10", "")
	if got := e.ClientIP(r); got != "203.0.113.10" {
		t.Fatalf("bare IPv4 should be promoted to /32: %q", got)
	}
	r2 := newReq("[2001:db8::1]:1234", "203.0.113.20", "")
	if got := e.ClientIP(r2); got != "203.0.113.20" {
		t.Fatalf("bare IPv6 should be promoted to /128: %q", got)
	}
	// A neighbour IP that ISN'T in the bare list must NOT be trusted.
	r3 := newReq("10.0.0.6:1234", "1.2.3.4", "")
	if got := e.ClientIP(r3); got != "10.0.0.6" {
		t.Fatalf("neighbour IP must not be trusted: %q", got)
	}
}

// TestInvalidCIDRRejected ensures bad config is loud at startup, not
// silently dropped at runtime.
func TestInvalidCIDRRejected(t *testing.T) {
	if _, err := New(true, []string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if _, err := New(true, []string{"10.0.0.0/99"}); err == nil {
		t.Fatal("expected error for /99")
	}
}

// TestUpdateHotReload — Update swaps in a new policy without losing
// concurrent reads.
func TestUpdateHotReload(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:1234", "203.0.113.5", "")
	if got := e.ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("pre-update: %q", got)
	}
	if err := e.Update(true, []string{"172.16.0.0/12"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// Same request: the previously-trusted peer is no longer trusted.
	if got := e.ClientIP(r); got != "10.0.0.5" {
		t.Fatalf("post-update: should ignore XFF for now-untrusted peer, got %q", got)
	}
}

// TestNilSafety — the extractor is plumbed through several layers and
// callers should not have to nil-check. A nil extractor degrades to
// "trust nothing": peer IP is returned, headers are ignored.
func TestNilSafety(t *testing.T) {
	var e *Extractor
	r := newReq("203.0.113.10:1234", "1.2.3.4", "9.9.9.9")
	if got := e.ClientIP(r); got != "203.0.113.10" {
		t.Fatalf("nil extractor must return peer (ignoring spoofed headers), got %q", got)
	}
	if e.TrustXFF() {
		t.Fatal("nil extractor TrustXFF should be false")
	}
	if e.HasTrustedProxies() {
		t.Fatal("nil extractor HasTrustedProxies should be false")
	}
	if e.IsTrustedPeer(r) {
		t.Fatal("nil extractor IsTrustedPeer should be false")
	}
	// Nil request is also safe.
	if got := e.ClientIP(nil); got != "" {
		t.Fatalf("nil request: %q", got)
	}
}

// TestIsTLSRequest_DirectTLSAlwaysHonoured — when the listener
// presents a real TLS state, the request is TLS regardless of trust
// policy. This branch can never be spoofed because r.TLS is set by
// the Go runtime, not the client.
func TestIsTLSRequest_DirectTLSAlwaysHonoured(t *testing.T) {
	e, _ := New(false, nil) // even with trust_xff off
	r := newReq("198.51.100.55:1234", "", "")
	r.TLS = &tls.ConnectionState{} // pretend the runtime accepted TLS
	if !e.IsTLSRequest(r) {
		t.Fatal("direct TLS must always count as TLS")
	}
}

// TestIsTLSRequest_UntrustedPeerCannotForge — the bypass class this
// helper closes. Attacker hits the WAF directly with X-Forwarded-Proto
// set; they must NOT be treated as TLS, otherwise the cookie layer
// would issue Secure cookies that the attacker captures plaintext on
// the next request.
func TestIsTLSRequest_UntrustedPeerCannotForge(t *testing.T) {
	e, _ := New(true, []string{"10.0.0.0/8"})
	r := newReq("198.51.100.55:1234", "", "")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Ssl", "on")
	if e.IsTLSRequest(r) {
		t.Fatal("untrusted peer must not be able to forge TLS via X-Forwarded-Proto")
	}
}

// TestIsTLSRequest_TrustedPeerHonoured — a legitimate edge proxy in
// the configured CIDR can announce HTTPS via X-Forwarded-Proto.
func TestIsTLSRequest_TrustedPeerHonoured(t *testing.T) {
	e, _ := New(true, []string{"10.0.0.0/8"})
	r := newReq("10.0.0.5:1234", "", "")
	r.Header.Set("X-Forwarded-Proto", "https")
	if !e.IsTLSRequest(r) {
		t.Fatal("trusted peer with X-Forwarded-Proto: https must count as TLS")
	}
	r2 := newReq("10.0.0.6:1234", "", "")
	r2.Header.Set("X-Forwarded-Ssl", "on")
	if !e.IsTLSRequest(r2) {
		t.Fatal("trusted peer with X-Forwarded-Ssl: on must count as TLS")
	}
}

// TestIsTLSRequest_LegacyTrustAll — back-compat: when trust_xff is on
// and no CIDRs are configured (legacy single-CDN deployments), every
// upstream is treated as trusted, matching the existing left-most
// XFF behaviour the trust gate inherits.
func TestIsTLSRequest_LegacyTrustAll(t *testing.T) {
	e, _ := New(true, nil)
	r := newReq("203.0.113.7:1234", "", "")
	r.Header.Set("X-Forwarded-Proto", "https")
	if !e.IsTLSRequest(r) {
		t.Fatal("legacy trust-all mode must still honour X-Forwarded-Proto")
	}
}

// TestEmptyXFFEntries — some proxies emit "client, , next" with empty
// elements; we must skip them rather than mistake an empty string for
// a real hop.
func TestEmptyXFFEntries(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:1234", "203.0.113.5, , 10.0.0.6", "")
	if got := e.ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("empty hop handling: %q", got)
	}
}

// TestBracketedIPv6InXFF — RFC 7239 examples bracket IPv6 entries.
func TestBracketedIPv6InXFF(t *testing.T) {
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:1234", "[2001:db8::abcd]", "")
	if got := e.ClientIP(r); got != "2001:db8::abcd" {
		t.Fatalf("bracketed IPv6 in XFF should strip brackets: %q", got)
	}
}

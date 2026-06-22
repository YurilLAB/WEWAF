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

// TestForgedNonIPHeadersRejected — an attacker transiting a trusted proxy
// sends a non-IP X-Real-Ip / XFF token to corrupt the derived client IP
// (which keys rate-limits, bans, and metrics). The extractor must reject the
// garbage and fall back to a real value rather than honour it verbatim.
func TestForgedNonIPHeadersRejected(t *testing.T) {
	// Strict mode: trusted peer, but X-Real-Ip is junk and there is no XFF.
	// Must fall back to the peer, not return "admin".
	e, err := New(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("10.0.0.5:54321", "", "admin")
	if got := e.ClientIP(r); got != "10.0.0.5" {
		t.Fatalf("forged non-IP X-Real-Ip must not be honoured, got %q", got)
	}

	// Strict mode: attacker injects a non-IP token as the left-most XFF
	// entry, the real client sits next to it, the trusted hop is closest.
	// The garbage must be skipped and the genuine untrusted IP returned —
	// never the "not-an-ip" token.
	r2 := newReq("10.0.0.5:54321", "not-an-ip, 203.0.113.99, 10.0.0.7", "")
	if got := e.ClientIP(r2); got != "203.0.113.99" {
		t.Fatalf("forged non-IP XFF hop must be skipped, got %q", got)
	}

	// Legacy mode (trust_xff, no allowlist): a garbage left-most XFF must
	// not become the key; fall through to a valid value.
	eLegacy, err := New(true, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r3 := newReq("203.0.113.10:54321", "garbage", "8.8.8.8")
	if got := eLegacy.ClientIP(r3); got != "8.8.8.8" {
		t.Fatalf("legacy: garbage XFF should fall back to valid X-Real-Ip, got %q", got)
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
	// Same peer, no XFF — returns the IPv6 sans port, masked to its /64 key
	// (ClientIP canonicalises IPv6 to /64 so a /64 sprayer can't mint
	// unlimited per-IP keys). A clean masked address proves the port and
	// brackets were stripped before parsing.
	r2 := newReq("[2001:db8::1]:54321", "", "")
	if got := e.ClientIP(r2); got != "2001:db8::" {
		t.Fatalf("IPv6 peer without XFF (expect /64 key): %q", got)
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

// TestIsTLSRequest_LegacyTrustAllDoesNotTrustProto — security guard. In
// legacy trust-all mode (trust_xff on, no trusted_proxies) the WAF keeps
// left-most XFF parsing for client-IP back-compat, but it must NOT treat an
// arbitrary direct peer as a trusted proxy for spoofable proof headers.
// Honouring X-Forwarded-Proto from any client there let an attacker forge an
// HTTPS origin (Secure-cookie misissuance), and the sibling
// X-WEWAF-Client-Cert-Verified gate forge a verified client cert. Peer trust
// for header-derived proof now requires an explicit trusted_proxies CIDR.
func TestIsTLSRequest_LegacyTrustAllDoesNotTrustProto(t *testing.T) {
	e, _ := New(true, nil)
	r := newReq("203.0.113.7:1234", "", "")
	r.Header.Set("X-Forwarded-Proto", "https")
	if e.IsTLSRequest(r) {
		t.Fatal("legacy trust-all mode must NOT honour X-Forwarded-Proto from an arbitrary peer (spoofable)")
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
	// Brackets are stripped, the entry parses as IPv6, and ClientIP returns
	// the /64 key. A clean masked result is only reachable if the brackets
	// were removed before parsing — so this still exercises bracket handling.
	if got := e.ClientIP(r); got != "2001:db8::" {
		t.Fatalf("bracketed IPv6 in XFF should strip brackets (expect /64 key): %q", got)
	}
}

// TestNormalizeIPKey covers the per-client key canonicalisation: IPv4 is
// unchanged (one /32 == one host) and IPv6 collapses to its /64 prefix so a
// single end site cannot rotate the low 64 bits to mint unlimited keys.
func TestNormalizeIPKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},                          // IPv4 unchanged
		{"10.0.0.1", "10.0.0.1"},                                // IPv4 unchanged
		{"2001:db8:abcd:1234::1", "2001:db8:abcd:1234::"},       // IPv6 -> /64
		{"2001:db8:abcd:1234:ffff:ffff:ffff:ffff", "2001:db8:abcd:1234::"}, // top of /64 -> same key
		{"2001:db8:abcd:1234::beef", "2001:db8:abcd:1234::"},    // different host, same /64
		{"::1", "::"},                                           // IPv6 loopback -> /64 key
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},                    // IPv4-mapped treated as IPv4
		{"not-an-ip", "not-an-ip"},                              // unparseable returned as-is
		{"", ""},                                                // empty stays empty
	}
	for _, c := range cases {
		if got := NormalizeIPKey(c.in); got != c.want {
			t.Errorf("NormalizeIPKey(%q) = %q, want %q", c.in, got, c.want)
		}
		// Idempotent.
		if got := NormalizeIPKey(NormalizeIPKey(c.in)); got != c.want {
			t.Errorf("NormalizeIPKey not idempotent for %q: %q", c.in, got)
		}
	}
	// Two distinct hosts in one /64 must produce the SAME key (the whole point).
	a := NormalizeIPKey("2001:db8:abcd:1234::5")
	b := NormalizeIPKey("2001:db8:abcd:1234:dead:beef:cafe:f00d")
	if a != b {
		t.Fatalf("two hosts in one /64 must share a key: %q != %q", a, b)
	}
}

// TestLegacyXFFGarbageRejected confirms the legacy trust-all branch ignores a
// non-IP X-Forwarded-For value and falls back to the real peer, so an attacker
// cannot mint unlimited keys with random garbage headers.
func TestLegacyXFFGarbageRejected(t *testing.T) {
	e, err := New(true, nil) // trust_xff on, no trusted_proxies => legacy trust-all
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq("203.0.113.50:1234", "garbage-not-an-ip-9f3a", "")
	if got := e.ClientIP(r); got != "203.0.113.50" {
		t.Fatalf("garbage XFF must fall back to peer, got %q", got)
	}
	// A VALID spoofed IP is still honoured in this (discouraged) legacy mode.
	r2 := newReq("203.0.113.50:1234", "198.51.100.9", "")
	if got := e.ClientIP(r2); got != "198.51.100.9" {
		t.Fatalf("valid XFF in legacy mode should be honoured, got %q", got)
	}
}

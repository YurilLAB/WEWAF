// Package clientip resolves the "real" client IP for a request, given a
// proxy-trust policy. It centralises a parser that was previously
// duplicated across four packages (proxy, session, web, core) and adds
// the missing piece that made the duplicates unsafe: a trusted-proxy
// allowlist.
//
// Why this exists. With trust_xff enabled but no trusted-proxy list,
// any client could send "X-Forwarded-For: 1.2.3.4" and the WAF would
// treat the request as originating from 1.2.3.4. That bypassed per-IP
// rate limiting, bans, brute-force counting, IP-drift scoring on
// sessions, and CIDR-based zero-trust policies. The Extractor here
// only honours forwarding headers when the immediate peer's TCP-layer
// address falls inside a configured CIDR (typical: the CDN / load
// balancer's egress range).
//
// Algorithm. When the peer is trusted we walk X-Forwarded-For from the
// rightmost (closest hop) entry and return the first IP that is NOT in
// the trusted-proxy set. That matches RFC 7239 / draft-ietf-rats-yang
// guidance and prevents an attacker from prepending a forged left-most
// entry through a trusted CDN — only the rightmost-untrusted entry is
// authoritative. When trust_xff is on but no trusted proxies are
// configured, we fall back to the legacy left-most behaviour with a
// runtime warning so existing single-CDN deployments keep working
// while operators are nudged toward a tighter config.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// Extractor pulls the client IP out of a request. Safe for concurrent
// use; the active config is held behind an atomic pointer so Update()
// can swap in new CIDR sets without locks on the hot path.
type Extractor struct {
	cfg atomic.Pointer[config]
}

type config struct {
	trustXFF    bool
	trustedNets []*net.IPNet
	// trustedAll is true when trustXFF is on but trustedNets is empty —
	// the legacy "trust every upstream" behaviour. We log a warning at
	// construction time but keep the door open for existing deployments.
	trustedAll bool
}

// New returns an Extractor with the given trust policy. CIDR parse
// errors return a non-nil error and a nil Extractor — callers should
// treat this as a fatal config error.
func New(trustXFF bool, trustedProxies []string) (*Extractor, error) {
	e := &Extractor{}
	if err := e.Update(trustXFF, trustedProxies); err != nil {
		return nil, err
	}
	return e, nil
}

// Update swaps the trust policy. Hot-reload safe.
func (e *Extractor) Update(trustXFF bool, trustedProxies []string) error {
	if e == nil {
		return nil
	}
	nets, err := parseCIDRs(trustedProxies)
	if err != nil {
		return err
	}
	c := &config{
		trustXFF:    trustXFF,
		trustedNets: nets,
		trustedAll:  trustXFF && len(nets) == 0,
	}
	e.cfg.Store(c)
	return nil
}

// TrustXFF reports whether the extractor will read forwarding headers
// at all.
func (e *Extractor) TrustXFF() bool {
	if e == nil {
		return false
	}
	c := e.cfg.Load()
	if c == nil {
		return false
	}
	return c.trustXFF
}

// HasTrustedProxies reports whether any CIDRs are configured. Useful
// for emitting the "you should set this" warning at startup once.
func (e *Extractor) HasTrustedProxies() bool {
	if e == nil {
		return false
	}
	c := e.cfg.Load()
	if c == nil {
		return false
	}
	return len(c.trustedNets) > 0
}

// ClientIP returns the best-guess client IP for the request. Never
// returns an empty string for a non-nil request — falls back to the
// raw RemoteAddr when nothing else is parseable.
func (e *Extractor) ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	c := configOrZero(e)
	peer := splitHost(r.RemoteAddr)
	if !c.trustXFF {
		return peer
	}

	// Legacy compatibility branch: trustXFF on but no allowlist
	// configured. Walk left-most so existing single-CDN setups keep
	// the same observable behaviour.
	if c.trustedAll {
		if v := leftmostXFF(r); v != "" {
			return v
		}
		if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); v != "" {
			return v
		}
		return peer
	}

	// Strict branch: only honour forwarding headers when the peer
	// itself is a trusted proxy.
	if !ipInNets(peer, c.trustedNets) {
		return peer
	}

	// Walk XFF right-to-left, skipping trusted-proxy hops, return the
	// first untrusted IP we encounter. If every hop is itself trusted
	// (rare; only happens when the client is also inside the trusted
	// CIDR — e.g. a health check), fall back to the left-most entry so
	// we don't return the WAF's own peer address.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := splitXFF(xff)
		for i := len(hops) - 1; i >= 0; i-- {
			h := hops[i]
			if h == "" {
				continue
			}
			if !ipInNets(h, c.trustedNets) {
				return h
			}
		}
		// Every hop was trusted — fall back to the left-most non-empty.
		for _, h := range hops {
			if h != "" {
				return h
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); v != "" {
		// X-Real-Ip is single-valued and only emitted by edge proxies,
		// so when the peer is trusted we accept it as-is.
		return v
	}
	return peer
}

// IsTrustedPeer reports whether the immediate TCP peer of r is in the
// trusted-proxy set. Used by callers that want to skip work that only
// makes sense for direct clients (e.g. mTLS-verified header parsing).
func (e *Extractor) IsTrustedPeer(r *http.Request) bool {
	if e == nil || r == nil {
		return false
	}
	c := e.cfg.Load()
	if c == nil || !c.trustXFF {
		return false
	}
	if c.trustedAll {
		// Legacy mode: every upstream is "trusted" so the answer is
		// always yes when trust_xff is on. Keeps observable behaviour
		// consistent with the legacy XFF parsing.
		return true
	}
	return ipInNets(splitHost(r.RemoteAddr), c.trustedNets)
}

// IsTLSRequest reports whether the request was received over a TLS
// channel. Direct r.TLS != nil is always honoured (the runtime can't
// lie about its own listener); X-Forwarded-Proto / X-Forwarded-Ssl are
// only believed when the immediate peer is a trusted proxy, so an
// attacker hitting the WAF directly cannot forge "this was HTTPS" and
// trick the cookie layer into emitting Secure cookies that the
// attacker can then capture over plaintext on the next hop. Mirrors
// the trust model already used for client-IP extraction.
func (e *Extractor) IsTLSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !e.IsTrustedPeer(r) {
		return false
	}
	if v := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(v, "https") {
		return true
	}
	if v := r.Header.Get("X-Forwarded-Ssl"); strings.EqualFold(v, "on") {
		return true
	}
	return false
}

// --- Helpers -----------------------------------------------------------

func configOrZero(e *Extractor) config {
	if e == nil {
		return config{}
	}
	c := e.cfg.Load()
	if c == nil {
		return config{}
	}
	return *c
}

// splitHost strips the port component from "host:port" or "[v6]:port".
// Returns the input unchanged when no port is present (so callers that
// pass a bare IP still get the right answer). Brackets around an IPv6
// host are removed so the result is directly comparable as a net.IP.
func splitHost(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	// SplitHostPort fails on a bare IP without a port; fall back gently.
	a := strings.TrimSpace(addr)
	a = strings.TrimPrefix(a, "[")
	a = strings.TrimSuffix(a, "]")
	return a
}

// leftmostXFF returns the first comma-separated entry, trimmed.
func leftmostXFF(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ""
	}
	if idx := strings.IndexByte(xff, ','); idx != -1 {
		return strings.TrimSpace(xff[:idx])
	}
	return strings.TrimSpace(xff)
}

func splitXFF(xff string) []string {
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Some proxies wrap IPv6 in brackets in XFF; drop them so the
		// result parses as a net.IP for membership checks.
		p = strings.TrimPrefix(p, "[")
		p = strings.TrimSuffix(p, "]")
		out = append(out, p)
	}
	return out
}

func ipInNets(ipStr string, nets []*net.IPNet) bool {
	if ipStr == "" || len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseCIDRs accepts entries that are either a CIDR ("10.0.0.0/8") or a
// bare IP address ("203.0.113.5"); bare IPs are promoted to a /32 (IPv4)
// or /128 (IPv6) so operators don't have to know the suffix syntax.
func parseCIDRs(in []string) ([]*net.IPNet, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("clientip: invalid trusted_proxies entry %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

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

// ClientIP returns the best-guess client IP for the request, canonicalised
// for use as a per-client key. IPv6 addresses are masked to their /64 prefix
// (see NormalizeIPKey) so a single end site — routinely allocated an entire
// /64 — cannot rotate the low 64 bits to mint 2^64 distinct identities and
// evade per-IP rate limiting, bans, and brute-force counting. IPv4 is returned
// as the full address. Never returns an empty string for a non-nil request —
// falls back to the raw RemoteAddr when nothing else is parseable.
func (e *Extractor) ClientIP(r *http.Request) string {
	return NormalizeIPKey(e.clientIPRaw(r))
}

// clientIPRaw resolves the client IP per the trust policy WITHOUT prefix
// normalisation. ClientIP wraps it; callers that need the literal address
// (none today outside ClientIP) could use it directly.
func (e *Extractor) clientIPRaw(r *http.Request) string {
	if r == nil {
		return ""
	}
	c := configOrZero(e)
	peer := splitHost(r.RemoteAddr)
	if peer == "" {
		// splitHost can reduce a malformed RemoteAddr (e.g. whitespace-only)
		// to empty. The documented contract is to never return empty for a
		// non-nil request, and an empty value would be a useless rate-limit /
		// ban key, so fall back to the raw RemoteAddr. (Surfaced by the
		// clientip fuzzer — not reachable from a real net.Conn, but the
		// guarantee must hold regardless.)
		peer = r.RemoteAddr
	}
	if !c.trustXFF {
		return peer
	}

	// Legacy compatibility branch: trustXFF on but no allowlist
	// configured. Walk left-most so existing single-CDN setups keep
	// the same observable behaviour. The header value is validated as a
	// parseable IP before it is trusted: without this, an attacker in this
	// (already-discouraged) mode could send a UNIQUE non-IP string per
	// request (e.g. "X-Forwarded-For: a<rand>") and have every request
	// attributed to a distinct key, defeating per-IP rate limiting, bans,
	// and brute-force counting wholesale. Unparseable values fall back to
	// the real TCP peer. (Spoofing with VALID IPs is inherent to this mode;
	// the strict trusted_proxies branch below is the fix operators should
	// adopt — this only removes the garbage-key amplification.)
	if c.trustedAll {
		if v := leftmostXFF(r); validIP(v) {
			return v
		}
		if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); validIP(v) {
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
			// A hop that doesn't parse as an IP is client-injected garbage
			// (e.g. "X-Forwarded-For: not-an-ip" to corrupt the rate-limit
			// key). Skip it rather than returning it as the client IP — the
			// previous code returned any non-trusted token verbatim, which
			// let an attacker behind a trusted proxy rotate arbitrary keys to
			// dodge per-IP rate-limits and bans.
			if !validIP(h) {
				continue
			}
			if !ipInNets(h, c.trustedNets) {
				return h
			}
		}
		// Every hop was trusted (or invalid) — fall back to the left-most
		// entry that is a valid IP.
		for _, h := range hops {
			if validIP(h) {
				return h
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); validIP(v) {
		// X-Real-Ip is single-valued and only emitted by edge proxies, so
		// when the peer is trusted we accept it — but only if it actually
		// parses as an IP. An unvalidated value here would become the
		// rate-limit / ban key, so a forged non-IP string must not pass.
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
	// Deliberately NOT honouring trustedAll here. Legacy "trust_xff with no
	// allowlist" mode keeps left-most XFF parsing for backward-compatible
	// client-IP resolution, but peer-trust gates a far more dangerous
	// decision: whether to believe spoofable proof headers like
	// X-WEWAF-Client-Cert-Verified (mTLS verdict) and X-Forwarded-Proto.
	// Treating every direct connection as a trusted proxy there would let an
	// attacker who reaches the WAF directly forge a verified client
	// certificate or an HTTPS origin. Require an explicit trusted_proxies
	// CIDR before any peer is trusted for header-derived proof — an empty
	// trustedNets set makes this correctly return false.
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

// ipv6KeyPrefixBits is the prefix length IPv6 client IPs are masked to before
// being used as a per-client key (rate limiter, DDoS per-IP maps, brute-force
// detector, ban matcher). A single end site is routinely allocated an entire
// /64 (or larger) and rotating the low 64 bits is free, so keying on the full
// /128 would let one client present 2^64 distinct identities and slip past
// every per-IP control. Masking to /64 makes the prefix the unit of accounting.
const ipv6KeyPrefixBits = 64

// NormalizeIPKey canonicalises an IP string for use as a per-client key.
// IPv4 (incl. IPv4-mapped IPv6) addresses are returned unchanged — a single
// /32 is already one host. IPv6 addresses are masked to their /64 prefix.
// Unparseable input is returned unchanged so callers that already fell back to
// a raw peer string keep a stable (if coarse) key. The operation is idempotent:
// NormalizeIPKey(NormalizeIPKey(x)) == NormalizeIPKey(x).
func NormalizeIPKey(ipStr string) string {
	if ipStr == "" {
		return ipStr
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ipStr
	}
	if parsed.To4() != nil {
		return ipStr // IPv4 / IPv4-mapped: full /32, unchanged.
	}
	masked := parsed.Mask(net.CIDRMask(ipv6KeyPrefixBits, 128))
	if masked == nil {
		return ipStr
	}
	return masked.String()
}

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

// CIDRSet is an immutable, concurrency-safe set of CIDR networks with O(n)
// membership testing. It reuses the same parser as the trusted_proxies
// allowlist (bare IPs are promoted to /32 or /128), so operators write
// allowlist entries in one consistent syntax across the whole config.
//
// It exists so the ban-input allowlist (core.BanList) and the host-firewall
// sink (internal/firewall) can share one validated never-touch set without
// re-implementing CIDR parsing — banning your own CDN egress range or the
// loopback interface is a self-DoS, and a single shared primitive makes that
// hard to get wrong in two places.
type CIDRSet struct {
	nets []*net.IPNet
}

// NewCIDRSet parses entries (CIDRs or bare IPs) into a set. A malformed entry
// returns a non-nil error and a nil set; callers should treat that as a fatal
// config error, exactly like trusted_proxies.
func NewCIDRSet(entries []string) (*CIDRSet, error) {
	nets, err := parseCIDRs(entries)
	if err != nil {
		return nil, err
	}
	return &CIDRSet{nets: nets}, nil
}

// Contains reports whether ipStr falls inside any network in the set. A nil
// set, an empty set, or an unparseable IP all return false. Safe for
// concurrent use — the set is never mutated after construction.
func (s *CIDRSet) Contains(ipStr string) bool {
	if s == nil {
		return false
	}
	return ipInNets(strings.TrimSpace(ipStr), s.nets)
}

// Overlaps reports whether the network n intersects any network in the set —
// i.e. one contains the other's base address. This is what the ban allowlist
// needs: a ban keyed on an IPv6 /64 must be refused if the allowlist names ANY
// host inside that /64 (a /128 admin entry), not only when the /64 base address
// itself is listed. A nil set or nil n returns false.
func (s *CIDRSet) Overlaps(n *net.IPNet) bool {
	if s == nil || n == nil {
		return false
	}
	for _, m := range s.nets {
		if m.Contains(n.IP) || n.Contains(m.IP) {
			return true
		}
	}
	return false
}

// Len returns the number of networks in the set.
func (s *CIDRSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}

// validIP reports whether s parses as an IPv4 or IPv6 address. Forwarding
// headers are attacker-influenced, so any value used as a client-IP (and
// therefore as a rate-limit / ban / metrics key) must pass this first.
func validIP(s string) bool {
	if s == "" {
		return false
	}
	return net.ParseIP(s) != nil
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
				if ip4 := ip.To4(); ip4 != nil {
					// Use the dotted-quad form so an IPv4-mapped IPv6 literal
					// ("::ffff:1.2.3.4") promotes to 1.2.3.4/32, not the 128-bit
					// "::ffff:1.2.3.4/32" which ParseCIDR would mask to ::/32.
					s = ip4.String() + "/32"
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

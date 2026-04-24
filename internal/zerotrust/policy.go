// Package zerotrust applies per-path access policies that run before the
// rule engine. Where the rule engine catches "this request looks malicious",
// zero-trust catches "this request shouldn't be allowed anywhere near this
// endpoint in the first place".
//
// A policy is a pattern + constraint set:
//
//   - PathPrefix / PathExact: what the policy applies to.
//   - RequireAuthHeader: request must carry a non-empty header by this name.
//   - RequireMTLS: request must present a verified client certificate (we
//     check for the X-WEWAF-Client-Cert-Verified header that a correctly
//     configured TLS terminator injects).
//   - AllowedCountries / BlockedCountries: two-letter ISO country codes.
//     Countries come from a lightweight IP→country lookup; if lookup fails
//     the policy fails closed unless FallbackAllow is set.
//   - AllowedIPs / BlockedIPs: CIDR ranges applied before country checks.
//
// Policies evaluate in registration order; the first match wins.
package zerotrust

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// Decision is the outcome of evaluating policies for one request.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
	DecisionNoMatch
)

// Policy is a single rule.
type Policy struct {
	ID                string   `json:"id"`
	Description       string   `json:"description,omitempty"`
	PathPrefix        string   `json:"path_prefix,omitempty"`
	PathExact         string   `json:"path_exact,omitempty"`
	RequireAuthHeader string   `json:"require_auth_header,omitempty"`
	RequireMTLS       bool     `json:"require_mtls,omitempty"`
	AllowedCountries  []string `json:"allowed_countries,omitempty"`
	BlockedCountries  []string `json:"blocked_countries,omitempty"`
	AllowedCIDRs      []string `json:"allowed_cidrs,omitempty"`
	BlockedCIDRs      []string `json:"blocked_cidrs,omitempty"`
	FallbackAllow     bool     `json:"fallback_allow,omitempty"`

	// compiled forms
	allowedNets []*net.IPNet `json:"-"`
	blockedNets []*net.IPNet `json:"-"`
}

// Engine holds the compiled policy list.
type Engine struct {
	mu       sync.RWMutex
	policies []*Policy
	geo      CountryLookup
}

// CountryLookup returns the ISO-3166-1 alpha-2 country code for an IP, or
// empty if unknown. Implementations should be fast (in-memory) and safe
// for concurrent use. A nil lookup is equivalent to "always unknown".
type CountryLookup interface {
	Country(ip net.IP) string
}

// NoopLookup is the default — returns "" for every IP.
type NoopLookup struct{}

func (NoopLookup) Country(net.IP) string { return "" }

// NewEngine constructs an empty policy engine.
func NewEngine(lookup CountryLookup) *Engine {
	if lookup == nil {
		lookup = NoopLookup{}
	}
	return &Engine{geo: lookup}
}

// SetPolicies replaces the policy list, compiling each policy's CIDR fields.
func (e *Engine) SetPolicies(policies []*Policy) error {
	compiled := make([]*Policy, 0, len(policies))
	for _, raw := range policies {
		if raw == nil {
			continue
		}
		p := *raw // shallow copy so we don't mutate caller's pointer
		p.allowedNets = p.allowedNets[:0]
		p.blockedNets = p.blockedNets[:0]
		for _, c := range p.AllowedCIDRs {
			if _, cidr, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
				p.allowedNets = append(p.allowedNets, cidr)
			}
		}
		for _, c := range p.BlockedCIDRs {
			if _, cidr, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
				p.blockedNets = append(p.blockedNets, cidr)
			}
		}
		compiled = append(compiled, &p)
	}
	e.mu.Lock()
	e.policies = compiled
	e.mu.Unlock()
	return nil
}

// Policies returns a copy of the current policy slice.
func (e *Engine) Policies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Policy, len(e.policies))
	for i, p := range e.policies {
		cp := *p
		out[i] = &cp
	}
	return out
}

// Evaluate runs the first matching policy. If no policy matches the request
// path, returns DecisionNoMatch and the proxy should fall through to the
// regular rule engine. Otherwise the returned reason is appended to the
// block message for operator visibility.
func (e *Engine) Evaluate(r *http.Request, clientIP string) (Decision, string, *Policy) {
	if e == nil || r == nil {
		return DecisionNoMatch, "", nil
	}
	e.mu.RLock()
	pols := e.policies
	e.mu.RUnlock()
	if len(pols) == 0 {
		return DecisionNoMatch, "", nil
	}
	path := r.URL.Path
	ip := net.ParseIP(clientIP)
	for _, p := range pols {
		if !p.matches(path) {
			continue
		}

		// IP allowlist: if set, the IP must be inside.
		if len(p.allowedNets) > 0 {
			if ip == nil || !anyCIDRContains(p.allowedNets, ip) {
				return DecisionDeny, "ip not in allowed CIDR list", p
			}
		}
		// IP blocklist.
		if len(p.blockedNets) > 0 && ip != nil && anyCIDRContains(p.blockedNets, ip) {
			return DecisionDeny, "ip in blocked CIDR list", p
		}

		// Country check.
		if len(p.AllowedCountries) > 0 || len(p.BlockedCountries) > 0 {
			country := ""
			if ip != nil {
				country = e.geo.Country(ip)
			}
			if country == "" {
				if !p.FallbackAllow {
					return DecisionDeny, "country lookup unavailable and fallback is deny", p
				}
			} else {
				if len(p.BlockedCountries) > 0 && containsIgnoreCase(p.BlockedCountries, country) {
					return DecisionDeny, "country " + country + " in blocklist", p
				}
				if len(p.AllowedCountries) > 0 && !containsIgnoreCase(p.AllowedCountries, country) {
					return DecisionDeny, "country " + country + " not in allowlist", p
				}
			}
		}

		// Required auth header.
		if p.RequireAuthHeader != "" {
			if r.Header.Get(p.RequireAuthHeader) == "" {
				return DecisionDeny, "missing required header " + p.RequireAuthHeader, p
			}
		}

		// Required mTLS flag — expects the TLS terminator to set
		// X-WEWAF-Client-Cert-Verified=1 after verifying the client cert.
		if p.RequireMTLS {
			if r.Header.Get("X-WEWAF-Client-Cert-Verified") != "1" {
				return DecisionDeny, "mTLS required but not verified", p
			}
		}

		return DecisionAllow, "", p
	}
	return DecisionNoMatch, "", nil
}

func (p *Policy) matches(path string) bool {
	if p.PathExact != "" {
		return path == p.PathExact
	}
	if p.PathPrefix != "" {
		return strings.HasPrefix(path, p.PathPrefix)
	}
	return false
}

func anyCIDRContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(haystack []string, needle string) bool {
	n := strings.ToUpper(needle)
	for _, h := range haystack {
		if strings.ToUpper(strings.TrimSpace(h)) == n {
			return true
		}
	}
	return false
}

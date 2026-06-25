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
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Decision is the outcome of evaluating policies for one request.
type Decision int

const (
	DecisionAllow    Decision = iota
	DecisionDeny              // enforce block
	DecisionSimulate          // policy matched but is in simulate mode — log only
	DecisionNoMatch
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	case DecisionSimulate:
		return "simulate"
	case DecisionNoMatch:
		return "no_match"
	}
	return "unknown"
}

// Policy is a single rule.
type Policy struct {
	ID                string   `json:"id"`
	Description       string   `json:"description,omitempty"`
	PathPrefix        string   `json:"path_prefix,omitempty"`
	PathExact         string   `json:"path_exact,omitempty"`
	PathRegex         string   `json:"path_regex,omitempty"`
	Methods           []string `json:"methods,omitempty"` // GET/POST/... (empty = any)
	RequireAuthHeader string   `json:"require_auth_header,omitempty"`
	RequireMTLS       bool     `json:"require_mtls,omitempty"`
	AllowedCountries  []string `json:"allowed_countries,omitempty"`
	BlockedCountries  []string `json:"blocked_countries,omitempty"`
	AllowedCIDRs      []string `json:"allowed_cidrs,omitempty"`
	BlockedCIDRs      []string `json:"blocked_cidrs,omitempty"`
	FallbackAllow     bool     `json:"fallback_allow,omitempty"`

	// TimeWindow restricts when the policy applies. Both fields are "HH:MM"
	// strings in UTC; e.g., Start="09:00" End="17:00" means enforcement
	// only happens during that window. Empty values mean always-on.
	TimeStart string `json:"time_start,omitempty"`
	TimeEnd   string `json:"time_end,omitempty"`

	// Simulate logs decisions as blocks but does not actually block. Useful
	// for rolling a new policy out in shadow mode before enforcing it.
	Simulate bool `json:"simulate,omitempty"`

	// DenyByDefault: if true and no other constraint matches the request,
	// deny anyway. Use on high-value paths where implicit allow is unsafe.
	DenyByDefault bool `json:"deny_by_default,omitempty"`

	// compiled forms
	allowedNets    []*net.IPNet    `json:"-"`
	blockedNets    []*net.IPNet    `json:"-"`
	pathRe         *regexp.Regexp  `json:"-"`
	methods        map[string]bool `json:"-"`
	pathExactNorm  string          `json:"-"` // lower(normalizePath(PathExact))
	pathPrefixNorm string          `json:"-"` // lower(PathPrefix)
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

// SetPolicies replaces the policy list, compiling each policy's CIDR +
// method + path-regex fields.
func (e *Engine) SetPolicies(policies []*Policy) error {
	compiled := make([]*Policy, 0, len(policies))
	for _, raw := range policies {
		if raw == nil {
			continue
		}
		p := *raw // shallow copy so we don't mutate caller's pointer
		p.allowedNets = nil
		p.blockedNets = nil
		p.pathRe = nil
		p.methods = nil
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
		if p.PathRegex != "" {
			if re, err := regexp.Compile(p.PathRegex); err == nil {
				p.pathRe = re
			}
		}
		if len(p.Methods) > 0 {
			p.methods = make(map[string]bool, len(p.Methods))
			for _, m := range p.Methods {
				m = strings.ToUpper(strings.TrimSpace(m))
				if m != "" {
					p.methods[m] = true
				}
			}
		}
		// Precompute the case-folded, canonical path selectors so the gate
		// matches the same resource view the origin routes on (see matches()).
		if p.PathExact != "" {
			p.pathExactNorm = strings.ToLower(normalizePath(p.PathExact))
		}
		p.pathPrefixNorm = strings.ToLower(p.PathPrefix)
		compiled = append(compiled, &p)
	}
	// Warn loudly if a country rule is configured but no GeoIP lookup is wired:
	// with the default NoopLookup the country dimension is a SILENT no-op (every
	// IP resolves to ""), so BlockedCountries never fires and AllowedCountries
	// either fails open (FallbackAllow) or denies everyone — a false sense of
	// security on an advertised control.
	if _, noop := e.geo.(NoopLookup); noop || e.geo == nil {
		for _, p := range compiled {
			if len(p.AllowedCountries) > 0 || len(p.BlockedCountries) > 0 {
				log.Printf("zerotrust: WARNING policy %q uses country allow/block rules but no GeoIP lookup is configured; the country dimension is INERT — no request will be geo-filtered. Wire a CountryLookup or remove the country fields.", p.ID)
			}
		}
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
//
// Policies with Simulate=true return DecisionSimulate instead of DecisionDeny
// so the caller can log the intent without actually blocking the traffic.
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
	canonOrig := normalizePath(path)
	canonLower := strings.ToLower(canonOrig)
	method := strings.ToUpper(r.Method)
	ip := net.ParseIP(clientIP)
	nowUTC := time.Now().UTC()

	// deny returns the right decision based on simulate.
	deny := func(p *Policy, reason string) (Decision, string, *Policy) {
		if p.Simulate {
			return DecisionSimulate, reason + " (simulate)", p
		}
		return DecisionDeny, reason, p
	}

	for _, p := range pols {
		if !p.matches(path, canonOrig, canonLower) {
			continue
		}
		if len(p.methods) > 0 && !p.methods[method] {
			continue
		}
		// Time-of-day window. Empty = always on.
		if !p.inWindow(nowUTC) {
			continue
		}

		// IP allowlist: if set, the IP must be inside.
		if len(p.allowedNets) > 0 {
			if ip == nil || !anyCIDRContains(p.allowedNets, ip) {
				return deny(p, "ip not in allowed CIDR list")
			}
		}
		// IP blocklist. An unparseable client IP must NOT silently skip the
		// blocklist — that fails open, letting a request whose source can't
		// be resolved past a policy that exists specifically to block source
		// ranges. Treat "can't tell who you are" as blocked when this policy
		// enforces an IP blocklist (the allowlist above already fails closed
		// on a nil IP; this brings the blocklist in line).
		if len(p.blockedNets) > 0 {
			if ip == nil {
				return deny(p, "unresolvable client IP under IP-blocklist policy")
			}
			if anyCIDRContains(p.blockedNets, ip) {
				return deny(p, "ip in blocked CIDR list")
			}
		}

		// Country check.
		if len(p.AllowedCountries) > 0 || len(p.BlockedCountries) > 0 {
			country := ""
			if ip != nil {
				country = e.geo.Country(ip)
			}
			if country == "" {
				if !p.FallbackAllow {
					return deny(p, "country lookup unavailable and fallback is deny")
				}
			} else {
				if len(p.BlockedCountries) > 0 && containsIgnoreCase(p.BlockedCountries, country) {
					return deny(p, "country "+country+" in blocklist")
				}
				if len(p.AllowedCountries) > 0 && !containsIgnoreCase(p.AllowedCountries, country) {
					return deny(p, "country "+country+" not in allowlist")
				}
			}
		}

		// Required auth header.
		if p.RequireAuthHeader != "" {
			if r.Header.Get(p.RequireAuthHeader) == "" {
				return deny(p, "missing required header "+p.RequireAuthHeader)
			}
		}

		// Required mTLS flag — expects the TLS terminator to set
		// X-WEWAF-Client-Cert-Verified=1 after verifying the client cert.
		if p.RequireMTLS {
			if r.Header.Get("X-WEWAF-Client-Cert-Verified") != "1" {
				return deny(p, "mTLS required but not verified")
			}
		}

		// DenyByDefault: if no positive constraint explicitly allowed
		// the request, deny anyway. This catches the case where a
		// high-value path matches the policy but has no other checks.
		if p.DenyByDefault && len(p.allowedNets) == 0 && p.RequireAuthHeader == "" && !p.RequireMTLS && len(p.AllowedCountries) == 0 {
			return deny(p, "deny-by-default for protected path")
		}

		return DecisionAllow, "", p
	}
	return DecisionNoMatch, "", nil
}

func (p *Policy) inWindow(now time.Time) bool {
	if p.TimeStart == "" && p.TimeEnd == "" {
		return true
	}
	start := parseHHMM(p.TimeStart)
	end := parseHHMM(p.TimeEnd)
	if start < 0 || end < 0 {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		return cur >= start && cur < end
	}
	// Window spans midnight, e.g., 22:00-06:00.
	return cur >= start || cur < end
}

// parseHHMM returns minutes since midnight, or -1 on parse failure.
func parseHHMM(s string) int {
	if s == "" {
		return -1
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return -1
	}
	h, err := parseNonNegInt(parts[0])
	if err != nil {
		return -1
	}
	m, err := parseNonNegInt(parts[1])
	if err != nil {
		return -1
	}
	if h > 23 || m > 59 {
		return -1
	}
	return h*60 + m
}

func parseNonNegInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errInvalid
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

var errInvalid = &parseErr{}

type parseErr struct{}

func (*parseErr) Error() string { return "invalid integer" }

// normalizePath canonicalizes a request path to the form a normalizing backend
// (servlet container, IIS, nginx) routes on, so the policy gate sees the same
// resource the origin will serve. Without this, an attacker reaches a
// PathExact/PathPrefix-gated endpoint while EVADING the gate by appending a
// matrix param (/admin;x), a duplicate slash (//admin), a trailing slash/dot
// (/admin/ , /admin.), or a case variant (/Admin) — all of which the origin
// folds back to the protected path. The exact normalization the codebase
// already applies to brute-force login detection (stripMatrixParams), now also
// applied to the higher-value zero-trust authz gate. Returns lower-case is left
// to the caller (selectors are matched case-insensitively).
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	// Strip matrix parameters (";jsessionid=…") from every segment.
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			if j := strings.IndexByte(s, ';'); j >= 0 {
				segs[i] = s[:j]
			}
		}
		p = strings.Join(segs, "/")
	}
	// Collapse runs of '/'.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	// Trim trailing slash/dot/space (servlet trailing-slash + Windows/IIS
	// trailing-dot canonicalization); keep the root "/".
	if len(p) > 1 {
		p = strings.TrimRight(p, "/. ")
	}
	if p == "" {
		return "/"
	}
	return p
}

// matches returns true if the policy's path selector applies to the request.
// rawPath is r.URL.Path; canonLower is lower(normalizePath(rawPath)). PathExact/
// PathPrefix are matched case-insensitively against the canonical path so a
// normalization-mismatch (matrix/slash/trailing/case) can't slip past the gate
// while still reaching the protected resource. PathRegex (operator-supplied,
// case-sensitive by intent) is matched against both the raw and the
// canonicalized path so an anchored regex still fires but evasion is caught.
//
// A policy with NO path selector (all three fields empty) used to match
// every request, which turned a careless operator's first "save" click
// into a deny-all outage. Empty-selector policies no longer match anything.
func (p *Policy) matches(rawPath, canonOrig, canonLower string) bool {
	if p.PathExact == "" && p.PathPrefix == "" && p.pathRe == nil {
		return false
	}
	if p.pathExactNorm != "" && canonLower == p.pathExactNorm {
		return true
	}
	if p.pathPrefixNorm != "" && strings.HasPrefix(canonLower, p.pathPrefixNorm) {
		return true
	}
	if p.pathRe != nil && (p.pathRe.MatchString(rawPath) || p.pathRe.MatchString(canonOrig)) {
		return true
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

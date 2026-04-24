package proxy

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"wewaf/internal/limits"
)

// mustRegexp compiles pat or panics at init — the regex literals below
// are all source-controlled, so a compile failure is a programming bug.
func mustRegexp(pat string) *regexp.Regexp {
	return regexp.MustCompile(pat)
}

// egressDNSCache memoises hostname lookups so a long-running egress workload
// doesn't hit the resolver for every request. Entries carry a TTL that the
// OS typically enforces anyway, but without a cache a burst of outbound
// requests to the same host serialises on the resolver's connection pool.
//
// The cache is safe for concurrent use, bounded in size, and evicts the
// least-recently-seen entry when full.
type egressDNSCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	max    int
	entries map[string]*dnsEntry
}

type dnsEntry struct {
	ips     []net.IP
	err     error
	expires time.Time
	lastHit time.Time
}

func newEgressDNSCache(ttl time.Duration, max int) *egressDNSCache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if max <= 0 {
		max = 2048
	}
	return &egressDNSCache{
		ttl:     ttl,
		max:     max,
		entries: make(map[string]*dnsEntry),
	}
}

// Lookup returns cached IPs for host or performs a fresh resolution.
// Negative results (DNS errors) are cached for half the normal TTL so a
// temporary resolver blip doesn't hammer the network.
func (c *egressDNSCache) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, &net.DNSError{Err: "empty host"}
	}
	now := time.Now()
	c.mu.Lock()
	if ent, ok := c.entries[host]; ok && ent.expires.After(now) {
		ent.lastHit = now
		ips, err := ent.ips, ent.err
		c.mu.Unlock()
		return ips, err
	}
	c.mu.Unlock()

	resolver := net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(lookupCtx, "ip", host)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictOldestLocked()
	}
	ttl := c.ttl
	if err != nil {
		ttl = c.ttl / 2
	}
	c.entries[host] = &dnsEntry{
		ips:     ips,
		err:     err,
		expires: now.Add(ttl),
		lastHit: now,
	}
	return ips, err
}

// Warm resolves each allowlist host asynchronously so the first real
// egress request doesn't stall on a five-second LookupIP. Errors are
// swallowed — a host that fails to resolve at startup will retry on
// demand, exactly the same way an uncached cache-miss would. We budget
// only a short timeout per host to avoid tying up startup if DNS is
// misconfigured entirely.
func (c *egressDNSCache) Warm(hosts []string) {
	if c == nil || len(hosts) == 0 {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" || net.ParseIP(h) != nil {
				continue
			}
			// Drop leading "*." used by subdomain wildcards; only the
			// right-hand host is resolvable.
			if strings.HasPrefix(h, "*.") {
				h = h[2:]
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = c.Lookup(ctx, h)
			cancel()
		}
	}()
}

func (c *egressDNSCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, v := range c.entries {
		if oldest.IsZero() || v.lastHit.Before(oldest) {
			oldest = v.lastHit
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// egressRateLimiter applies a per-destination-host token bucket so one
// noisy dependency can't exfiltrate everything. It piggybacks on the same
// token-bucket limiter the proxy uses for ingress.
type egressRateLimiter struct {
	rl *limits.RateLimiter
}

func newEgressRateLimiter(rps, burst int) *egressRateLimiter {
	if rps <= 0 {
		rps = 50
	}
	if burst <= 0 {
		burst = rps * 2
	}
	return &egressRateLimiter{rl: limits.NewRateLimiter(rps, burst)}
}

// Allow returns true if this request to `host` is within the per-host budget.
func (e *egressRateLimiter) Allow(host string) bool {
	if e == nil || e.rl == nil {
		return true
	}
	return e.rl.Allow(host)
}

// --- Response-body exfiltration detection ------------------------------

// exfilMaxInspectBytes is how much of an outbound response we scan. The
// typical leak shape (dump-of-a-users-table-as-JSON) shows in the first
// tens of KB; scanning more than this burns CPU on API payloads that are
// legitimately large. The rest of the response still forwards fine.
const exfilMaxInspectBytes = 256 * 1024

// Precompiled patterns. Kept conservative to minimise false positives:
//   - credit card: 15-19 consecutive digits, validated with Luhn
//   - secret envelopes: AKIA-prefixed AWS access keys, "ghp_"/"gho_"/"ghs_"
//     GitHub tokens, "AIza" Google API keys, "sk-live_" / "sk_live_" Stripe
//     live keys. Each is a strict prefix pattern so benign text doesn't trip.
var (
	exfilDigitRun   = mustRegexp(`[0-9]{13,19}`)
	exfilAWSKey     = mustRegexp(`\bAKIA[0-9A-Z]{16}\b`)
	exfilGitHubTok  = mustRegexp(`\bgh[pousr]_[A-Za-z0-9]{36,251}\b`)
	exfilGoogleKey  = mustRegexp(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	exfilStripeKey  = mustRegexp(`\bsk_live_[0-9A-Za-z]{20,}\b`)
	exfilSlackToken = mustRegexp(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)
	exfilJWT        = mustRegexp(`\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b`)
)

// exfilFinding captures one detection. Callers aggregate these into a
// single egress-exfil counter bump + audit log line, not a per-pattern
// avalanche of alerts.
type exfilFinding struct {
	Kind   string
	Sample string
}

// inspectEgressResponseBody returns findings for the first chunk of a
// response body. `sample` is assumed to already be capped at exactly
// exfilMaxInspectBytes. Callers pass body already read into memory so we
// don't have to do our own io plumbing here.
//
// Defensive: never panics on malformed input; returns an empty slice if
// the body isn't scannable. The caller decides whether findings should
// block, log, or both — the detector's job is just "did we see it".
func inspectEgressResponseBody(sample []byte) []exfilFinding {
	if len(sample) == 0 {
		return nil
	}
	var findings []exfilFinding
	// Credit-card: Luhn-verify each digit run so phone numbers, tracking
	// IDs, and invoice numbers don't trigger a false alarm.
	for _, m := range exfilDigitRun.FindAll(sample, -1) {
		if luhnValid(m) {
			findings = append(findings, exfilFinding{
				Kind:   "credit_card",
				Sample: maskDigits(string(m)),
			})
			break // one is enough to flag; don't spam
		}
	}
	tryPattern := func(kind string, pat interface{ Find([]byte) []byte }) {
		if m := pat.Find(sample); m != nil {
			findings = append(findings, exfilFinding{
				Kind:   kind,
				Sample: maskSecret(string(m)),
			})
		}
	}
	tryPattern("aws_access_key", exfilAWSKey)
	tryPattern("github_token", exfilGitHubTok)
	tryPattern("google_api_key", exfilGoogleKey)
	tryPattern("stripe_live_key", exfilStripeKey)
	tryPattern("slack_token", exfilSlackToken)
	tryPattern("jwt", exfilJWT)
	return findings
}

// luhnValid implements the standard credit-card checksum over an ASCII
// digit run. Bounded by the regex to 13-19 digits, so this is O(1).
func luhnValid(digits []byte) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// maskDigits returns a hint like "4xxxxxxxxxxx1234" instead of the raw
// card number — important so audit logs don't themselves become the
// exfil surface we were trying to prevent.
func maskDigits(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	out := make([]byte, len(s))
	for i := range out {
		if i == 0 || i >= len(out)-4 {
			out[i] = s[i]
		} else {
			out[i] = 'x'
		}
	}
	return string(out)
}

// maskSecret truncates a token to its prefix so operators can see which
// vendor leaked without seeing the whole secret in logs.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "***"
}

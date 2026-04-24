package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	"wewaf/internal/limits"
)

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

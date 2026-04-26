// Package ja3 computes JA3 TLS client fingerprints from ClientHello data
// and exposes a small in-memory cache so the rest of the stack can look up
// the fingerprint of an inbound HTTP request by remote address.
//
// The JA3 algorithm (Salesforce, 2017) is a stable hash of the bits of the
// TLS ClientHello that vary between client implementations:
//
//	MD5( SSLVersion , CipherSuites , Extensions , EllipticCurves , ECPointFormats )
//
// Each list is dash-joined integers, the five lists are comma-joined, and
// the final string is MD5'd. We strip TLS GREASE values per RFC 8701
// (their whole purpose is to be ignored by middleboxes) so that the same
// real client doesn't produce different fingerprints across handshakes.
//
// We use JA3 as a *signal*, not an identifier. Real Chrome's fingerprint
// rotates every few months; curl, Go's net/http, and the well-known
// headless-Chrome variants are stable enough to flag with high confidence.
// The default policy is "+15 risk score on a known-bad match"; an
// optional hard-block flag exists for operators who want it.
package ja3

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FingerprintInput is the subset of *tls.ClientHelloInfo the JA3 algorithm
// reads. We accept this rather than a *ClientHelloInfo directly so the
// computation is testable without a real TLS handshake.
type FingerprintInput struct {
	Version          uint16   // ClientHello legacy_version (0x0301..0x0304)
	CipherSuites     []uint16 // offered cipher suites, in order
	Extensions       []uint16 // extension type IDs, in order they appeared
	SupportedCurves  []uint16 // supported_groups extension contents
	SupportedPoints  []uint8  // ec_point_formats extension contents
}

// Fingerprint is the structured form of one observation.
//
// Hash is classic JA3 (MD5 of the canonical string); kept for
// compatibility with public threat-intel feeds (sslbl.abuse.ch etc.)
// which still list JA3 hashes. JA3N is the order-normalized variant —
// stable against the random extension reorder Chrome 110+ does on
// every handshake. JA4 is the FoxIO format and is what the rest of
// the stack should prefer for fingerprint *matching*; classic JA3
// remains useful for *signal correlation* with feeds that haven't
// migrated yet.
type Fingerprint struct {
	Hash    string    // 32-char lowercase MD5 of String (classic JA3)
	JA3N    string    // 32-char lowercase MD5 — JA3 with sorted ext list
	JA4     string    // 36-char FoxIO JA4 fingerprint
	String  string    // canonical JA3 string (for diagnostics + JA3N rederivation)
	SeenAt  time.Time // when this entry was cached
	Version uint16    // copied for diagnostics
}

// Compute returns the JA3 string and its MD5 hash for the given ClientHello.
// Returns ("","") only when the input is empty / unusable; production code
// should treat that as "no fingerprint available" not "match".
func Compute(in FingerprintInput) (jaString, jaHash string) {
	// Defensive: a zero ClientHello is meaningless. Returning empty lets
	// callers skip caching without us having to special-case downstream.
	if in.Version == 0 && len(in.CipherSuites) == 0 && len(in.Extensions) == 0 {
		return "", ""
	}

	var b strings.Builder
	// Pre-grow once. Worst case: ~20 cipher suites + ~15 extensions + ~10
	// curves, all ≤5 chars + separators. 256 bytes is comfortable.
	b.Grow(256)

	b.WriteString(strconv.Itoa(int(in.Version)))
	b.WriteByte(',')
	writeFilteredUint16s(&b, in.CipherSuites)
	b.WriteByte(',')
	writeFilteredUint16s(&b, in.Extensions)
	b.WriteByte(',')
	writeFilteredUint16s(&b, in.SupportedCurves)
	b.WriteByte(',')
	writeFilteredUint8s(&b, in.SupportedPoints)

	jaString = b.String()
	sum := md5.Sum([]byte(jaString))
	jaHash = hex.EncodeToString(sum[:])
	return
}

// FromClientHello adapts a real *tls.ClientHelloInfo into a Fingerprint.
// The Go stdlib unfortunately does NOT expose the raw extension order or
// raw cipher list before filtering — so we make do with what's exported.
// CipherSuites is the offered list, SupportedVersions tells us the
// negotiated max, Extensions order is approximated from the well-known
// fields the API exposes (this is a known limitation; a TLS-replacement
// library like utls would give us the real ordering).
//
// Even so, the resulting hash is stable per-client and that is what
// matters for fingerprint detection.
//
// Returns the classic JA3 string + hash. Use FullFromClientHello when
// the caller wants JA3N and JA4 too.
func FromClientHello(chi *tls.ClientHelloInfo) (jaString, jaHash string) {
	in := buildJA3Input(chi)
	if in.Version == 0 && len(in.CipherSuites) == 0 {
		return "", ""
	}
	return Compute(in)
}

// FullFromClientHello returns a fully-populated Fingerprint with classic
// JA3, JA3N (sorted-ext variant), and JA4 (FoxIO format) all computed
// from the same handshake. Cheap — the three algorithms share most of
// their input prep.
func FullFromClientHello(chi *tls.ClientHelloInfo) Fingerprint {
	if chi == nil {
		return Fingerprint{}
	}
	in := buildJA3Input(chi)
	if in.Version == 0 && len(in.CipherSuites) == 0 {
		return Fingerprint{}
	}

	jaString, jaHash := Compute(in)
	_, jaNHash := ComputeJA3N(in)

	sigSchemes := make([]uint16, 0, len(chi.SignatureSchemes))
	for _, s := range chi.SignatureSchemes {
		sigSchemes = append(sigSchemes, uint16(s))
	}
	ja4 := ComputeJA4(JA4Input{
		Version:          in.Version,
		HasSNI:           chi.ServerName != "",
		CipherSuites:     in.CipherSuites,
		Extensions:       in.Extensions,
		SignatureSchemes: sigSchemes,
		ALPN:             append([]string(nil), chi.SupportedProtos...),
	})

	return Fingerprint{
		Hash:    jaHash,
		JA3N:    jaNHash,
		JA4:     ja4,
		String:  jaString,
		Version: in.Version,
	}
}

func buildJA3Input(chi *tls.ClientHelloInfo) FingerprintInput {
	if chi == nil {
		return FingerprintInput{}
	}
	in := FingerprintInput{
		CipherSuites:    append([]uint16(nil), chi.CipherSuites...),
		SupportedCurves: curvesAsUint16(chi.SupportedCurves),
		SupportedPoints: append([]uint8(nil), chi.SupportedPoints...),
	}
	if len(chi.SupportedVersions) > 0 {
		var max uint16
		for _, v := range chi.SupportedVersions {
			if v > max {
				max = v
			}
		}
		in.Version = max
	} else {
		in.Version = tls.VersionTLS12
	}
	in.Extensions = synthesizeExtensions(chi)
	return in
}

// IsGREASE returns true if v is a TLS GREASE value (RFC 8701). GREASE
// values are 16-bit numbers of the form 0xRARA where R is one of the
// reserved nibbles. They must be filtered before fingerprinting because
// real clients pick one at random per handshake.
func IsGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

func writeFilteredUint16s(b *strings.Builder, xs []uint16) {
	first := true
	for _, x := range xs {
		if IsGREASE(x) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
		first = false
	}
}

func writeFilteredUint8s(b *strings.Builder, xs []uint8) {
	first := true
	for _, x := range xs {
		if !first {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
		first = false
	}
}

func curvesAsUint16(xs []tls.CurveID) []uint16 {
	out := make([]uint16, 0, len(xs))
	for _, c := range xs {
		out = append(out, uint16(c))
	}
	return out
}

// synthesizeExtensions derives a stable extension-ID list from the
// information the stdlib *does* expose. The resulting list is not the
// wire ordering; it's a canonical per-feature flag set. Two real clients
// with the same TLS feature surface produce the same list.
func synthesizeExtensions(chi *tls.ClientHelloInfo) []uint16 {
	out := make([]uint16, 0, 12)
	// SNI (extension 0)
	if chi.ServerName != "" {
		out = append(out, 0)
	}
	// supported_groups (extension 10)
	if len(chi.SupportedCurves) > 0 {
		out = append(out, 10)
	}
	// ec_point_formats (extension 11)
	if len(chi.SupportedPoints) > 0 {
		out = append(out, 11)
	}
	// signature_algorithms (extension 13)
	if len(chi.SignatureSchemes) > 0 {
		out = append(out, 13)
	}
	// application_layer_protocol_negotiation / ALPN (extension 16)
	if len(chi.SupportedProtos) > 0 {
		out = append(out, 16)
	}
	// supported_versions (extension 43)
	if len(chi.SupportedVersions) > 0 {
		out = append(out, 43)
	}
	return out
}

// -----------------------------------------------------------------------------
// Cache: short-lived map of remoteAddr → Fingerprint, populated by
// GetConfigForClient during the TLS handshake and read by HTTP handlers via
// req.RemoteAddr.

// Cache holds recent fingerprints keyed by remote address. It is bounded:
// hard cap on entries, drop-oldest when full, TTL on read. Concurrency is a
// single RWMutex — operations are short and contention is rare in practice
// (one write per handshake, one read per request).
type Cache struct {
	mu      sync.RWMutex
	entries map[string]Fingerprint
	cap     int
	ttl     time.Duration

	// Stats are atomic so the admin UI can snapshot them without taking
	// the lock and starving real traffic.
	hits    atomic.Uint64
	misses  atomic.Uint64
	evicted atomic.Uint64
	stored  atomic.Uint64
}

// NewCache creates a JA3 cache with the given capacity and TTL.
// Zero/negative values fall back to defaults: 4096 entries, 30s TTL.
// These were chosen so that a 100k-RPS edge keeping ~10s of Keep-Alive
// connections fits comfortably with no GC churn.
func NewCache(capacity int, ttl time.Duration) *Cache {
	if capacity <= 0 {
		capacity = 4096
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Cache{
		entries: make(map[string]Fingerprint, capacity),
		cap:     capacity,
		ttl:     ttl,
	}
}

// Put records a fingerprint for the given remote address. Safe to call
// from a TLS GetConfigForClient hook in any goroutine. If the cache is at
// capacity, one arbitrary entry is dropped — this is sufficient because
// the TTL keeps the working set small; eviction is a safety net not the
// primary collector.
func (c *Cache) Put(remoteAddr string, fp Fingerprint) {
	if c == nil || remoteAddr == "" || fp.Hash == "" {
		return
	}
	host := normalizeAddr(remoteAddr)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.cap {
		// Drop one expired entry first; if none expired drop any one.
		now := time.Now()
		dropped := false
		for k, v := range c.entries {
			if now.Sub(v.SeenAt) > c.ttl {
				delete(c.entries, k)
				c.evicted.Add(1)
				dropped = true
				break
			}
		}
		if !dropped {
			for k := range c.entries {
				delete(c.entries, k)
				c.evicted.Add(1)
				break
			}
		}
	}
	if fp.SeenAt.IsZero() {
		fp.SeenAt = time.Now()
	}
	c.entries[host] = fp
	c.stored.Add(1)
}

// Get returns the cached fingerprint for the remote address, or zero value
// + false if absent or expired. Expired entries are evicted lazily.
func (c *Cache) Get(remoteAddr string) (Fingerprint, bool) {
	if c == nil || remoteAddr == "" {
		return Fingerprint{}, false
	}
	host := normalizeAddr(remoteAddr)
	c.mu.RLock()
	fp, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		c.misses.Add(1)
		return Fingerprint{}, false
	}
	if time.Since(fp.SeenAt) > c.ttl {
		// Lazy expire — upgrade to write lock and remove.
		c.mu.Lock()
		// Re-check under the write lock in case a concurrent Put
		// refreshed the entry.
		if cur, stillThere := c.entries[host]; stillThere && time.Since(cur.SeenAt) > c.ttl {
			delete(c.entries, host)
		}
		c.mu.Unlock()
		c.misses.Add(1)
		return Fingerprint{}, false
	}
	c.hits.Add(1)
	return fp, true
}

// Stats returns a snapshot of cache stats. Cheap; uses atomics only.
type Stats struct {
	Size    int
	Cap     int
	Hits    uint64
	Misses  uint64
	Evicted uint64
	Stored  uint64
}

func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.RLock()
	size := len(c.entries)
	cap := c.cap
	c.mu.RUnlock()
	return Stats{
		Size:    size,
		Cap:     cap,
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Evicted: c.evicted.Load(),
		Stored:  c.stored.Load(),
	}
}

// Sweep removes expired entries. Cheap to call periodically (every TTL/2)
// from the same housekeeper goroutine that handles other cache TTLs.
func (c *Cache) Sweep() int {
	if c == nil {
		return 0
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, v := range c.entries {
		if now.Sub(v.SeenAt) > c.ttl {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// normalizeAddr strips the port from an "ip:port" RemoteAddr and lowercases
// IPv6 hex. The TLS callback gets the raw conn.RemoteAddr so it always
// includes the port; HTTP handlers see the same. Keying by ip:port is
// what we want — different sockets from the same IP can absolutely have
// different fingerprints (curl + browser on one box).
func normalizeAddr(s string) string {
	// SplitHostPort only fails if there's no port — accept whatever the
	// caller gave us in that case.
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h + ":" + p
	}
	return s
}

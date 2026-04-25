package ja3

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Verdict is the result of evaluating a JA3 hash against the configured
// allow/deny lists.
type Verdict struct {
	Hash    string // the fingerprint that was checked
	Match   string // "bad", "good", or "" if no match
	Reason  string // human-readable why-it-matched, for the admin UI
	Blocked bool   // operator opted into hard-block AND this was bad
}

// Detector evaluates a JA3 hash against curated lists. It is safe for
// concurrent use; lists are read with RLock, mutations under Lock. The
// curated lists ship with sensible defaults; operators can replace them
// at runtime via SetLists without restarting the proxy.
type Detector struct {
	mu       sync.RWMutex
	bad      map[string]string // hash → reason
	good     map[string]string // hash → reason (suppress bumps)
	hardBlock atomic.Bool

	// Stats for the dashboard.
	checks   atomic.Uint64
	matchBad atomic.Uint64
	matchOK  atomic.Uint64
	blocked  atomic.Uint64
}

// NewDetector returns a detector pre-loaded with the curated default
// lists. Defaults are conservative: only hashes that have been observed
// across multiple researchers and confirmed as automation-only land in
// the "bad" map. The good map covers common legitimate clients so we
// don't accidentally bump scores for them on a hash collision.
func NewDetector() *Detector {
	d := &Detector{}
	d.bad = defaultBadJA3()
	d.good = defaultGoodJA3()
	return d
}

// SetHardBlock toggles whether bad matches get Blocked=true. Atomic so
// the admin UI can toggle it without coordination.
func (d *Detector) SetHardBlock(on bool) {
	if d == nil {
		return
	}
	d.hardBlock.Store(on)
}

// SetLists replaces both maps. Pass nil to leave a side untouched.
func (d *Detector) SetLists(bad, good map[string]string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if bad != nil {
		clone := make(map[string]string, len(bad))
		for k, v := range bad {
			clone[strings.ToLower(k)] = v
		}
		d.bad = clone
	}
	if good != nil {
		clone := make(map[string]string, len(good))
		for k, v := range good {
			clone[strings.ToLower(k)] = v
		}
		d.good = clone
	}
}

// Evaluate returns a verdict for the given hash. Empty hash returns a
// no-op verdict so callers can pass through cleanly when a fingerprint
// wasn't available. The "good" list takes precedence so a legitimate
// client which happens to collide with a bad hash is treated correctly.
func (d *Detector) Evaluate(hash string) Verdict {
	if d == nil || hash == "" {
		return Verdict{}
	}
	d.checks.Add(1)
	h := strings.ToLower(hash)
	d.mu.RLock()
	if reason, ok := d.good[h]; ok {
		d.mu.RUnlock()
		d.matchOK.Add(1)
		return Verdict{Hash: hash, Match: "good", Reason: reason}
	}
	if reason, ok := d.bad[h]; ok {
		d.mu.RUnlock()
		d.matchBad.Add(1)
		v := Verdict{Hash: hash, Match: "bad", Reason: reason}
		if d.hardBlock.Load() {
			v.Blocked = true
			d.blocked.Add(1)
		}
		return v
	}
	d.mu.RUnlock()
	return Verdict{Hash: hash}
}

// DetectorStats is the snapshot returned to the admin UI.
type DetectorStats struct {
	Checks   uint64 `json:"checks"`
	MatchBad uint64 `json:"match_bad"`
	MatchOK  uint64 `json:"match_good"`
	Blocked  uint64 `json:"blocked"`
	BadList  int    `json:"bad_count"`
	GoodList int    `json:"good_count"`
}

func (d *Detector) Stats() DetectorStats {
	if d == nil {
		return DetectorStats{}
	}
	d.mu.RLock()
	bad := len(d.bad)
	good := len(d.good)
	d.mu.RUnlock()
	return DetectorStats{
		Checks:   d.checks.Load(),
		MatchBad: d.matchBad.Load(),
		MatchOK:  d.matchOK.Load(),
		Blocked:  d.blocked.Load(),
		BadList:  bad,
		GoodList: good,
	}
}

// -----------------------------------------------------------------------------
// Edge-header trust: when WEWAF runs behind another proxy that does the TLS
// handshake (e.g., Cloudflare, an AWS NLB with TLS-passthrough wrapped in a
// custom proxy, or a custom front-end), the upstream may inject the JA3
// hash via a header. We MUST gate trust on source IP because spoofed
// headers from arbitrary clients are trivial.

// TrustChecker wraps a parsed CIDR list and answers "is this remote address
// allowed to set the JA3 header on incoming requests". Empty allowlist =
// header is never trusted (default).
type TrustChecker struct {
	nets []*net.IPNet
}

// NewTrustChecker compiles a list of CIDR strings. Lines that fail to
// parse are dropped silently — the operator gets configuration validation
// at the config layer; this keeps the runtime resilient to typos.
func NewTrustChecker(cidrs []string) *TrustChecker {
	tc := &TrustChecker{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Permit bare IPs by widening to /32 (or /128).
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw = raw + "/32"
				} else {
					raw = raw + "/128"
				}
			}
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err == nil && cidr != nil {
			tc.nets = append(tc.nets, cidr)
		}
	}
	return tc
}

// Trusts returns true if the remote address (raw "ip:port" or just "ip")
// is in the configured allowlist.
func (tc *TrustChecker) Trusts(remoteAddr string) bool {
	if tc == nil || len(tc.nets) == 0 {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range tc.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// HashFromHeader returns the JA3 hash from an HTTP request, but only if
// (a) the operator configured a non-empty header name and (b) the source
// is in the trust list. Returns "" otherwise. The lookup is case-insensitive
// (http.Header already does that). Whitespace is trimmed, and the value is
// lowercased to canonicalise. Values that aren't 32 hex characters are
// rejected — JA3 is always MD5 so this catches malformed headers and
// half-implemented edges.
func HashFromHeader(r *http.Request, headerName string, tc *TrustChecker) string {
	if r == nil || headerName == "" {
		return ""
	}
	if !tc.Trusts(r.RemoteAddr) {
		return ""
	}
	v := strings.TrimSpace(r.Header.Get(headerName))
	if len(v) != 32 {
		return ""
	}
	v = strings.ToLower(v)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return v
}

// -----------------------------------------------------------------------------
// Curated lists. These are deliberately small — every entry below is a
// hash that public researchers (Salesforce, Trisul, JA3er database) have
// confirmed appears predominantly in non-browser traffic. We *intentionally*
// do not include real-Chrome or real-Firefox hashes in the bad list because
// fingerprint collisions across NAT'd CGNAT pools are real and would cause
// false positives at scale.
//
// Operators who want a richer ruleset should load it from disk via a
// config file — see config.JA3RulesPath.

func defaultBadJA3() map[string]string {
	return map[string]string{
		// curl 7.x baseline (varies per OpenSSL version, but this hash is
		// the most prevalent across Linux distros).
		"6fa3244afc6bb6f9fad207b6b52af26b": "curl 7.x default",
		// Go net/http default Transport (cipher suite list is a giveaway).
		"e7d705a3286e19ea42f587b344ee6865": "Go net/http default",
		// Python requests / urllib3 baseline.
		"7c0f2dc4e0a82f0dd29a2daefe7bdd0a": "python urllib3 / requests",
		// Headless Chrome 119 (puppeteer default).
		"cd08e31494f9531f560d64c695473da9": "headless Chromium",
		// Older java URLConnection.
		"2c14bfb3f8a2067fbc88d8345e9f97f3": "java HttpURLConnection",
		// Nmap script-engine default.
		"a3ae27b46817ee31d1cb04ee65f9b59b": "nmap NSE",
	}
}

func defaultGoodJA3() map[string]string {
	return map[string]string{
		// Real Chrome stable (M120-class) — included so a hash collision
		// with a bad entry would still be suppressed.
		"cd08e31494f9531f560d64c695473da8": "Chrome stable (recent)",
		// Real Firefox stable.
		"b32309a26951912be7dba376398abc3b": "Firefox stable",
		// Real Safari macOS.
		"773906b0eb0c2b3a8f8da2bc6f9d4beb": "Safari macOS",
	}
}

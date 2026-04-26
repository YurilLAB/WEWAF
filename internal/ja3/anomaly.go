package ja3

import (
	"strings"
	"sync/atomic"
)

// AnomalyResult captures cross-signal disagreements between the TLS
// fingerprint and the HTTP-level User-Agent. The idea is that any single
// signal is noisy (Chrome's JA3 mutates monthly, UA strings are trivially
// spoofable) but a *disagreement* between two independent signals is a
// strong, low-FP indicator of automation.
//
// We deliberately do NOT block on this — the score bump is additive and
// reaches the session-level threshold via accumulation. That keeps the
// false-positive cost low for unusual-but-legitimate combinations like
// custom Electron apps with non-Chrome UA strings.
type AnomalyResult struct {
	Tags       []string // e.g. ["ua-claims-chrome-but-ja3-curl"]
	ScoreBump  int      // recommended additive bump, capped at 25
	HumanReason string  // for logs / admin UI
}

// AnomalyDetector pairs UA-keyed expectations with fingerprint families.
// We keep this stateless and side-effect-free apart from atomic counters —
// the proxy calls Check on the hot path and the result is folded into the
// session score.
type AnomalyDetector struct {
	checks   atomic.Uint64
	mismatch atomic.Uint64
}

func NewAnomalyDetector() *AnomalyDetector { return &AnomalyDetector{} }

// Check inspects the (UA, fingerprint) pair for known-bad disagreements.
// The fingerprint family is inferred from the JA4 ALPN / version section
// (cheap) plus a small handful of well-known JA3 hashes for clients that
// don't expose ALPN at all.
//
// All comparisons are case-insensitive on the UA side.
func (a *AnomalyDetector) Check(ua string, fp Fingerprint) AnomalyResult {
	if a == nil {
		return AnomalyResult{}
	}
	a.checks.Add(1)

	uaLow := strings.ToLower(strings.TrimSpace(ua))
	if uaLow == "" || (fp.Hash == "" && fp.JA4 == "") {
		// Not enough signal to compare. Don't penalise — empty UAs are
		// already a separate signal handled by the rule engine.
		return AnomalyResult{}
	}

	tags := make([]string, 0, 2)
	bump := 0

	// 1. UA claims Chrome / Edge / Firefox / Safari but JA3 hash matches
	//    a known automation-only family. The "known" list overlaps with
	//    defaultBadJA3 deliberately — these are stable and high-confidence.
	jaLow := strings.ToLower(fp.Hash)
	switch jaLow {
	case "6fa3244afc6bb6f9fad207b6b52af26b": // curl 7.x
		if claimsBrowser(uaLow) {
			tags = append(tags, "ua-claims-browser-ja3-curl")
			bump += 15
		}
	case "e7d705a3286e19ea42f587b344ee6865": // Go net/http
		if claimsBrowser(uaLow) {
			tags = append(tags, "ua-claims-browser-ja3-go")
			bump += 15
		}
	case "7c0f2dc4e0a82f0dd29a2daefe7bdd0a": // python urllib3 / requests
		if claimsBrowser(uaLow) {
			tags = append(tags, "ua-claims-browser-ja3-python")
			bump += 15
		}
	}

	// 2. JA4 ALPN says "h2" or "h3" (HTTP/2/3) but UA looks like a CLI
	//    tool. Real curl is HTTP/1.1 by default and doesn't enable h2
	//    unless --http2 is passed; the combination of `h2` ALPN with
	//    `curl/X.Y` UA is suspicious without being conclusive.
	if claimsCLI(uaLow) && hasH2OrH3ALPN(fp.JA4) {
		tags = append(tags, "cli-ua-with-h2-alpn")
		bump += 5
	}

	// 3. JA4 reports TLS 1.0 (`t10`) or no TLS version known (`t00`) but
	//    UA claims a modern browser. Real Chrome/Firefox/Safari haven't
	//    done <1.2 since 2020.
	if claimsModernBrowser(uaLow) && (strings.HasPrefix(fp.JA4, "t10") || strings.HasPrefix(fp.JA4, "t11") || strings.HasPrefix(fp.JA4, "t00")) {
		tags = append(tags, "modern-browser-ua-with-old-tls")
		bump += 10
	}

	// 4. Empty SNI section (`i`) but UA says browser. Real browsers send
	//    SNI on every HTTPS request; absence is highly automation-like.
	if claimsBrowser(uaLow) && len(fp.JA4) >= 4 && fp.JA4[3] == 'i' {
		tags = append(tags, "browser-ua-no-sni")
		bump += 8
	}

	if bump > 25 {
		bump = 25
	}
	if len(tags) == 0 {
		return AnomalyResult{}
	}
	a.mismatch.Add(1)
	return AnomalyResult{
		Tags:        tags,
		ScoreBump:   bump,
		HumanReason: strings.Join(tags, ","),
	}
}

// AnomalyStats is the counter snapshot for the admin UI.
type AnomalyStats struct {
	Checks    uint64 `json:"checks"`
	Mismatch  uint64 `json:"mismatch"`
}

func (a *AnomalyDetector) Stats() AnomalyStats {
	if a == nil {
		return AnomalyStats{}
	}
	return AnomalyStats{
		Checks:   a.checks.Load(),
		Mismatch: a.mismatch.Load(),
	}
}

// claimsBrowser returns true if the UA string contains any of the
// browser-family tokens. Substring match is intentional; we want
// "Mozilla/5.0 ... Chrome/120 ..." to count.
func claimsBrowser(uaLow string) bool {
	for _, tok := range []string{"chrome/", "edg/", "firefox/", "safari/", "opera/", "opr/"} {
		if strings.Contains(uaLow, tok) {
			return true
		}
	}
	return false
}

func claimsModernBrowser(uaLow string) bool {
	// Modern = released since 2020 (TLS 1.0 fully deprecated). We use the
	// same broad set as claimsBrowser; finer version parsing isn't
	// worth the maintenance cost vs. the coarse-grained signal here.
	return claimsBrowser(uaLow)
}

func claimsCLI(uaLow string) bool {
	for _, tok := range []string{"curl/", "wget/", "python-", "go-http-client", "java/", "okhttp/", "node-fetch/", "axios/"} {
		if strings.Contains(uaLow, tok) {
			return true
		}
	}
	return false
}

// hasH2OrH3ALPN inspects bytes 8-9 of a JA4 string (ALPN section).
// Cheap O(1) check; returns false on malformed input.
func hasH2OrH3ALPN(ja4 string) bool {
	if len(ja4) < 10 {
		return false
	}
	tag := ja4[8:10]
	return tag == "h2" || tag == "h3"
}

package proxy

import (
	"crypto/subtle"
	"net/http"
)

// originShield injects a shared-secret header on every request forwarded to the
// backend so the origin can reject traffic that did NOT pass through the WAF.
//
// Why this protects the SERVER (not just the website): a WAF only protects an
// origin if traffic is forced through it. The moment an attacker learns the
// origin's IP and connects to it directly, every request skips the rule engine,
// the ban list, the rate limiter — the whole WAF. Injecting a secret the origin
// is configured to require (the Cloudflare "Authenticated Origin Pull" / AWS
// CloudFront custom-header pattern) makes a direct hit fail at the origin. The
// secret is shared with the origin out of band — never auto-generated to a
// random per-restart value, which the origin could never verify — and is
// redacted from every UI and log surface.
type originShield struct {
	header   string
	secret   string
	previous string // accepted during rotation so a key change never 403s live traffic
}

func newOriginShield(header, secret, previous string) *originShield {
	if header == "" {
		header = "X-WEWAF-Origin-Verify"
	}
	return &originShield{header: header, secret: secret, previous: previous}
}

// wrapDirector composes the existing reverse-proxy director with the header
// injection. It uses Set (overwrite), so any value a client tried to smuggle is
// replaced — the origin only ever sees the WAF's real secret.
func (o *originShield) wrapDirector(base func(*http.Request)) func(*http.Request) {
	return func(r *http.Request) {
		if base != nil {
			base(r)
		}
		r.Header.Set(o.header, o.secret)
	}
}

// VerifyOriginSecret reports whether provided matches the active or previous
// origin secret, compared in constant time. An empty configured secret never
// matches, so a half-configured origin can't be tricked into treating an empty
// header as "verified". Exported so a Go origin (or a chained WEWAF instance)
// can verify with the same primitive the WAF uses to sign.
func VerifyOriginSecret(provided, current, previous string) bool {
	ok := false
	// Both comparisons always run (no short-circuit) so timing reveals nothing
	// about which secret, if any, matched.
	if current != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(current)) == 1 {
		ok = true
	}
	if previous != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(previous)) == 1 {
		ok = true
	}
	return ok
}

package proxy

import "net/http"

// BrowserChallengeRiskBump is the risk weight added to a session that, under
// BrowserChallengeBlock, has not proven itself with a Proof-of-Work pass. It
// lowers that session's EFFECTIVE PoW trigger to (PoWTriggerScore - this).
//
// Exported so cmd/waf can warn, from a single source of truth, when an
// operator's thresholds leave the bump unable to reach any band.
//
// Calibrated below the default PoW trigger (60) on purpose — the "escalate into
// the existing bands" model: a clean first-time visitor (and a cross-site
// SSO/payment POST that arrives with no cookie, base score ~0) is NOT challenged
// by the +40 alone, so those flows keep working; an un-verified session is
// driven into the PoW gate only once it ALSO accrues ~20 of other risk. The
// honest caveat (see the config field doc): a low-and-slow bot that rotates or
// omits its __wewaf_sid cookie keeps base score 0 across requests, so the
// per-session signals never accrue and the +40 alone never gates it. Catching
// that class requires lowering PoWTriggerScore toward this value (challenging
// every un-verified request, at the cost of also challenging cross-site
// POST/XHR) or the orthogonal per-IP controls (rate limiter, reputation, DDoS).
const BrowserChallengeRiskBump = 40

// browserChallengeEscalation returns the extra risk weight for an un-verified
// session under BrowserChallengeBlock, or 0 when the escalation does not apply.
// It is added ONLY to the header-phase score that feeds the PoW gate (and the
// throttle band) — never to the body-phase block band, so it can never hard-
// block a session that was not first offered the PoW escape.
//
// The suppressor is the PoW pass cookie (hasValidPoWCookie), NOT the browser-
// integrity signals. This is deliberate and is what makes the control honest:
//
//   - The signals (navigator.webdriver, plugin count, …) are entirely client-
//     supplied, so a bot can forge a "real browser" submission. They therefore
//     stay a SOFT score input (the existing +15 missing-challenge bump) and can
//     never, on their own, clear this escalation.
//   - The PoW pass cookie is session+IP-bound, HMAC-authenticated, TTL'd, and
//     only obtainable by actually solving the JS Proof-of-Work — work a no-JS
//     client cannot fake by reading the page. So the ONLY way to shed this
//     weight is to do unforgeable client-side work.
//   - The cookie survives session-map eviction (it is verified from the request,
//     never the in-memory map), so a passed visitor is not re-escalated when a
//     rotation flood churns the LRU — unlike anything keyed on session state.
//
// Requires PoW enabled — but config.Validate force-enables PoW under block mode,
// so in a validated config this is always satisfied; the guard is defence in
// depth for a hand-constructed config (e.g. tests).
func (wp *WAFProxy) browserChallengeEscalation(r *http.Request, sessID string) int {
	if wp == nil || sessID == "" {
		return 0
	}
	c := wp.conf()
	if c == nil || !c.BrowserChallengeBlock || !c.PoWEnabled {
		return 0
	}
	// Never escalate the WAF's own challenge/asset endpoints. The PoW verify
	// endpoint in particular is where a client SUBMITS its solution to obtain
	// the pass cookie — by definition it arrives without one, so escalating it
	// could push it over SessionBlockThreshold and block the very request that
	// would clear the gate, deadlocking the solve loop. (The PoW-gate and
	// throttle checks already bypass these paths; the body-phase block band does
	// not, so the guard belongs here where both score sites consult it.)
	if isPoWBypassPath(r.URL.Path) {
		return 0
	}
	if wp.hasValidPoWCookie(r, sessID) {
		return 0
	}
	return BrowserChallengeRiskBump
}

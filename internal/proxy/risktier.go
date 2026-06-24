package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// RiskAction is the graduated enforcement decision derived from a session's
// risk score. The ladder is ordered by severity, lowest to highest:
//
//	RiskAllow < RiskThrottle < RiskChallenge < RiskBlock
//
// The integer values double as the severity ranking (iota order), which the
// monotonicity tests rely on. This is WEWAF's single risk-policy mapping —
// every score resolves to exactly one action, and every action is explainable
// from the band it landed in (no opaque ML model in the path).
type RiskAction int

const (
	// RiskAllow lets the request proceed with no risk-based intervention.
	RiskAllow RiskAction = iota
	// RiskThrottle proceeds but imposes a bounded latency penalty — the
	// graduated middle band between "allow" and a step-up challenge.
	RiskThrottle
	// RiskChallenge serves a proof-of-work step-up before allowing.
	RiskChallenge
	// RiskBlock refuses the request.
	RiskBlock
)

func (a RiskAction) String() string {
	switch a {
	case RiskBlock:
		return "block"
	case RiskChallenge:
		return "challenge"
	case RiskThrottle:
		return "throttle"
	default:
		return "allow"
	}
}

// throttleMaxDelayMs caps the throttle tarpit. A throttle is a delay applied
// to a *server goroutine*, so an unbounded value would let an operator turn
// their own WAF into a connection-holding amplifier under load. 2s is long
// enough to meaningfully tax an abusive session without that risk; config
// Validate() clamps SessionThrottleDelayMs to this ceiling too, so this is a
// defence in depth.
const throttleMaxDelayMs = 2000

// riskTier maps a risk score to an action given the three band thresholds.
//
// It is TOTAL — every score yields exactly one action — and FAIL-SECURE: the
// bands are tested most-severe-first, so the strictest applicable band wins
// even if an operator mis-orders the thresholds. A block band set below the
// challenge band still blocks rather than silently downgrading to a challenge.
//
// A threshold <= 0 disables its band. Scores are expected in [0,100] but the
// function is defined for any int.
//
// Severity is monotonic in score for any fixed set of bands: raising the score
// can only satisfy more `score >= threshold` predicates, and most-severe-first
// selection means the chosen action can therefore only become more (or equally)
// severe. FuzzRiskTier asserts exactly that invariant.
func riskTier(score, throttleAt, challengeAt, blockAt int) RiskAction {
	if blockAt > 0 && score >= blockAt {
		return RiskBlock
	}
	if challengeAt > 0 && score >= challengeAt {
		return RiskChallenge
	}
	if throttleAt > 0 && score >= throttleAt {
		return RiskThrottle
	}
	return RiskAllow
}

// riskActionFor resolves the graduated action for a session score using the
// operator's configured bands. The challenge band is only active when PoW is
// enabled (a "challenge" the proxy cannot actually serve would be useless), so
// with PoW off a would-be-challenge score falls through to the next lower
// active band — exactly mirroring the legacy two-threshold behaviour.
//
// This is the unified policy mapping; the existing shouldGateWithPoW (which
// also owns the valid-cookie suppression and bypass-path rules) remains the
// executor for the challenge band, and the body-phase SessionBlockThreshold
// check remains the executor for the block band so phase-1 rule logging is
// preserved. riskActionFor is used directly to drive the new throttle band.
func (wp *WAFProxy) riskActionFor(score int) RiskAction {
	if wp == nil {
		return RiskAllow
	}
	c := wp.conf()
	if c == nil {
		return RiskAllow
	}
	challengeAt := 0
	if c.PoWEnabled {
		challengeAt = c.PoWTriggerScore
	}
	return riskTier(score, c.SessionThrottleThreshold, challengeAt, c.SessionBlockThreshold)
}

// throttleDelay sleeps for delayMs (clamped to throttleMaxDelayMs), returning
// early if ctx is cancelled. It returns the duration actually waited. Pulled
// out of applyThrottle so the bound and cancellation behaviour are unit- and
// fuzz-testable without standing up a full proxy.
func throttleDelay(ctx context.Context, delayMs int) time.Duration {
	if delayMs <= 0 {
		return 0
	}
	if delayMs > throttleMaxDelayMs {
		delayMs = throttleMaxDelayMs
	}
	start := time.Now()
	t := time.NewTimer(time.Duration(delayMs) * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
	return time.Since(start)
}

// applyThrottle imposes the configured, bounded, cancellation-aware delay on a
// throttle-band request and emits a log-only history event. The request is NOT
// terminated — throttle is a tax, not a block, so the caller continues to full
// inspection afterward. If the client disconnects mid-delay the wait aborts
// immediately, so the tarpit cannot be flipped into a resource amplifier.
func (wp *WAFProxy) applyThrottle(ctx context.Context, r *http.Request, score int) {
	if wp == nil {
		return
	}
	delayMs := 0
	if c := wp.conf(); c != nil {
		delayMs = c.SessionThrottleDelayMs
	}
	if delayMs <= 0 {
		return
	}
	waited := throttleDelay(ctx, delayMs)
	if wp.metrics != nil && wp.ipExtractor != nil {
		ip := wp.ipExtractor.ClientIP(r)
		// Observe-only: the request was delayed, not blocked — keep it out of
		// the block total (it continues to full inspection after the delay).
		wp.metrics.RecordSecurityEvent(ip, r.Method, r.URL.Path,
			"SESSION-THROTTLE", "session",
			fmt.Sprintf("session throttled %dms (score=%d)", int(waited.Milliseconds()), score), 0)
	}
}

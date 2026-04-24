package session

import (
	"math"
	"time"
)

// ScoreRequest recomputes the session's risk score based on current state.
// Called after every request. Runs inside the tracker lock so callers just
// invoke it through Tracker.Score.
//
// Score is monotonically-derived from observed signals with explicit
// weights — it is NOT an ML model. That's intentional: every bump is
// explainable in the admin UI ("+15 for UA drift", "+20 for rate spike"),
// and operators can tune thresholds without retraining anything. Anomaly
// scoring with opaque ML tends to false-positive in ways operators can't
// debug during an incident.
//
// Weights (all additive, capped at 100):
//   - Rate anomaly:         up to +25  (reqs/min > ceiling)
//   - Path explosion:       up to +20  (distinct paths > ceiling)
//   - UA drift:             +10 per distinct UA after the first (max +30)
//   - IP drift:             +10 per distinct IP after the first (max +20)
//   - Missing challenge:    +15  (active session with no browser cookie)
//   - Missing beacon:       +10  (10+ requests, no event reports)
//   - Suspiciously uniform: +10  (beacon with zero mouse AND zero keys)
//   - Block ratio:          up to +30 (blocks ÷ requests)
//
// Scores >= 60 are "high risk" and the proxy can optionally drop its
// block threshold for these sessions.
func (t *Tracker) Score(id string) int {
	if t == nil || id == "" || !t.enabled.Load() {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[id]
	if !ok {
		return 0
	}
	score := 0
	now := time.Now().UTC()

	// Rate anomaly — normalise to reqs-per-minute over the session's
	// observed duration. For very short sessions we clamp the denominator
	// to 15 s to avoid divide-by-near-zero inflating the signal.
	observedSec := now.Sub(s.FirstSeen).Seconds()
	if observedSec < 15 {
		observedSec = 15
	}
	reqsPerMin := float64(s.RequestCount) * 60.0 / observedSec
	ceiling := float64(t.requestRateCeiling.Load())
	if ceiling > 0 && reqsPerMin > ceiling {
		over := reqsPerMin / ceiling
		// Log scale so 2× adds +10, 5× adds +20, 20× adds +25 (capped).
		bump := int(math.Min(25, 10*math.Log2(over+1)))
		score += bump
	}

	// Path explosion — legitimate SPAs visit tens of paths; scanners visit
	// hundreds. Any distinct-path count above the ceiling contributes.
	pathCeiling := int(t.pathCountCeiling.Load())
	if pathCeiling > 0 && len(s.Paths) > pathCeiling {
		over := len(s.Paths) - pathCeiling
		bump := over / 5
		if bump > 20 {
			bump = 20
		}
		score += bump
	}

	// UA drift — a real browser has exactly one User-Agent for the session.
	// Two is a weird-but-possible (UA-spoofing extension); three+ is almost
	// always automation cycling UAs to dodge rules.
	if n := len(s.UserAgents); n > 1 {
		bump := (n - 1) * 10
		if bump > 30 {
			bump = 30
		}
		score += bump
	}

	// IP drift — residential NAT + mobile handoffs can reasonably produce
	// 2-3 IPs, but 4+ on a stable session is rare outside of deliberate
	// proxy rotation.
	if n := len(s.IPs); n > 1 {
		bump := (n - 1) * 10
		if bump > 20 {
			bump = 20
		}
		score += bump
	}

	// Missing challenge — only penalise after a few requests so a
	// landing-page hit isn't flagged before the JS has a chance to run.
	if !s.ChallengePassed && s.RequestCount > 5 {
		score += 15
	}

	// Missing beacon — headless browsers rarely execute the beacon. If
	// we've seen 10+ requests and zero beacons, that's suspicious.
	if s.BeaconCount == 0 && s.RequestCount >= 10 {
		score += 10
	}

	// Zero-activity beacon — JS is running enough to hit the beacon
	// endpoint but reports exactly zero input. Puppeteer scripts that
	// carry cookies but don't drive input look like this.
	if s.BeaconCount > 0 && s.MouseEvents == 0 && s.KeyEvents == 0 {
		score += 10
	}

	// Block ratio — if this session has been blocked repeatedly, bump.
	if s.RequestCount > 0 {
		ratio := float64(s.BlockCount) / float64(s.RequestCount)
		if ratio > 0.1 {
			bump := int(math.Min(30, ratio*100))
			score += bump
		}
	}

	if score > 100 {
		score = 100
	}
	s.RiskScore = score
	s.LastScoreBump = now
	return score
}

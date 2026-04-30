package session

import (
	"math"
	"time"
)

// Per-second event rate above which a beacon is "implausibly active"
// — a real human averages 50–200 mouse events per minute (~0.8–3.3 per
// second); 100 per second sustained is automation faking realism.
// Calibrated from public UEBA datasets and aligned with what most
// CAPTCHA-replacement services consider the human-noise ceiling.
const beaconImplausibleEventsPerSec = 100

// ScoreRequest recomputes the session's risk score based on current state.
// Called after every request. Runs inside the tracker lock so callers just
// invoke it through Tracker.Score.
//
// Score is observed-signal-derived with explicit weights — it is NOT an
// ML model. That's intentional: every bump is explainable in the admin
// UI ("+15 for UA drift", "+20 for rate spike"), and operators can tune
// thresholds without retraining anything. Anomaly scoring with opaque ML
// tends to false-positive in ways operators can't debug during an
// incident.
//
// Weights (all additive, capped at 100):
//   - Rate anomaly:         up to +25  (reqs/min > ceiling)
//   - Path explosion:       up to +20  (distinct paths > ceiling)
//   - UA drift:             +10 per distinct UA after the first (max +30)
//   - IP drift:             +10 per distinct IP after the first (max +20)
//   - Missing challenge:    +15  (active session with no fresh challenge pass)
//   - Missing beacon:       +10  (10+ requests, no event reports)
//   - Suspiciously uniform: +10  (beacon with zero mouse AND zero keys)
//   - Implausible beacon:   +15  (reported event rate above human ceiling)
//   - Block ratio:          up to +30 (blocks ÷ requests, min 5 reqs)
//   - JA3 verdict bad:      +15
//   - JA3 drift:            +25 per drift, capped +50 (high-signal cookie sharing)
//
// Plus a time-decay step: scoreDecayPerMin points fade per minute of
// inactivity so a session that earned a spike from one bad burst
// gradually returns to baseline if it then behaves.
//
// Scores >= 60 are "high risk" and the proxy can optionally drop its
// block threshold for these sessions.
func (t *Tracker) Score(id string) int {
	if t == nil || id == "" || !t.enabled.Load() {
		return 0
	}
	// Read-lock for the bulk of the scoring math so multiple admin-UI /
	// hot-path callers can compute scores in parallel. The result is
	// written back to the session struct under a brief write lock at
	// the end. The previous unconditional write lock serialised every
	// scoring call against every other tracker mutation, which made
	// the admin /api/sessions page contend with live request scoring.
	t.mu.RLock()
	s, ok := t.sessions[id]
	if !ok {
		t.mu.RUnlock()
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

	// Missing challenge — penalise active sessions that don't have a
	// fresh challenge pass. The freshness check closes a class of
	// bypass: ChallengePassed used to be a permanent boolean, so a
	// bot solved once and stayed passed for the entire session
	// lifetime (which can be days when activity keeps the idle TTL
	// bumped). The TTL gate forces re-challenge after a configured
	// window, putting an upper bound on how long a stolen cookie or
	// a once-solved bot can ride a single session ID.
	challengeFresh := s.ChallengePassed && !s.ChallengeAt.IsZero()
	if challengeFresh {
		ttlSec := t.challengeTTLSec.Load()
		if ttlSec > 0 && now.Sub(s.ChallengeAt) > time.Duration(ttlSec)*time.Second {
			challengeFresh = false
		}
	}
	if !challengeFresh && s.RequestCount > 5 {
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

	// Implausible-activity beacon — the inverse failure mode. A bot
	// faking realism has to commit to numbers; cap that with a
	// human-baseline ceiling (mouse + key events per second sustained
	// over the session). 100/sec is roughly 50× a busy human.
	if s.BeaconCount > 0 && observedSec > 30 {
		evRate := float64(s.MouseEvents+s.KeyEvents) / observedSec
		if evRate > beaconImplausibleEventsPerSec {
			score += 15
		}
	}

	// Block ratio — bump only when there's enough sample to mean
	// anything. The previous unconditional check let a 1-block /
	// 2-request session score +30 from one cold-start mismatch.
	if s.RequestCount >= 5 {
		ratio := float64(s.BlockCount) / float64(s.RequestCount)
		if ratio > 0.1 {
			bump := int(math.Min(30, ratio*100))
			score += bump
		}
	}

	// JA3 — a curated-bad fingerprint adds a fixed bump. We do NOT block
	// on JA3 alone in the scoring path; that's the operator's choice via
	// the hard-block flag in the JA3 detector.
	if s.JA3Verdict == "bad" {
		score += 15
	}

	// JA3 drift — the cleanest cookie-sharing tell we have. A stolen
	// __wewaf_sid replayed on a different machine carries a different
	// TLS stack and so a different JA3 hash. The first drift is +25;
	// each subsequent drift adds +25 too, capped at +50 so legitimate
	// network handoffs (mobile NAT swap, VPN connect/disconnect) don't
	// get pinned past redemption. Anything past two distinct stacks on
	// the same session ID is bot territory.
	if s.JA3Drifts > 0 {
		bump := s.JA3Drifts * 25
		if bump > 50 {
			bump = 50
		}
		score += bump
	}

	if score > 100 {
		score = 100
	}

	// Apply time-decay AFTER all positive bumps — the new evidence is
	// the most useful signal but we still want yesterday's spike to
	// fade if the session has since been quiet. Decay anchors on
	// LastScoreBump so a chatty-then-quiet session gradually returns
	// to baseline without ever erasing a fresh spike.
	if rate := t.scoreDecayPerMin.Load(); rate > 0 && !s.LastScoreBump.IsZero() {
		quietMin := now.Sub(s.LastScoreBump).Minutes()
		if quietMin > 0 {
			fade := int(quietMin * float64(rate))
			if fade > 0 {
				score -= fade
				if score < 0 {
					score = 0
				}
			}
		}
	}

	// PoW cap — if this session has cleared the proof-of-work gate within
	// the last hour, bound the visible score at 49. This prevents a
	// Sisyphean loop where a high-risk session solves PoW, immediately
	// trips the threshold again on the next request, and gets challenged
	// repeatedly. The full underlying signal is still available to
	// admin-UI introspection (see SessionView).
	if !s.PowPassedAt.IsZero() && now.Sub(s.PowPassedAt) < time.Hour {
		if score > 49 {
			score = 49
		}
	}
	t.mu.RUnlock()

	// Promote to write lock just long enough to record the result. Skip
	// the write entirely when nothing changed so a steady-state session
	// doesn't fight other mutators for the lock.
	if s.RiskScore == score {
		return score
	}
	t.mu.Lock()
	prev := s.RiskScore
	s.RiskScore = score
	// Only refresh LastScoreBump on UPWARD movement so a decay-driven
	// drop doesn't count as fresh activity that resets the decay clock.
	// Without this guard the decay never converges on a stable score
	// for a quiet session.
	if score > prev {
		s.LastScoreBump = now
	}
	t.mu.Unlock()
	return score
}

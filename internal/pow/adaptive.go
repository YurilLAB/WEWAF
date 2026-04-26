package pow

import (
	"sync"
	"sync/atomic"
	"time"
)

// AdaptiveTier wraps a PoW Issuer with reputation-weighted difficulty
// tier-2 management. Where the base Issuer maps a single risk score to a
// fixed bit count, this layer composes four independent signals and only
// then asks the Issuer to clamp into its [min,max] window.
//
// Inputs (all 0..1, summed with weights):
//
//	risk      session risk score / 100 — primary contributor
//	failRate  per-IP recent solve-fail rate over the last 5 min
//	loadHint  global system-load hint set by the DDoS detector (0 idle, 1 attack)
//	rareFP    1 - (JA4 fingerprint global popularity, 0..1) — rare fingerprints
//	          score harder; widely-used fingerprints stay near the floor.
//
// Output is in *additive bits over min*. The Issuer applies its own
// [min,max] clamp on Issue(), so callers can pass garbage and still get
// a safe result.
//
// Tier-2 escalation: if an IP has failed N PoW challenges in a 1-hour
// window we add a flat penalty for the next hour. This is the
// Cloudflare-style "you've been bad, please re-establish trust" signal.
type AdaptiveTier struct {
	issuer *Issuer

	// Per-IP failure tracker. Keys are IP strings; values are
	// (failures, lastFail, escalatedUntil). All accesses go through
	// the mu lock — operations are short and contention is low because
	// the hot path is read-only when an IP isn't in the map.
	mu      sync.RWMutex
	rep     map[string]*ipRep
	cap     int // max entries before random-drop eviction

	// Atomic counters for the admin UI.
	tierBumps    atomic.Uint64
	totalQueries atomic.Uint64

	// Global system-load hint (0..1). Set externally by the DDoS
	// detector via SetLoadHint. Atomic so the hot path stays lock-free.
	loadBits atomic.Uint64 // store float64 bits via math.Float64bits

	// Tier-2 thresholds (defaults baked in; not currently exposed).
	tier2Failures   uint32        // # fails in tier2Window before escalation
	tier2Window     time.Duration // sliding window for fail counting
	tier2Penalty    uint8         // bits added to the floor while escalated
	tier2Cooldown   time.Duration // how long the escalation lasts
}

type ipRep struct {
	failures        uint32
	firstFailAt     time.Time
	lastFailAt      time.Time
	escalatedUntil  time.Time
}

// NewAdaptiveTier wraps an Issuer with the default Tier-2 parameters.
func NewAdaptiveTier(issuer *Issuer) *AdaptiveTier {
	return &AdaptiveTier{
		issuer:        issuer,
		rep:           make(map[string]*ipRep, 1024),
		cap:           65536,
		tier2Failures: 5,
		tier2Window:   time.Hour,
		tier2Penalty:  3,
		tier2Cooldown: time.Hour,
	}
}

// SetLoadHint takes a 0..1 system-load value (typically derived from
// DDoSDetector.Stats() — fraction of windows in attack state). Concurrent-
// safe; cheaper than a config reload because it's hit on every Issue.
func (a *AdaptiveTier) SetLoadHint(load float64) {
	if a == nil {
		return
	}
	if load < 0 {
		load = 0
	} else if load > 1 {
		load = 1
	}
	// Store via uint64 bits — math.Float64bits is the canonical way but
	// avoiding the math import here; we use a lossy 12-bit fixed-point
	// since 4096 levels is way more resolution than the input deserves.
	q := uint64(load * 4095)
	a.loadBits.Store(q)
}

func (a *AdaptiveTier) loadHint() float64 {
	if a == nil {
		return 0
	}
	return float64(a.loadBits.Load()) / 4095.0
}

// Recommend returns the difficulty bits to issue. Inputs:
//
//	ip       client IP (used for tier-2 escalation lookup; "" disables)
//	score    session risk score 0..100
//	rareFP   1 - JA4 popularity, 0..1 — pass 0 if popularity unknown
//
// Output is clamped by the Issuer on Issue(); callers don't need to clamp.
func (a *AdaptiveTier) Recommend(ip string, score int, rareFP float64) uint8 {
	if a == nil || a.issuer == nil {
		return DefaultMinDifficulty
	}
	a.totalQueries.Add(1)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if rareFP < 0 {
		rareFP = 0
	} else if rareFP > 1 {
		rareFP = 1
	}

	// Base via the Issuer (its [min..max] window is the truth source).
	base := a.issuer.SuggestDifficulty(score)

	// Additive bits from secondary signals. Numbers are deliberately
	// small — combined max ≈ 6 bits over the base floor before the
	// Issuer's own max clamp kicks in. That's a 64× cost multiplier
	// for highly-suspicious clients, plenty of friction.
	failRate := a.recentFailRate(ip)
	add := 0.0
	add += rareFP * 2.0          // rare JA4 → up to +2 bits
	add += failRate * 2.0         // recent fails → up to +2 bits
	add += a.loadHint() * 2.0     // global load → up to +2 bits

	bump := uint8(add + 0.5)

	// Tier-2 escalation penalty. We must hold the RLock while reading
	// r.escalatedUntil — RecordFailure / RecordSuccess mutate that field
	// under the write lock, and reading time.Time concurrently is at
	// best a torn read and at worst a logical race that misclassifies
	// the escalation window.
	if ip != "" {
		a.mu.RLock()
		if r, ok := a.rep[ip]; ok && time.Now().Before(r.escalatedUntil) {
			a.mu.RUnlock()
			bump += a.tier2Penalty
			a.tierBumps.Add(1)
		} else {
			a.mu.RUnlock()
		}
	}

	d := base + bump
	// Issuer.Issue will clamp to its own max. We just guard against
	// overflow on the uint8 add itself.
	if d < base {
		d = 255 // saturated; Issuer max will floor it
	}
	return d
}

// RecordFailure logs a failed PoW solve for the given IP. Bumps the
// per-IP fail counter; if the threshold is reached, sets the
// escalatedUntil timestamp. Backwards-bounded by tier2Window.
func (a *AdaptiveTier) RecordFailure(ip string) {
	if a == nil || ip == "" {
		return
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.rep) >= a.cap {
		// Random-drop to keep the map bounded. Old escalations expire
		// naturally; we just need to stop unbounded growth from a
		// distributed grinder.
		dropped := 0
		for k := range a.rep {
			delete(a.rep, k)
			dropped++
			if dropped >= 64 {
				break
			}
		}
	}

	r := a.rep[ip]
	if r == nil {
		r = &ipRep{firstFailAt: now}
		a.rep[ip] = r
	}
	// Reset window if the previous burst is older than tier2Window.
	if now.Sub(r.firstFailAt) > a.tier2Window {
		r.firstFailAt = now
		r.failures = 0
	}
	r.failures++
	r.lastFailAt = now

	if r.failures >= a.tier2Failures && now.After(r.escalatedUntil) {
		r.escalatedUntil = now.Add(a.tier2Cooldown)
		a.tierBumps.Add(1)
	}
}

// RecordSuccess decays the failure counter for the IP. We don't reset
// outright — a successful solve right after 4 fails should still carry
// some weight. Halve the counter and clear escalation if it dropped
// below the threshold.
func (a *AdaptiveTier) RecordSuccess(ip string) {
	if a == nil || ip == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.rep[ip]
	if r == nil {
		return
	}
	r.failures /= 2
	if r.failures < a.tier2Failures {
		r.escalatedUntil = time.Time{}
	}
	if r.failures == 0 {
		// Clean up clean IPs to keep the map small.
		delete(a.rep, ip)
	}
}

// Sweep prunes entries whose escalation has expired AND failure window
// has rolled off. Cheap; call from a housekeeper alongside the Issuer
// sweep.
func (a *AdaptiveTier) Sweep() int {
	if a == nil {
		return 0
	}
	now := time.Now()
	cutoff := now.Add(-a.tier2Window).Add(-a.tier2Cooldown)
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := 0
	for k, r := range a.rep {
		if r.lastFailAt.Before(cutoff) && now.After(r.escalatedUntil) {
			delete(a.rep, k)
			removed++
		}
	}
	return removed
}

// recentFailRate returns failures/window normalized to 0..1 for the
// given IP. 0 if unknown. Reads happen under the RLock — RecordFailure
// mutates r.failures under the write lock, so dereferencing the
// returned pointer outside the lock is a data race that the race
// detector would flag and that produces wrong rates in practice.
func (a *AdaptiveTier) recentFailRate(ip string) float64 {
	if ip == "" {
		return 0
	}
	a.mu.RLock()
	r, ok := a.rep[ip]
	if !ok {
		a.mu.RUnlock()
		return 0
	}
	failures := r.failures
	a.mu.RUnlock()
	// Normalize: each fail beyond the first contributes 1/(threshold)
	// up to a ceiling of 1.
	v := float64(failures) / float64(a.tier2Failures)
	if v > 1 {
		v = 1
	}
	return v
}

// AdaptiveStats is the snapshot for the admin UI.
type AdaptiveStats struct {
	IPsTracked   int     `json:"ips_tracked"`
	TierBumps    uint64  `json:"tier_bumps"`
	TotalQueries uint64  `json:"total_queries"`
	LoadHint     float64 `json:"load_hint"`
}

func (a *AdaptiveTier) Stats() AdaptiveStats {
	if a == nil {
		return AdaptiveStats{}
	}
	a.mu.RLock()
	n := len(a.rep)
	a.mu.RUnlock()
	return AdaptiveStats{
		IPsTracked:   n,
		TierBumps:    a.tierBumps.Load(),
		TotalQueries: a.totalQueries.Load(),
		LoadHint:     a.loadHint(),
	}
}

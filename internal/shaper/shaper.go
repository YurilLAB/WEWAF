// Package shaper provides pre-WAF admission control.
//
// The rule engine, body buffering, and telemetry writes are all cheap on a
// per-request basis, but a determined attacker aiming a flood at those paths
// still causes CPU and memory pressure. The shaper sits at the very front of
// the proxy handler and uses a single global token bucket to decide whether
// a new request even gets to see the rule engine.
//
// Under normal operation the shaper does nothing — the configured MaxRPS is
// set well above realistic traffic. Its value comes when something is
// actively wrong: when ddos.Detector reports under_attack, the proxy tells
// the shaper to tighten, and the ceiling drops to a fraction (default 20%)
// of the base cap. That protects the WAF's own resources so it can keep
// serving the requests it does admit rather than falling over mid-flood.
//
// The shaper exposes a small amount of state so the admin dashboard can show
// operators whether requests are being early-shed and at what rate.
package shaper

import (
	"sync"
	"sync/atomic"
	"time"
)

// Shaper is the admission-control primitive.
type Shaper struct {
	enabled atomic.Bool

	baseMaxRPS int
	baseBurst  int

	mu          sync.Mutex
	maxRPS      float64 // effective rate, after under-attack tightening
	burst       float64 // effective bucket size
	tokens      float64
	lastRefill  time.Time
	tightening  bool

	admitted  atomic.Uint64
	rejected  atomic.Uint64
	tightened atomic.Uint64 // number of times the ceiling has been tightened
}

// Config mirrors the subset of wewaf config the shaper cares about.
type Config struct {
	Enabled bool
	MaxRPS  int
	Burst   int
}

// New constructs a Shaper with the given config.
func New(c Config) *Shaper {
	if c.MaxRPS <= 0 {
		c.MaxRPS = 2000
	}
	if c.Burst <= 0 {
		c.Burst = c.MaxRPS * 2
	}
	s := &Shaper{
		baseMaxRPS: c.MaxRPS,
		baseBurst:  c.Burst,
		maxRPS:     float64(c.MaxRPS),
		burst:      float64(c.Burst),
		tokens:     float64(c.Burst),
		lastRefill: time.Now(),
	}
	s.enabled.Store(c.Enabled)
	return s
}

// SetEnabled flips the shaper on/off at runtime. A disabled shaper is a no-op
// that always returns Admit.
func (s *Shaper) SetEnabled(v bool) {
	s.enabled.Store(v)
}

// Admit returns true if the request should be allowed to proceed. When the
// shaper is disabled (the default) it always returns true.
func (s *Shaper) Admit() bool {
	if s == nil || !s.enabled.Load() {
		if s != nil {
			s.admitted.Add(1)
		}
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Refill based on wall-clock since last call. This means the shaper's
	// time-domain matches request arrivals, which is what you want under
	// bursty load — no background goroutine required.
	elapsed := now.Sub(s.lastRefill).Seconds()
	if elapsed > 0 {
		s.tokens += elapsed * s.maxRPS
		if s.tokens > s.burst {
			s.tokens = s.burst
		}
		s.lastRefill = now
	}
	if s.tokens >= 1 {
		s.tokens--
		s.admitted.Add(1)
		return true
	}
	s.rejected.Add(1)
	return false
}

// Tighten lowers the effective rate and burst to the given fraction of the
// base. The proxy calls this when ddos.Detector says under_attack. Idempotent
// — repeated calls with the same fraction are no-ops.
func (s *Shaper) Tighten(fraction float64) {
	if s == nil || fraction <= 0 {
		return
	}
	if fraction > 1 {
		fraction = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	newMax := float64(s.baseMaxRPS) * fraction
	newBurst := float64(s.baseBurst) * fraction
	if s.maxRPS == newMax && s.burst == newBurst {
		return
	}
	s.maxRPS = newMax
	s.burst = newBurst
	// Don't refund tokens — if we just tightened, any excess bucket would
	// let a lot of traffic slip through.
	if s.tokens > s.burst {
		s.tokens = s.burst
	}
	if !s.tightening {
		s.tightening = true
		s.tightened.Add(1)
	}
}

// Relax restores the configured base rate/burst. The proxy calls this when
// the detector clears under_attack.
func (s *Shaper) Relax() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxRPS = float64(s.baseMaxRPS)
	s.burst = float64(s.baseBurst)
	s.tightening = false
}

// StatsSnapshot is what /api/shaper/stats returns.
func (s *Shaper) StatsSnapshot() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}
	s.mu.Lock()
	maxRPS := s.maxRPS
	burst := s.burst
	tokens := s.tokens
	tightening := s.tightening
	s.mu.Unlock()
	return map[string]interface{}{
		"enabled":        s.enabled.Load(),
		"base_max_rps":   s.baseMaxRPS,
		"base_burst":     s.baseBurst,
		"current_rps":    maxRPS,
		"current_burst":  burst,
		"tokens":         tokens,
		"admitted":       s.admitted.Load(),
		"rejected":       s.rejected.Load(),
		"tightenings":    s.tightened.Load(),
		"under_pressure": tightening,
	}
}

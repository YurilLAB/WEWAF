package limits

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

// ErrOverloaded is returned by AdaptiveLimiter.Acquire when the current
// adaptively-tuned concurrency limit is reached. Callers should SHED the
// request (e.g. respond 503) rather than queue it — fast shedding under
// overload is the whole point, versus the static semaphore which blocks the
// caller until a slot frees or the context deadline fires.
var ErrOverloaded = errors.New("limits: concurrency limit reached (overloaded)")

// AdaptiveLimiter is a self-tuning in-flight concurrency limiter using a
// Netflix-Gradient2-style controller. It grows the admitted-concurrency limit
// while request latency stays near the observed no-load baseline and shrinks it
// (multiplicatively) when latency climbs or requests fail — so the WAF admits
// roughly as much as the backend can actually serve, instead of a fixed cap
// that either admits into a dying backend or throttles a healthy one.
//
// It starts at the maximum (so a healthy system runs at full capacity and the
// limiter only ever *reduces* admission under measured overload — fail-open
// relative to the existing static semaphore) and is non-blocking: at the limit,
// Acquire returns ErrOverloaded immediately.
type AdaptiveLimiter struct {
	mu       sync.Mutex
	limit    float64 // current soft limit (kept as float for smooth AIMD)
	inFlight int
	min      float64
	max      float64

	rttMin    float64 // rolling no-load baseline RTT, nanoseconds
	rttSmooth float64 // EWMA of sampled RTT, nanoseconds
	samples   uint64
}

// Controller tuning constants. Chosen conservatively: the limiter reacts within
// a handful of samples but won't oscillate.
const (
	alRTTAlpha    = 0.2    // EWMA weight for the sampled RTT
	alRTTMinDecay = 0.0005 // slow upward drift of the baseline so it tracks reality
	alGradientLo  = 0.5    // floor on the gradient => at most halve the limit per step
	alDropFactor  = 0.9    // multiplicative decrease on a failed/timed-out request
	alSmooth      = 0.5    // blend between current and freshly-computed limit
)

// NewAdaptiveLimiter returns a limiter clamped to [min,max], starting at max.
func NewAdaptiveLimiter(min, max int) *AdaptiveLimiter {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	return &AdaptiveLimiter{
		limit: float64(max),
		min:   float64(min),
		max:   float64(max),
	}
}

// Acquire admits a request if in-flight is below the current limit, else returns
// ErrOverloaded (or the context error if already cancelled). Non-blocking.
func (a *AdaptiveLimiter) Acquire(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if float64(a.inFlight) >= a.limit {
		return ErrOverloaded
	}
	a.inFlight++
	return nil
}

// Release returns a slot and feeds the controller the request's latency and
// whether it failed (5xx / breaker / timeout). rtt<=0 only decrements in-flight
// (no controller update).
func (a *AdaptiveLimiter) Release(rtt time.Duration, dropped bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight > 0 {
		a.inFlight--
	}
	a.observe(rtt, dropped)
}

func (a *AdaptiveLimiter) observe(rtt time.Duration, dropped bool) {
	r := float64(rtt)
	if r <= 0 {
		return
	}
	a.samples++
	if a.rttSmooth == 0 {
		a.rttSmooth = r
	} else {
		a.rttSmooth = a.rttSmooth*(1-alRTTAlpha) + r*alRTTAlpha
	}
	// Track the rolling minimum (no-load baseline). A new low pins it; otherwise
	// let it drift slowly upward toward the smoothed RTT so a single fast sample
	// early on doesn't make every later sample look "slow" forever.
	if a.rttMin == 0 || r < a.rttMin {
		a.rttMin = r
	} else {
		a.rttMin += (a.rttSmooth - a.rttMin) * alRTTMinDecay
	}

	if dropped {
		a.limit = math.Max(a.min, a.limit*alDropFactor)
		return
	}

	// Gradient2: gradient = baseline/current in (0,1]. queue headroom = sqrt(limit).
	gradient := a.rttMin / a.rttSmooth
	if gradient > 1 {
		gradient = 1
	}
	if gradient < alGradientLo {
		gradient = alGradientLo
	}
	newLimit := a.limit*gradient + math.Sqrt(a.limit)
	a.limit = a.limit*(1-alSmooth) + newLimit*alSmooth
	a.limit = math.Max(a.min, math.Min(a.max, a.limit))
}

// Limit returns the current admission limit (rounded down).
func (a *AdaptiveLimiter) Limit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return int(a.limit)
}

// InFlight returns the current in-flight count.
func (a *AdaptiveLimiter) InFlight() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inFlight
}

// LoadFraction reports how far the admission limit has shrunk from max toward
// min, as 0..1 (0 = at max / healthy, 1 = at min / maximally constrained).
// Returns 0 when min==max. Used as a system-load signal for priority shedding.
func (a *AdaptiveLimiter) LoadFraction() float64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	span := a.max - a.min
	if span <= 0 {
		return 0
	}
	frac := (a.max - a.limit) / span
	if frac < 0 {
		return 0
	}
	if frac > 1 {
		return 1
	}
	return frac
}

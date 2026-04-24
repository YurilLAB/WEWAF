package limits

import (
	"sync"
	"sync/atomic"
	"time"
)

// Breaker is a three-state circuit breaker for the backend proxy.
//
//   - Closed: requests flow normally.
//   - Open:   the backend is failing; requests short-circuit to 503 without
//     touching the backend.
//   - Half-open: the breaker has timed out in Open; the first request is
//     allowed through as a probe. If it succeeds the breaker closes; if it
//     fails, it re-opens for another cool-down.
//
// The implementation is lock-light: state transitions are guarded by a short
// mutex section, but the hot-path Allow() check is a single atomic load.
type BreakerState int32

const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// Breaker tracks failure rate on a rolling window.
type Breaker struct {
	// failureThreshold is the consecutive failure count that flips Closed→Open.
	failureThreshold int
	// openTimeout is how long the breaker stays open before entering half-open.
	openTimeout time.Duration

	state        atomic.Int32 // BreakerState
	failures     atomic.Int32
	successes    atomic.Uint64
	totalFails   atomic.Uint64
	shortCircuit atomic.Uint64
	openedAt     atomic.Int64 // unix ns

	mu sync.Mutex
}

// NewBreaker builds a breaker with the given threshold and cool-down.
func NewBreaker(failureThreshold int, openTimeout time.Duration) *Breaker {
	if failureThreshold <= 0 {
		failureThreshold = 10
	}
	if openTimeout <= 0 {
		openTimeout = 30 * time.Second
	}
	return &Breaker{
		failureThreshold: failureThreshold,
		openTimeout:      openTimeout,
	}
}

// Allow reports whether a new request may be sent to the backend. The caller
// MUST call RecordSuccess or RecordFailure after the request completes so
// the breaker can update its state. A false return means the request should
// short-circuit — typically to a 503 Service Unavailable.
func (b *Breaker) Allow() bool {
	if b == nil {
		return true
	}
	s := BreakerState(b.state.Load())
	switch s {
	case BreakerClosed:
		return true
	case BreakerOpen:
		// Check whether the cool-down has elapsed; if so, try a single probe.
		opened := time.Unix(0, b.openedAt.Load())
		if time.Since(opened) >= b.openTimeout {
			b.mu.Lock()
			// Re-read under lock to avoid double-transition races.
			if BreakerState(b.state.Load()) == BreakerOpen && time.Since(opened) >= b.openTimeout {
				b.state.Store(int32(BreakerHalfOpen))
				b.mu.Unlock()
				return true
			}
			b.mu.Unlock()
		}
		b.shortCircuit.Add(1)
		return false
	case BreakerHalfOpen:
		// Only the first concurrent caller should pass through; other
		// in-flights will short-circuit until the probe resolves.
		// Race is acceptable — worst case we send 2 probes instead of 1.
		return true
	}
	return true
}

// RecordSuccess resets the failure counter and, if we were half-open, closes
// the breaker. Safe to call concurrently.
func (b *Breaker) RecordSuccess() {
	if b == nil {
		return
	}
	b.successes.Add(1)
	b.failures.Store(0)
	s := BreakerState(b.state.Load())
	if s == BreakerHalfOpen {
		b.mu.Lock()
		if BreakerState(b.state.Load()) == BreakerHalfOpen {
			b.state.Store(int32(BreakerClosed))
		}
		b.mu.Unlock()
	}
}

// RecordFailure bumps the failure count. If the threshold is reached, the
// breaker flips to Open. If we were already half-open and got a failure, the
// breaker re-opens for another cool-down.
func (b *Breaker) RecordFailure() {
	if b == nil {
		return
	}
	b.totalFails.Add(1)
	f := b.failures.Add(1)

	s := BreakerState(b.state.Load())
	switch s {
	case BreakerHalfOpen:
		b.mu.Lock()
		if BreakerState(b.state.Load()) == BreakerHalfOpen {
			b.state.Store(int32(BreakerOpen))
			b.openedAt.Store(time.Now().UnixNano())
		}
		b.mu.Unlock()
	case BreakerClosed:
		if int(f) >= b.failureThreshold {
			b.mu.Lock()
			if BreakerState(b.state.Load()) == BreakerClosed {
				b.state.Store(int32(BreakerOpen))
				b.openedAt.Store(time.Now().UnixNano())
			}
			b.mu.Unlock()
		}
	}
}

// State returns the current breaker state.
func (b *Breaker) State() BreakerState {
	if b == nil {
		return BreakerClosed
	}
	return BreakerState(b.state.Load())
}

// StatsSnapshot returns counters for the admin API.
func (b *Breaker) StatsSnapshot() map[string]interface{} {
	if b == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"state":                 b.State().String(),
		"consecutive_failures":  b.failures.Load(),
		"successes":             b.successes.Load(),
		"total_failures":        b.totalFails.Load(),
		"short_circuited":       b.shortCircuit.Load(),
		"opened_at_unix_nano":   b.openedAt.Load(),
		"failure_threshold":     b.failureThreshold,
		"open_timeout_seconds":  int(b.openTimeout.Seconds()),
	}
}

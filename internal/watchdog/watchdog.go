// Package watchdog periodically checks that WEWAF's critical subsystems are
// alive and responsive. Each check returns a Health record with a status
// tag and a human-readable message; the aggregated state is exposed at
// /api/health/detail so operators can see exactly which subsystem is
// degraded without tailing logs.
//
// Watchdog runs on its own goroutine with a generous timeout so a stuck
// subsystem cannot stall the whole process. If any check returns a Fail
// status, the watchdog increments a counter and records the event so the
// Errors page shows it.
package watchdog

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Status describes one subsystem's current state.
type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusFail     Status = "fail"
)

// Health is one subsystem's most recent check outcome.
type Health struct {
	Subsystem string                 `json:"subsystem"`
	Status    Status                 `json:"status"`
	Message   string                 `json:"message"`
	Detail    map[string]interface{} `json:"detail,omitempty"`
	At        time.Time              `json:"at"`
}

// CheckFunc is the function signature each subsystem registers with the
// watchdog. It should return promptly — the watchdog applies a 2-second
// cap around each invocation via context.
type CheckFunc func(ctx context.Context) Health

// Watchdog is the aggregator.
type Watchdog struct {
	interval time.Duration
	checks   []registered

	mu       sync.RWMutex
	last     map[string]Health
	failures atomic.Uint64

	stopOnce sync.Once
	stopCh   chan struct{}
	onFail   func(Health) // invoked for every StatusFail result
}

type registered struct {
	name string
	fn   CheckFunc
}

// New creates a watchdog that runs its registered checks every interval.
func New(interval time.Duration) *Watchdog {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Watchdog{
		interval: interval,
		last:     make(map[string]Health),
		stopCh:   make(chan struct{}),
	}
}

// Register adds a check to the rotation. Safe before Start only.
func (w *Watchdog) Register(name string, fn CheckFunc) {
	w.checks = append(w.checks, registered{name: name, fn: fn})
}

// OnFail installs a callback fired every time a check returns StatusFail.
// Typically wired to Server.RecordError so the error surfaces in the UI.
func (w *Watchdog) OnFail(fn func(Health)) { w.onFail = fn }

// Start launches the background loop.
func (w *Watchdog) Start(ctx context.Context) {
	go w.loop(ctx)
}

// Stop halts the loop.
func (w *Watchdog) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

func (w *Watchdog) loop(ctx context.Context) {
	defer func() { _ = recover() }()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	// Prime with one immediate pass so /api/health/detail isn't empty.
	w.runAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.runAll(ctx)
		}
	}
}

func (w *Watchdog) runAll(parent context.Context) {
	for _, c := range w.checks {
		func(c registered) {
			defer func() {
				if rec := recover(); rec != nil {
					h := Health{
						Subsystem: c.name,
						Status:    StatusFail,
						Message:   "check panicked",
						At:        time.Now().UTC(),
					}
					w.record(h)
				}
			}()
			ctx, cancel := context.WithTimeout(parent, 2*time.Second)
			defer cancel()
			h := c.fn(ctx)
			h.Subsystem = c.name
			if h.At.IsZero() {
				h.At = time.Now().UTC()
			}
			w.record(h)
		}(c)
	}
}

func (w *Watchdog) record(h Health) {
	w.mu.Lock()
	w.last[h.Subsystem] = h
	w.mu.Unlock()
	if h.Status == StatusFail {
		w.failures.Add(1)
		if w.onFail != nil {
			w.onFail(h)
		}
	}
}

// Snapshot returns a stable view of every subsystem's latest result.
func (w *Watchdog) Snapshot() []Health {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Health, 0, len(w.last))
	for _, h := range w.last {
		out = append(out, h)
	}
	return out
}

// Failures returns the lifetime count of StatusFail results.
func (w *Watchdog) Failures() uint64 {
	return w.failures.Load()
}

// Overall returns the worst status across all subsystems. OK unless any
// check failed/degraded.
func (w *Watchdog) Overall() Status {
	w.mu.RLock()
	defer w.mu.RUnlock()
	worst := StatusOK
	for _, h := range w.last {
		if h.Status == StatusFail {
			return StatusFail
		}
		if h.Status == StatusDegraded {
			worst = StatusDegraded
		}
	}
	return worst
}

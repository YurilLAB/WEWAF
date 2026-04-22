package limits

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// Apply configures OS-level and runtime-level resource constraints.
func Apply(maxCPU int, maxMemMB int64) error {
	if maxCPU > 0 {
		runtime.GOMAXPROCS(maxCPU)
	} else {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	if maxMemMB > 0 {
		limit := maxMemMB * 1024 * 1024
		debug.SetMemoryLimit(limit)
	} else {
		// Remove any previous limit.
		debug.SetMemoryLimit(-1)
	}

	return nil
}

// Semaphore is a simple counting semaphore for concurrency control.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a semaphore with the given capacity.
func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
}

// Acquire blocks until a slot is available or the context is cancelled.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot. It is safe to call even if unpaired (no-op).
func (s *Semaphore) Release() {
	select {
	case <-s.ch:
	default:
		// Unpaired release; ignore to avoid panic.
	}
}

// Available returns the number of free slots.
func (s *Semaphore) Available() int {
	return cap(s.ch) - len(s.ch)
}

// rateBucket holds token-bucket state for a single IP.
type rateBucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter implements a per-IP token-bucket rate limiter.
type RateLimiter struct {
	mu       sync.RWMutex
	buckets  map[string]*rateBucket
	rps      float64
	burst    float64
	stop     chan struct{}
	stopOnce sync.Once
}

// NewRateLimiter creates a rate limiter and starts a background janitor.
func NewRateLimiter(rps, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*rateBucket),
		rps:     float64(rps),
		burst:   float64(burst),
		stop:    make(chan struct{}),
	}
	go rl.janitor()
	return rl
}

// Allow checks whether a single request from ip is permitted under the rate limit.
func (rl *RateLimiter) Allow(ip string) bool {
	if rl.rps <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &rateBucket{tokens: rl.burst - 1, last: now}
		rl.buckets[ip] = b
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(rl.burst, b.tokens+elapsed*rl.rps)
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Stop halts the background janitor goroutine.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stop)
	})
}

// janitor removes stale buckets every 5 minutes.
func (rl *RateLimiter) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, b := range rl.buckets {
				if now.Sub(b.last) > 10*time.Minute {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

// Stats returns current resource usage.
func Stats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]interface{}{
		"goroutines":    runtime.NumGoroutine(),
		"cpu_cores":     runtime.GOMAXPROCS(0),
		"memory_used_mb": fmt.Sprintf("%.2f", float64(m.Alloc)/(1024*1024)),
		"memory_sys_mb":  fmt.Sprintf("%.2f", float64(m.Sys)/(1024*1024)),
		"gc_count":       m.NumGC,
	}
}

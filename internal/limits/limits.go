package limits

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// Apply configures OS-level and runtime-level resource constraints.
func Apply(maxCPU int, maxMemMB int64) error {
	if maxCPU > 0 {
		runtime.GOMAXPROCS(maxCPU)
	}

	if maxMemMB > 0 {
		limit := maxMemMB * 1024 * 1024
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("panic recovered in debug.SetMemoryLimit: %v", r)
				}
			}()
			debug.SetMemoryLimit(limit)
		}()
	} else {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("panic recovered in debug.SetMemoryLimit: %v", r)
				}
			}()
			debug.SetMemoryLimit(-1)
		}()
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
	if s == nil {
		log.Println("warning: Semaphore.Acquire called on nil semaphore")
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot. It is safe to call even if unpaired (no-op).
func (s *Semaphore) Release() {
	if s == nil {
		return
	}
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

const maxBuckets = 1_000_000

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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in RateLimiter.Allow: %v", r)
		}
	}()

	if rl.rps <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		// Bounded random-drop eviction. Scanning 1M buckets to find "oldest"
		// while holding the write lock would stall every caller; Go's map
		// iteration is already randomised, so dropping a small sample is an
		// unbiased eviction that runs in O(budget).
		if len(rl.buckets) >= maxBuckets {
			dropBudget := 128
			for k := range rl.buckets {
				delete(rl.buckets, k)
				dropBudget--
				if dropBudget <= 0 {
					break
				}
			}
		}
		b = &rateBucket{tokens: rl.burst - 1, last: now}
		rl.buckets[ip] = b
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	// Cap at burst, NOT burst*2 — the latter let a long-idle client
	// burst at 2× the configured ceiling, which surprises operators
	// reading the config and (more importantly) breaks the
	// rate-limit invariant the tests document.
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

// janitor removes stale buckets every 5 minutes. To avoid stalling
// hot-path Allow callers on a million-entry map, the sweep is split
// across multiple short chunks per tick with a 1ms yield between them.
// We cap the work at maxChunksPerTick so the janitor never busy-loops
// on a permanently-full map: any entries we miss this tick are picked
// up next tick, which is the right trade — Go's randomised map
// iteration is unbiased so eviction probability is uniform.
func (rl *RateLimiter) janitor() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in RateLimiter.janitor: %v", r)
		}
	}()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.sweepOnce()
		case <-rl.stop:
			return
		}
	}
}

// sweepOnce performs one bounded sweep pass. It runs at most
// maxChunksPerTick chunks of chunkSize entries, with a brief yield
// between chunks so concurrent Allow callers aren't starved.
func (rl *RateLimiter) sweepOnce() {
	const (
		chunkSize        = 4096
		maxChunksPerTick = 64 // ≤ 256k entries scanned per tick worst-case
	)
	cutoff := time.Now().Add(-10 * time.Minute)
	for i := 0; i < maxChunksPerTick; i++ {
		if done := rl.sweepChunk(chunkSize, cutoff); done {
			return
		}
		// Allow a quick observer interrupt between chunks instead
		// of a hard sleep — Stop() should unblock the next tick.
		select {
		case <-rl.stop:
			return
		case <-time.After(time.Millisecond):
		}
	}
}

// sweepChunk evicts up to budget stale entries. Returns true when the
// scan reached the end of the map (i.e., no further chunks needed).
func (rl *RateLimiter) sweepChunk(budget int, cutoff time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	scanned := 0
	for ip, b := range rl.buckets {
		scanned++
		if b.last.Before(cutoff) {
			delete(rl.buckets, ip)
		}
		if scanned >= budget {
			return false
		}
	}
	return true
}

// Stats returns current resource usage.
func Stats() map[string]interface{} {
	result := map[string]interface{}{
		"goroutines":     0,
		"cpu_cores":      0,
		"memory_used_mb": "0.00",
		"memory_sys_mb":  "0.00",
		"gc_count":       0,
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in Stats: %v", r)
		}
	}()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	result["goroutines"] = runtime.NumGoroutine()
	result["cpu_cores"] = runtime.GOMAXPROCS(0)
	result["memory_used_mb"] = fmt.Sprintf("%.2f", float64(m.Alloc)/(1024*1024))
	result["memory_sys_mb"] = fmt.Sprintf("%.2f", float64(m.Sys)/(1024*1024))
	result["gc_count"] = m.NumGC
	return result
}

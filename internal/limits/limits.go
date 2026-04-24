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
	b.tokens = min(rl.burst*2, b.tokens+elapsed*rl.rps)
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

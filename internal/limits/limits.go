package limits

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
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

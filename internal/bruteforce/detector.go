package bruteforce

import (
	"fmt"
	"sync"
	"time"
)

// Detector tracks login attempts per key (e.g., IP or IP:user) in a sliding window.
type Detector struct {
	mu       sync.RWMutex
	window   time.Duration
	entries  map[string]*entry
	ticker   *time.Ticker
	stopCh   chan struct{}
	stopOnce sync.Once
}

type entry struct {
	attempts []time.Time
}

// NewDetector creates a brute-force detector with the given window.
func NewDetector(window time.Duration) *Detector {
	if window <= 0 {
		window = time.Minute
	}
	d := &Detector{
		window:  window,
		entries: make(map[string]*entry),
		stopCh:  make(chan struct{}),
	}
	// Start a background janitor to evict stale entries.
	d.ticker = time.NewTicker(window / 2)
	go d.janitor()
	return d
}

// Record increments the attempt counter for a key and returns the current count.
func (d *Detector) Record(key string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	e, ok := d.entries[key]
	if !ok {
		e = &entry{}
		d.entries[key] = e
	}
	e.attempts = append(e.attempts, now)
	// Trim old attempts outside the window.
	cutoff := now.Add(-d.window)
	idx := len(e.attempts)
	for i, t := range e.attempts {
		if t.After(cutoff) {
			idx = i
			break
		}
	}
	e.attempts = e.attempts[idx:]
	return len(e.attempts)
}

// Count returns the number of attempts for a key in the current window.
func (d *Detector) Count(key string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, ok := d.entries[key]
	if !ok {
		return 0
	}
	cutoff := time.Now().UTC().Add(-d.window)
	count := 0
	for _, t := range e.attempts {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// IsBruteForce reports whether the key has exceeded the threshold.
func (d *Detector) IsBruteForce(key string, threshold int) bool {
	return d.Count(key) >= threshold
}

// Stop halts the background janitor.
func (d *Detector) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		d.ticker.Stop()
	})
}

func (d *Detector) janitor() {
	for {
		select {
		case <-d.ticker.C:
			d.evict()
		case <-d.stopCh:
			return
		}
	}
}

func (d *Detector) evict() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().UTC().Add(-d.window)
	for k, e := range d.entries {
		idx := -1
		for i, t := range e.attempts {
			if t.After(cutoff) {
				idx = i
				break
			}
		}
		if idx == -1 {
			delete(d.entries, k)
		} else if idx > 0 {
			e.attempts = e.attempts[idx:]
		}
	}
}

// Key formats a key from an IP and optional username.
func Key(ip, user string) string {
	if user == "" {
		return ip
	}
	return fmt.Sprintf("%s:%s", ip, user)
}

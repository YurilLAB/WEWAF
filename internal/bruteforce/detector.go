package bruteforce

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	maxAttemptsPerEntry = 10000
	maxEntries          = 100000
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
		log.Println("warning: bruteforce detector window must be > 0, defaulting to 5 minutes")
		window = 5 * time.Minute
	}
	d := &Detector{
		window:  window,
		entries: make(map[string]*entry),
		stopCh:  make(chan struct{}),
	}
	// Start a background janitor to evict stale entries with jitter.
	jitter := time.Duration(0)
	if wb := window / 10; wb > 0 {
		jitter = time.Duration(time.Now().UnixNano() % int64(wb))
	}
	d.ticker = time.NewTicker(window/2 + jitter)
	go d.janitor()
	return d
}

// Record increments the attempt counter for a key and returns the current count.
func (d *Detector) Record(key string) int {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in bruteforce Record: %v", r)
		}
	}()

	if key == "" {
		return 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	e, ok := d.entries[key]
	if !ok {
		// Two-phase eviction: first drop entries whose latest attempt is
		// outside the window (they were going to be swept anyway); if that
		// didn't free enough, random-drop a larger sample. Scaling the
		// budget to ~1% of capacity means 1000 drops per overflow, which
		// covers sustained rotating-IP floods without stalling the lock
		// (each delete is O(1) on Go's map).
		if len(d.entries) >= maxEntries {
			cutoff := now.Add(-d.window)
			scanBudget := 256
			for k, e := range d.entries {
				if len(e.attempts) == 0 || e.attempts[len(e.attempts)-1].Before(cutoff) {
					delete(d.entries, k)
				}
				scanBudget--
				if scanBudget <= 0 {
					break
				}
			}
			if len(d.entries) >= maxEntries {
				dropBudget := maxEntries / 100 // 1%
				for k := range d.entries {
					delete(d.entries, k)
					dropBudget--
					if dropBudget <= 0 {
						break
					}
				}
			}
		}
		e = &entry{}
		d.entries[key] = e
	}
	e.attempts = append(e.attempts, now)
	// Cap to prevent unbounded memory growth under sustained attack.
	if len(e.attempts) > maxAttemptsPerEntry {
		e.attempts = e.attempts[len(e.attempts)-maxAttemptsPerEntry:]
	}
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
	if d.window <= 0 {
		return 0
	}
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in bruteforce IsBruteForce: %v", r)
		}
	}()
	if threshold <= 0 {
		threshold = 1
	}
	return d.Count(key) >= threshold
}

// Reset manually clears an IP's attempt history.
func (d *Detector) Reset(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.entries, key)
}

// Stop halts the background janitor.
func (d *Detector) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		d.ticker.Stop()
	})
}

func (d *Detector) janitor() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in bruteforce janitor: %v", r)
		}
	}()
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in bruteforce evict: %v", r)
		}
	}()
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

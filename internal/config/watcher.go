package config

import (
	"log"
	"os"
	"sync"
	"time"
)

// Watcher polls a config file's mtime and invokes a callback when it changes.
// Polling avoids a platform-specific fsnotify dependency and sidesteps the
// inotify CLOSE_WRITE vs RENAME subtleties editors like vim trigger. A fresh
// Load + Validate happens before the callback so the caller never sees a
// half-parsed file.
type Watcher struct {
	path     string
	interval time.Duration
	onChange func(*Config)

	stopCh   chan struct{}
	stopOnce sync.Once
	lastMod  time.Time
}

// NewWatcher returns a polling watcher. A non-positive interval defaults to 5s.
func NewWatcher(path string, interval time.Duration, onChange func(*Config)) *Watcher {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		path:     path,
		interval: interval,
		onChange: onChange,
		stopCh:   make(chan struct{}),
	}
}

// Start runs the watcher in a background goroutine. No-op if path is empty.
func (w *Watcher) Start() {
	if w == nil || w.path == "" {
		return
	}
	go w.loop()
}

// Stop halts the watcher. Safe to call multiple times.
func (w *Watcher) Stop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() { close(w.stopCh) })
}

func (w *Watcher) loop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("config.Watcher: loop panic: %v", r)
		}
	}()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	if st, err := os.Stat(w.path); err == nil {
		w.lastMod = st.ModTime()
	}

	// Back off aggressively if the last N reloads all failed — a user
	// editing a config with a syntax error shouldn't get a log line every
	// 5 seconds until they fix it. Resets as soon as one load succeeds.
	const maxFailureBackoff = 12 // ~1 minute at 5 s cadence
	failureStreak := 0

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			st, err := os.Stat(w.path)
			if err != nil {
				// ENOENT during an atomic rename (vim's default save) is
				// expected — swallow the miss and try again next tick.
				continue
			}
			if !st.ModTime().After(w.lastMod) {
				continue
			}
			// Wait a full tick after a failed reload before retrying, and
			// scale up to ~1 minute if the operator has a broken config.
			if failureStreak > 0 {
				skip := failureStreak - 1
				if skip > maxFailureBackoff {
					skip = maxFailureBackoff
				}
				if skip > 0 {
					failureStreak++ // count the skip itself so we don't hammer
					if failureStreak%2 != 0 {
						continue
					}
				}
			}
			w.lastMod = st.ModTime()
			fresh, err := Load(w.path)
			if err != nil {
				// Zero-byte file is almost certainly an in-progress atomic
				// write; other errors are operator-visible.
				if st.Size() > 0 {
					log.Printf("config.Watcher: reload failed: %v", err)
					failureStreak++
				}
				continue
			}
			if err := fresh.Validate(); err != nil {
				log.Printf("config.Watcher: validate failed (keeping previous config): %v", err)
				failureStreak++
				continue
			}
			failureStreak = 0
			log.Printf("config.Watcher: reloaded %s", w.path)
			if w.onChange != nil {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("config.Watcher: onChange panic: %v", r)
						}
					}()
					w.onChange(fresh)
				}()
			}
		}
	}
}

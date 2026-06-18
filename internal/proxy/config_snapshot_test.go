package proxy

import (
	"sync"
	"testing"
	"time"

	"wewaf/internal/config"
)

// TestConfigSnapshotNoRace proves the hot-path config reads go through the
// atomically-published snapshot (conf()), so they no longer race the config
// writers. The writer mirrors the admin handler / hot-reload watcher: mutate
// the live cfg fields under cfg's lock, then RefreshConfig() to republish the
// snapshot. The reader mirrors the proxy hot path: conf().<field>, including a
// string (FailsafeMode) and a slice (WebSocketOriginAllowlist) where a torn
// read previously risked a panic. Must stay clean under -race.
func TestConfigSnapshotNoRace(t *testing.T) {
	cfg := &config.Config{FailsafeMode: "closed"}
	wp := &WAFProxy{cfg: cfg}
	wp.RefreshConfig()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			cfg.Lock()
			if i%2 == 0 {
				cfg.FailsafeMode = "open"
				cfg.WebSocketOriginAllowlist = []string{"a.example.com", "b.example.com"}
			} else {
				cfg.FailsafeMode = "closed"
				cfg.WebSocketOriginAllowlist = []string{"c.example.com"}
			}
			cfg.Unlock()
			wp.RefreshConfig()
			i++
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c := wp.conf()
			_ = c.FailsafeMode
			for range c.WebSocketOriginAllowlist {
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

package session

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestSessionViewNoRace guards the GET /api/sessions/<id> handler path. It used
// to call Lookup().Snapshot() with no lock held, racing touchSession's map
// writes — a FATAL "concurrent map iteration and map write". Tracker.View now
// snapshots under the read lock; this test drives the writer and the View path
// concurrently and must stay clean under -race.
func TestSessionViewNoRace(t *testing.T) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, MaxSessions: 1000})
	const id = "race-session-id"

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: hammer touchSession with varying paths/UAs/IPs to grow the maps.
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
			r, _ := http.NewRequest(http.MethodGet, "/p"+string(rune('a'+i%20)), nil)
			r.Header.Set("User-Agent", "ua"+string(rune('a'+i%10)))
			r.RemoteAddr = "10.0.0." + string(rune('1'+i%9)) + ":1234"
			tr.touchSession(id, r)
			i++
		}
	}()

	// Reader: the admin handler path — Lookup then Snapshot, no lock held.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = tr.View(id)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

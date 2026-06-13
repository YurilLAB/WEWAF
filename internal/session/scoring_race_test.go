package session

import (
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestScoreConcurrentNoRace exercises the scoring hot path the way the live
// proxy does: many goroutines call Score on the same session while others
// mutate it with fresh requests and blocks (mirroring the proxy hot path plus
// the admin /api/sessions sweep, which both call Score concurrently). Before
// the fix, Score read s.RiskScore without holding the lock — after releasing
// the RLock and before taking the write lock — racing the write a few lines
// down; `go test -race` flags that. This is the regression guard, and the
// final-range assertion proves no torn write corrupted the score.
func TestScoreConcurrentNoRace(t *testing.T) {
	tr := NewTracker(Config{
		Enabled:            true,
		IdleTTL:            time.Minute,
		MaxSessions:        1000,
		RequestRateCeiling: 1,
		PathCountCeiling:   1,
	})
	defer tr.Stop()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s := tr.EnsureSession(w, r)
	if s == nil {
		t.Fatal("EnsureSession returned nil")
	}
	cookies := w.Result().Cookies()

	var wg sync.WaitGroup
	const workers = 16
	const iters = 400
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if g%2 == 0 {
					_ = tr.Score(s.ID)
					continue
				}
				// Mutate the session so the computed score keeps moving,
				// which forces Score down its write path while the readers
				// above are mid-Score.
				rr := httptest.NewRequest("GET", "/p"+strconv.Itoa(i), nil)
				for _, c := range cookies {
					rr.AddCookie(c)
				}
				tr.EnsureSession(httptest.NewRecorder(), rr)
				tr.RecordBlock(s.ID)
			}
		}(g)
	}
	wg.Wait()

	if sc := tr.Score(s.ID); sc < 0 || sc > 100 {
		t.Fatalf("score out of range after concurrent access: %d", sc)
	}
}

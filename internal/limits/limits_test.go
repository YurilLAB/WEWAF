package limits

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiterAllows(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	defer rl.Stop()

	// Burst of 5 should all pass.
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.1.1.1") {
			t.Fatalf("request %d unexpectedly denied during burst", i)
		}
	}
	// 6th token-less request within the same tick should fail.
	if rl.Allow("1.1.1.1") {
		t.Fatalf("expected burst exhaustion to deny request 6")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := NewRateLimiter(100, 2)
	defer rl.Stop()
	rl.Allow("x")
	rl.Allow("x")
	if rl.Allow("x") {
		t.Fatalf("expected third request to be denied immediately")
	}
	// After 20 ms at 100 rps we should have refilled at least 1 token.
	time.Sleep(30 * time.Millisecond)
	if !rl.Allow("x") {
		t.Fatalf("expected refill to allow a request after 30 ms")
	}
}

// TestRateLimiterClockJumpDoesNotSelfDoS reproduces the bug where a
// backwards clock step (NTP slew, suspended-VM resume) drove the
// token bucket negative, denying every subsequent legitimate request
// for minutes until the bucket re-filled past 1. We can't actually
// reach into time.Now(), but we can exercise the same code path by
// rewinding the bucket's `last` field directly — which is what the
// clock-skew condition produces inside Allow().
func TestRateLimiterClockJumpDoesNotSelfDoS(t *testing.T) {
	rl := NewRateLimiter(100, 5)
	defer rl.Stop()
	// Drain the burst.
	for i := 0; i < 5; i++ {
		rl.Allow("ip")
	}
	// Now simulate a backwards clock step by reaching into the
	// bucket and pushing `last` an hour into the future, so the
	// next Allow() sees a deeply-negative elapsed.
	rl.mu.Lock()
	rl.buckets["ip"].last = time.Now().Add(time.Hour)
	rl.mu.Unlock()
	// Without the clamp this Allow goes through math like
	//   tokens = min(5, 0 + (-3600 * 100)) = -360000
	// which then refuses every subsequent caller for an hour.
	// With the clamp, elapsed=0 keeps tokens at 0 and the next
	// natural refill (after a real sleep) re-allows traffic.
	rl.Allow("ip") // rejected, that's fine
	rl.mu.RLock()
	got := rl.buckets["ip"].tokens
	rl.mu.RUnlock()
	if got < 0 {
		t.Fatalf("clock-jump self-DoS: tokens drained to %v (expected >=0)", got)
	}
}

func TestRateLimiterDisabledWhenRPSZero(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	defer rl.Stop()
	for i := 0; i < 100; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("rps=0 should never deny, got deny at i=%d", i)
		}
	}
}

func TestRateLimiterRaceSafe(t *testing.T) {
	rl := NewRateLimiter(1000, 200)
	defer rl.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				rl.Allow("ip-" + itoa(id))
			}
		}(i)
	}
	wg.Wait()
}

func TestBreakerTripsAfterFailures(t *testing.T) {
	b := NewBreaker(3, 50*time.Millisecond)
	if !b.Allow() {
		t.Fatalf("fresh breaker should allow")
	}
	b.RecordFailure()
	b.RecordFailure()
	b.RecordFailure()
	if b.Allow() {
		t.Fatalf("breaker should open after 3 failures")
	}
	// After timeout, breaker enters half-open and allows exactly one probe.
	time.Sleep(60 * time.Millisecond)
	if !b.Allow() {
		t.Fatalf("breaker should allow one probe after open timeout")
	}
	if b.Allow() {
		t.Fatalf("second concurrent probe in half-open must be denied")
	}
	b.RecordSuccess()
	if !b.Allow() {
		t.Fatalf("breaker should close after a successful probe")
	}
}

func TestBreakerHalfOpenReopensOnFailure(t *testing.T) {
	b := NewBreaker(2, 40*time.Millisecond)
	b.RecordFailure()
	b.RecordFailure()
	time.Sleep(50 * time.Millisecond)
	if !b.Allow() {
		t.Fatalf("expected half-open probe slot")
	}
	b.RecordFailure()
	if b.Allow() {
		t.Fatalf("failed probe should re-open the breaker immediately")
	}
}

// itoa is a tiny strconv-free helper so this test file has zero imports
// beyond testing + time + sync.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [10]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

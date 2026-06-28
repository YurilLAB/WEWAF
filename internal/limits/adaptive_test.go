package limits

import (
	"context"
	"testing"
	"time"
)

func TestAdaptiveLimiterAcquireRejectsAtLimit(t *testing.T) {
	a := NewAdaptiveLimiter(1, 1) // limit pinned to 1
	ctx := context.Background()
	if err := a.Acquire(ctx); err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}
	if err := a.Acquire(ctx); err != ErrOverloaded {
		t.Fatalf("second acquire should be ErrOverloaded, got %v", err)
	}
	a.Release(0, false)
	if err := a.Acquire(ctx); err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
}

func TestAdaptiveLimiterAcquireHonorsContext(t *testing.T) {
	a := NewAdaptiveLimiter(1, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Acquire(ctx); err == nil {
		t.Fatal("acquire with cancelled context should error")
	}
}

func TestAdaptiveLimiterInFlightAccounting(t *testing.T) {
	a := NewAdaptiveLimiter(1, 10)
	_ = a.Acquire(context.Background())
	_ = a.Acquire(context.Background())
	if got := a.InFlight(); got != 2 {
		t.Fatalf("inFlight=%d, want 2", got)
	}
	a.Release(time.Millisecond, false)
	if got := a.InFlight(); got != 1 {
		t.Fatalf("inFlight=%d, want 1", got)
	}
}

// TestAdaptiveLimiterShrinksUnderHighLatency: after a baseline is established,
// sustained high latency must pull the limit well below max.
func TestAdaptiveLimiterShrinksUnderHighLatency(t *testing.T) {
	a := NewAdaptiveLimiter(2, 100)
	// Establish a low-latency baseline.
	for i := 0; i < 50; i++ {
		a.Release(2*time.Millisecond, false)
	}
	// Now sustained high latency (20x baseline).
	for i := 0; i < 200; i++ {
		a.Release(40*time.Millisecond, false)
	}
	if got := a.Limit(); got >= 100 {
		t.Fatalf("limit should shrink under high latency, got %d (max 100)", got)
	}
	if got := a.Limit(); got < 2 {
		t.Fatalf("limit must not drop below min, got %d", got)
	}
}

// TestAdaptiveLimiterBacksOffOnDrops: repeated failures shrink the limit toward min.
func TestAdaptiveLimiterBacksOffOnDrops(t *testing.T) {
	a := NewAdaptiveLimiter(3, 200)
	for i := 0; i < 200; i++ {
		a.Release(time.Millisecond, true) // dropped
	}
	if got := a.Limit(); got != 3 {
		t.Fatalf("sustained drops should drive limit to min (3), got %d", got)
	}
}

// TestAdaptiveLimiterRecoversUnderLowLatency: after shrinking, steady low
// latency must let the limit climb back up.
func TestAdaptiveLimiterRecoversUnderLowLatency(t *testing.T) {
	a := NewAdaptiveLimiter(2, 100)
	for i := 0; i < 300; i++ {
		a.Release(time.Millisecond, true) // crash it down to min
	}
	low := a.Limit()
	if low > 5 {
		t.Fatalf("precondition: limit should be near min, got %d", low)
	}
	// Steady fast responses → recovery.
	for i := 0; i < 300; i++ {
		a.Release(time.Millisecond, false)
	}
	if got := a.Limit(); got <= low {
		t.Fatalf("limit should recover under low latency: was %d, now %d", low, got)
	}
}

func TestAdaptiveLimiterClamps(t *testing.T) {
	a := NewAdaptiveLimiter(5, 50)
	// Hammer with low latency: must never exceed max.
	for i := 0; i < 500; i++ {
		a.Release(time.Microsecond, false)
	}
	if got := a.Limit(); got > 50 {
		t.Fatalf("limit exceeded max: %d", got)
	}
	// Hammer with drops: must never drop below min.
	for i := 0; i < 500; i++ {
		a.Release(time.Second, true)
	}
	if got := a.Limit(); got < 5 {
		t.Fatalf("limit dropped below min: %d", got)
	}
}

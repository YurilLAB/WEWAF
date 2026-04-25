package bruteforce

import (
	"sync"
	"testing"
	"time"
)

func TestDetectorCountsAttempts(t *testing.T) {
	d := NewDetector(time.Minute)
	defer d.Stop()
	for i := 0; i < 3; i++ {
		d.Record("1.1.1.1")
	}
	if got := d.Count("1.1.1.1"); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
	if d.IsBruteForce("1.1.1.1", 5) {
		t.Fatalf("3 attempts below threshold should not be brute force")
	}
	for i := 0; i < 3; i++ {
		d.Record("1.1.1.1")
	}
	if !d.IsBruteForce("1.1.1.1", 5) {
		t.Fatalf("6 attempts should cross threshold")
	}
}

func TestDetectorWindowExpiry(t *testing.T) {
	d := NewDetector(30 * time.Millisecond)
	defer d.Stop()
	d.Record("x")
	d.Record("x")
	time.Sleep(60 * time.Millisecond)
	d.Record("x")
	if got := d.Count("x"); got != 1 {
		t.Fatalf("expected 1 attempt after window expiry, got %d", got)
	}
}

func TestDetectorReset(t *testing.T) {
	d := NewDetector(time.Minute)
	defer d.Stop()
	d.Record("a")
	d.Record("a")
	d.Reset("a")
	if got := d.Count("a"); got != 0 {
		t.Fatalf("expected Reset to clear history, got %d", got)
	}
}

func TestDetectorRaceSafe(t *testing.T) {
	d := NewDetector(time.Second)
	defer d.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				d.Record("shared")
				_ = d.IsBruteForce("shared", 1000)
			}
		}(i)
	}
	wg.Wait()
	// Hit shouldn't have panicked; count must be 1600.
	if got := d.Count("shared"); got != 1600 {
		t.Fatalf("expected 1600 recorded attempts, got %d", got)
	}
}

func TestKeyFormat(t *testing.T) {
	if got := Key("1.1.1.1", ""); got != "1.1.1.1" {
		t.Fatalf("Key with no user should be IP, got %q", got)
	}
	if got := Key("1.1.1.1", "alice"); got != "1.1.1.1:alice" {
		t.Fatalf("Key with user should combine, got %q", got)
	}
}

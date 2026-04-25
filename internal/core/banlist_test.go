package core

import (
	"testing"
	"time"
)

func TestBanListBasicEvict(t *testing.T) {
	bl := NewBanList()
	bl.Ban("1.1.1.1", "scan", 20*time.Millisecond)
	if !bl.IsBanned("1.1.1.1") {
		t.Fatalf("expected IP to be banned immediately")
	}
	time.Sleep(30 * time.Millisecond)
	if bl.IsBanned("1.1.1.1") {
		t.Fatalf("expected ban to have expired")
	}
}

func TestBanListCleanupRemovesExpired(t *testing.T) {
	bl := NewBanList()
	bl.Ban("a", "", 10*time.Millisecond)
	bl.Ban("b", "", time.Hour)
	time.Sleep(20 * time.Millisecond)
	bl.Cleanup()
	if bl.Count() != 1 {
		t.Fatalf("expected Cleanup to leave 1 active ban, got %d", bl.Count())
	}
}

func TestBanListExponentialBackoff(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 2, time.Minute, time.Hour)
	bl.Ban("repeat", "x", 100*time.Millisecond)
	first := bl.entries["repeat"].ExpiresAt
	// Second ban within the backoff window doubles the duration.
	bl.Ban("repeat", "x", 100*time.Millisecond)
	second := bl.entries["repeat"].ExpiresAt
	if !second.After(first.Add(80 * time.Millisecond)) {
		t.Fatalf("expected second ban to extend ~2x beyond first; first=%v second=%v", first, second)
	}
	// Third ban should be ~4x the base.
	bl.Ban("repeat", "x", 100*time.Millisecond)
	third := bl.entries["repeat"].ExpiresAt
	if !third.After(second.Add(180 * time.Millisecond)) {
		t.Fatalf("expected third ban to extend ~4x beyond first; second=%v third=%v", second, third)
	}
}

func TestBanListBackoffCappedAtMax(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 10, time.Minute, 150*time.Millisecond)
	for i := 0; i < 5; i++ {
		bl.Ban("cap", "x", 100*time.Millisecond)
	}
	// After a few doublings we should be capped at ~150ms, not 100*10^4.
	entry := bl.entries["cap"]
	expires := entry.ExpiresAt
	maxExpected := entry.Timestamp.Add(150 * time.Millisecond)
	if expires.After(maxExpected.Add(50 * time.Millisecond)) {
		t.Fatalf("backoff exceeded max cap: expires=%v max=%v", expires, maxExpected)
	}
}

func TestBanListBackoffResetsAfterWindow(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 2, 30*time.Millisecond, time.Hour)
	bl.Ban("fresh", "x", 50*time.Millisecond)
	// Wait past both the ban and the backoff-history window.
	time.Sleep(80 * time.Millisecond)
	bl.Ban("fresh", "x", 50*time.Millisecond)
	entry := bl.entries["fresh"]
	if entry.Offenses != 1 {
		t.Fatalf("expected offense counter to reset after backoff window, got %d", entry.Offenses)
	}
}

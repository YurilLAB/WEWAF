package reputation

import (
	"context"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wewaf/internal/clientip"
)

func testEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reputation.sqlite")
	e, err := Open(Options{Path: path, Config: cfg})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	e.Start(context.Background())
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// TestEscalation_Doubling proves the duration doubles per offense tier at
// factor=2 (mirrors core/banlist_test.go's 1x/2x/4x proof) and clamps at max.
func TestEscalation_Doubling(t *testing.T) {
	base := 600 * time.Second
	max := 365 * 24 * time.Hour
	want := []time.Duration{
		base,      // offense 1
		base * 2,  // 2
		base * 4,  // 3
		base * 8,  // 4
		base * 16, // 5
		base * 32, // 6
	}
	for i, w := range want {
		got := escalatedDuration(i+1, base, max, 2.0, 0)
		if got != w {
			t.Errorf("offense %d: got %s want %s", i+1, got, w)
		}
	}
}

func TestEscalation_ClampAtMax(t *testing.T) {
	base := 600 * time.Second
	max := 7 * 24 * time.Hour
	// A high offense tier must saturate exactly at max, never overflow negative.
	for _, off := range []int{20, 32, 1000} {
		got := escalatedDuration(off, base, max, 2.0, 0)
		if got != max {
			t.Errorf("offense %d: got %s want clamp %s", off, got, max)
		}
		if got < 0 {
			t.Errorf("offense %d produced negative duration %s", off, got)
		}
	}
}

func TestEscalation_JitterBounds(t *testing.T) {
	base := 600 * time.Second
	max := 365 * 24 * time.Hour
	jitter := 60 * time.Second
	for i := 0; i < 500; i++ {
		got := escalatedDuration(1, base, max, 2.0, jitter)
		if got < base || got >= base+jitter {
			t.Fatalf("jittered duration %s out of [%s,%s)", got, base, base+jitter)
		}
	}
}

func TestDecay_HalfLife(t *testing.T) {
	half := 2 * time.Hour
	anchor := time.Now().UTC()
	// One half-life -> half the score.
	if got := decayedScore(100, anchor, anchor.Add(half), half); math.Abs(got-50) > 1e-6 {
		t.Errorf("after 1 half-life: got %.4f want ~50", got)
	}
	// Two half-lives -> quarter.
	if got := decayedScore(100, anchor, anchor.Add(2*half), half); math.Abs(got-25) > 1e-6 {
		t.Errorf("after 2 half-lives: got %.4f want ~25", got)
	}
	// No elapsed time -> unchanged.
	if got := decayedScore(100, anchor, anchor, half); got != 100 {
		t.Errorf("no elapsed: got %.4f want 100", got)
	}
}

func TestPrefixInvariant(t *testing.T) {
	valid := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.7",
		"2606:4700:4700::1111", "fe80::1", "2001:db8:abcd:0012::1",
	}
	for _, ip := range valid {
		k, ok := repKey(ip)
		if !ok {
			t.Errorf("repKey(%q) should be ok", ip)
			continue
		}
		if k != clientip.NormalizeIPKey(ip) {
			t.Errorf("repKey(%q)=%q != NormalizeIPKey=%q", ip, k, clientip.NormalizeIPKey(ip))
		}
	}
	for _, bad := range []string{"", "not-an-ip", "999.999.999.999", "10.0.0.1/24", "; rm -rf /"} {
		if _, ok := repKey(bad); ok {
			t.Errorf("repKey(%q) should be rejected", bad)
		}
	}
}

func TestAutoBanTrigger(t *testing.T) {
	e := testEngine(t, Config{
		Enabled:      true,
		Window:       time.Hour,
		Threshold:    3,
		BaseDuration: 600 * time.Second,
		Factor:       2.0,
		MaxDuration:  7 * 24 * time.Hour,
	})
	ip := "203.0.113.9"
	for i := 1; i <= 2; i++ {
		if d := e.RecordBlock(ip, "engine", "xss"); d.Ban {
			t.Fatalf("block %d should not yet auto-ban", i)
		}
	}
	d := e.RecordBlock(ip, "engine", "xss")
	if !d.Ban {
		t.Fatalf("3rd block at threshold 3 should auto-ban")
	}
	if d.Duration < 600*time.Second {
		t.Errorf("first auto-ban duration %s should be >= base 600s", d.Duration)
	}
}

func TestAutoBan_DisabledWhenNotEnabled(t *testing.T) {
	e := testEngine(t, Config{Enabled: false, Threshold: 1})
	if d := e.RecordBlock("203.0.113.9", "engine", "x"); d.Ban {
		t.Fatalf("reputation disabled: RecordBlock must never auto-ban")
	}
}

func TestOffensesAndEscalationDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.sqlite")
	cfg := Config{Enabled: true, BaseDuration: 600 * time.Second, Factor: 2.0, MaxDuration: 365 * 24 * time.Hour, OffenseWindow: 24 * time.Hour}

	e1, err := Open(Options{Path: path, Config: cfg})
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	e1.Start(context.Background())
	key := clientip.NormalizeIPKey("203.0.113.11")
	now := time.Now().UTC()
	// Two bans recorded: offense tier reaches 2.
	e1.RecordBan(key, "manual", 1, now, now.Add(time.Hour))
	e1.RecordBan(key, "manual", 2, now, now.Add(2*time.Hour))
	if n, _, ok := e1.Offenses(key); !ok || n != 2 {
		t.Fatalf("in-memory offenses got (%d,%v) want 2,true", n, ok)
	}
	if err := e1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	// Reopen: escalation memory must survive (restart-amnesia fix).
	e2, err := Open(Options{Path: path, Config: cfg})
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	n, _, ok := e2.Offenses(key)
	if !ok || n != 2 {
		t.Fatalf("after restart offenses got (%d,%v) want 2,true", n, ok)
	}
	// Next escalation uses the restored tier: base * factor^(3-1) = 4x base.
	if d := e2.EscalatedDuration("203.0.113.11", 600*time.Second); d != 600*time.Second*4 {
		t.Errorf("restored escalation got %s want %s", d, 600*time.Second*4)
	}
}

func TestPersistence_RestoreActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.sqlite")
	cfg := Config{Enabled: true}

	e1, err := Open(Options{Path: path, Config: cfg})
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	e1.Start(context.Background())
	now := time.Now().UTC()
	active := clientip.NormalizeIPKey("203.0.113.21")
	lapsed := clientip.NormalizeIPKey("203.0.113.22")
	e1.RecordBan(active, "x", 1, now, now.Add(time.Hour)) // still active
	e1.RecordBan(lapsed, "x", 1, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := e1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	e2, err := Open(Options{Path: path, Config: cfg})
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	restored := e2.RestoreActive()
	if len(restored) != 1 {
		t.Fatalf("RestoreActive returned %d want 1 (lapsed must be dropped): %+v", len(restored), restored)
	}
	if restored[0].Key != active {
		t.Errorf("restored key %q want %q", restored[0].Key, active)
	}
	if !restored[0].ExpiresAt.After(now) {
		t.Errorf("restored expiry %s not in the future", restored[0].ExpiresAt)
	}
}

// TestFailOpen_FullBuffer proves a saturated durable-write buffer never blocks
// the caller and never loses the in-memory update — reputation degrades to its
// in-memory cache rather than stalling the request path.
func TestFailOpen_FullBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.sqlite")
	// Tiny buffer, and deliberately DON'T Start the writer so the channel fills.
	e, err := Open(Options{Path: path, Config: Config{Enabled: true}, BufferSize: 2})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			e.RecordBlock("203.0.113.31", "engine", "x")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RecordBlock blocked on a full write buffer (should be non-blocking)")
	}
	if dropped, _ := e.store.stats(); dropped == 0 {
		t.Errorf("expected dropped durable writes with a full buffer, got 0")
	}
	// In-memory cache must still reflect the offender despite dropped writes.
	if rep := e.Consult("203.0.113.31"); !rep.Known {
		t.Errorf("offender not tracked in memory after dropped durable writes")
	}
}

func TestConsultDecaysScore(t *testing.T) {
	e := testEngine(t, Config{Enabled: true, HalfLife: time.Hour})
	ip := "203.0.113.41"
	e.RecordBlock(ip, "engine", "x")
	rep := e.Consult(ip)
	if !rep.Known || rep.Score <= 0 {
		t.Fatalf("expected positive score after a block, got %+v", rep)
	}
	if rep.Subsystems&SubEngine == 0 {
		t.Errorf("expected SubEngine bit set, got %b", rep.Subsystems)
	}
}

// TestConcurrent_RecordConsult is the -race guard: many goroutines hammering
// RecordBlock/Consult/EscalatedDuration on overlapping keys, with a config swap
// mid-flight, must not race or tear.
func TestConcurrent_RecordConsult(t *testing.T) {
	e := testEngine(t, Config{Enabled: true, Window: time.Hour, Threshold: 50, BaseDuration: time.Minute, Factor: 2, MaxDuration: time.Hour})
	keys := []string{"203.0.113.1", "203.0.113.2", "2001:db8::1", "198.51.100.5"}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := keys[g%len(keys)]
			for i := 0; i < 200; i++ {
				switch i % 4 {
				case 0:
					e.RecordBlock(ip, "engine", "x")
				case 1:
					_ = e.Consult(ip)
				case 2:
					_ = e.EscalatedDuration(ip, time.Minute)
				case 3:
					e.SetConfig(Config{Enabled: true, Window: time.Hour, Threshold: 50, BaseDuration: time.Minute, Factor: 2, MaxDuration: time.Hour})
				}
			}
		}(g)
	}
	wg.Wait()
}

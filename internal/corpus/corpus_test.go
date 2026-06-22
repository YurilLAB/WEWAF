package corpus

import (
	"context"
	"errors"
	"testing"
	"time"

	"wewaf/internal/history"
)

type fakeSource struct {
	blocks    []history.BlockEvent
	ips       []history.IPActivity
	blocksErr error
	ipsErr    error
}

func (f *fakeSource) QueryBlocks(_, _ time.Time, _ int) ([]history.BlockEvent, error) {
	return f.blocks, f.blocksErr
}
func (f *fakeSource) QueryIPs(_, _ time.Time, _ int) ([]history.IPActivity, error) {
	return f.ips, f.ipsErr
}

func blk(rule, cat, ip string) history.BlockEvent {
	return history.BlockEvent{RuleID: rule, RuleCategory: cat, IP: ip}
}

func TestMineRanksRulesByVolumeAndDistinctIPs(t *testing.T) {
	src := &fakeSource{blocks: []history.BlockEvent{
		// XSS-001: 5 blocks, all from ONE IP (doing its job).
		blk("XSS-001", "xss", "1.1.1.1"), blk("XSS-001", "xss", "1.1.1.1"),
		blk("XSS-001", "xss", "1.1.1.1"), blk("XSS-001", "xss", "1.1.1.1"), blk("XSS-001", "xss", "1.1.1.1"),
		// FP-001: 3 blocks across 3 DISTINCT IPs (false-positive candidate).
		blk("FP-001", "generic", "2.2.2.2"), blk("FP-001", "generic", "3.3.3.3"), blk("FP-001", "generic", "4.4.4.4"),
		// blocks with empty rule ID are ignored.
		blk("", "", "5.5.5.5"),
	}}

	rep, err := Mine(src, time.Now().UTC(), Options{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if rep.TotalBlocks != 9 {
		t.Errorf("TotalBlocks = %d want 9", rep.TotalBlocks)
	}
	if len(rep.TopRules) != 2 {
		t.Fatalf("TopRules len = %d want 2 (empty rule ID dropped): %+v", len(rep.TopRules), rep.TopRules)
	}
	// Ranked by volume: XSS-001 (5) before FP-001 (3).
	if rep.TopRules[0].RuleID != "XSS-001" || rep.TopRules[0].BlockCount != 5 || rep.TopRules[0].DistinctIPs != 1 {
		t.Errorf("top rule = %+v want XSS-001 count=5 distinct=1", rep.TopRules[0])
	}
	// The FP candidate is visible via its DistinctIPs spread.
	if rep.TopRules[1].RuleID != "FP-001" || rep.TopRules[1].DistinctIPs != 3 {
		t.Errorf("rule[1] = %+v want FP-001 distinct=3", rep.TopRules[1])
	}
}

func TestMineFlagsRepeatOffenders(t *testing.T) {
	src := &fakeSource{ips: []history.IPActivity{
		{IP: "9.9.9.9", RequestCount: 10, BlockCount: 8},  // ratio 0.8 -> offender
		{IP: "8.8.8.8", RequestCount: 100, BlockCount: 2}, // ratio 0.02 -> not
		{IP: "7.7.7.7", RequestCount: 3, BlockCount: 3},   // ratio 1.0 but below min requests -> not
		{IP: "6.6.6.6", RequestCount: 20, BlockCount: 19}, // ratio 0.95 -> offender, ranks first
	}}
	rep, err := Mine(src, time.Now().UTC(), Options{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(rep.RepeatOffenders) != 2 {
		t.Fatalf("offenders = %d want 2: %+v", len(rep.RepeatOffenders), rep.RepeatOffenders)
	}
	// Ranked by ratio desc: 6.6.6.6 (0.95) before 9.9.9.9 (0.8).
	if rep.RepeatOffenders[0].IP != "6.6.6.6" {
		t.Errorf("top offender = %s want 6.6.6.6", rep.RepeatOffenders[0].IP)
	}
	if rep.RepeatOffenders[1].IP != "9.9.9.9" {
		t.Errorf("offender[1] = %s want 9.9.9.9", rep.RepeatOffenders[1].IP)
	}
}

func TestMineWindowAndDefaults(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	rep, _ := Mine(&fakeSource{}, now, Options{Window: 6 * time.Hour})
	if !rep.From.Equal(now.Add(-6*time.Hour)) || !rep.To.Equal(now) {
		t.Errorf("window wrong: from=%v to=%v", rep.From, rep.To)
	}
	// Empty source -> empty, non-nil slices (JSON-friendly).
	if rep.TopRules == nil || rep.RepeatOffenders == nil {
		t.Error("ranked slices must be non-nil even when empty")
	}
}

func TestMineNilSourceAndErrors(t *testing.T) {
	if rep, err := Mine(nil, time.Now(), Options{}); err != nil || rep == nil {
		t.Errorf("nil source should yield (report, nil); got rep=%v err=%v", rep, err)
	}
	bErr := errors.New("blocks boom")
	if _, err := Mine(&fakeSource{blocksErr: bErr}, time.Now(), Options{}); !errors.Is(err, bErr) {
		t.Errorf("blocks query error not propagated: %v", err)
	}
	iErr := errors.New("ips boom")
	if _, err := Mine(&fakeSource{ipsErr: iErr}, time.Now(), Options{}); !errors.Is(err, iErr) {
		t.Errorf("ips query error not propagated: %v", err)
	}
}

func TestMineTopNCap(t *testing.T) {
	var blocks []history.BlockEvent
	for i := 0; i < 50; i++ {
		// Distinct rule IDs, descending volume so order is deterministic.
		id := string(rune('A'+i%26)) + string(rune('A'+i/26))
		for j := 0; j <= i; j++ {
			blocks = append(blocks, blk("R-"+id, "c", "1.2.3.4"))
		}
	}
	rep, _ := Mine(&fakeSource{blocks: blocks}, time.Now(), Options{TopN: 5})
	if len(rep.TopRules) != 5 {
		t.Errorf("TopN cap not applied: got %d want 5", len(rep.TopRules))
	}
}

// TestMineAgainstRealStore is a light end-to-end check against the real
// history.Store (which satisfies Source), proving the interface wiring holds.
func TestMineAgainstRealStore(t *testing.T) {
	st, err := history.Open(history.Options{Dir: t.TempDir(), FlushEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("history open: %v", err)
	}
	defer st.Close()
	st.Start(context.Background())
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		st.EnqueueBlock(history.BlockEvent{Timestamp: now, IP: "203.0.113.9", RuleID: "XSS-001", RuleCategory: "xss", Score: 100})
	}
	// Give the async writer a moment to flush, then mine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		rep, err := Mine(st, now.Add(time.Minute), Options{Window: time.Hour})
		if err != nil {
			t.Fatalf("Mine: %v", err)
		}
		if rep.TotalBlocks >= 4 && len(rep.TopRules) == 1 && rep.TopRules[0].RuleID == "XSS-001" {
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatalf("mining the real store did not surface the blocks in time: %+v", rep)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

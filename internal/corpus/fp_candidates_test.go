package corpus

import (
	"testing"
	"time"

	"wewaf/internal/history"
)

// TestMineFPCandidatesRankByDistinctIPs is the regression for CORPUS-S5-001: the
// FP-prone signal must rank by the BREADTH of the blocked client population
// (distinct IPs), not raw block volume. The old single volume-ranked list
// buried a rule firing once across many legit users below a busy-but-correct
// scanner rule, then the TopN cut dropped it.
func TestMineFPCandidatesRankByDistinctIPs(t *testing.T) {
	var blocks []history.BlockEvent
	// SCAN-001: 20 blocks from ONE IP — busiest rule, but doing its job.
	for i := 0; i < 20; i++ {
		blocks = append(blocks, blk("SCAN-001", "bot", "1.1.1.1"))
	}
	// FP-001: 6 blocks across 6 DISTINCT IPs — the false-positive candidate.
	for _, ip := range []string{"2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4", "2.2.2.5", "2.2.2.6"} {
		blocks = append(blocks, blk("FP-001", "generic", ip))
	}
	// NARROW-001: 4 blocks from a single IP — not a diverse-population FP, must
	// be EXCLUDED from the FP candidate list.
	for i := 0; i < 4; i++ {
		blocks = append(blocks, blk("NARROW-001", "sqli", "9.9.9.9"))
	}

	rep, err := Mine(&fakeSource{blocks: blocks}, time.Now().UTC(), Options{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}

	// Volume view still ranks the busiest rule first.
	if rep.TopRules[0].RuleID != "SCAN-001" {
		t.Errorf("TopRules[0] = %q want SCAN-001 (volume view)", rep.TopRules[0].RuleID)
	}

	// FP view ranks the diverse-population rule first.
	if len(rep.FPCandidates) == 0 {
		t.Fatalf("FPCandidates empty; expected FP-001 surfaced")
	}
	if rep.FPCandidates[0].RuleID != "FP-001" || rep.FPCandidates[0].DistinctIPs != 6 {
		t.Errorf("FPCandidates[0] = %+v want FP-001 distinct=6", rep.FPCandidates[0])
	}
	// Single-IP rules must not appear in the FP list.
	for _, r := range rep.FPCandidates {
		if r.DistinctIPs < 2 {
			t.Errorf("single-IP rule leaked into FP candidates: %+v", r)
		}
		if r.RuleID == "NARROW-001" {
			t.Errorf("NARROW-001 (1 IP) must be excluded from FP candidates")
		}
	}
}

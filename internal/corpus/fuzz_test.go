package corpus

import (
	"math"
	"strings"
	"testing"
	"time"

	"wewaf/internal/history"
)

// FuzzMine feeds arbitrary block rows and IP-activity counters through a mining
// pass to prove it never panics, never divides by zero in the block-ratio math,
// always produces finite ratios, and always honours the TopN bound — for any
// rule/IP strings and any (possibly zero/negative) request/block counts.
func FuzzMine(f *testing.F) {
	f.Add("XSS-001\x001.1.1.1\x00FP-001\x002.2.2.2", 5, int64(10), int64(8))
	f.Add("", 0, int64(0), int64(0))
	f.Add("\x00\x00\x00", -3, int64(-1), int64(100))
	f.Fuzz(func(t *testing.T, raw string, topN int, reqCount, blockCount int64) {
		parts := strings.Split(raw, "\x00")
		var blocks []history.BlockEvent
		for i := 0; i+1 < len(parts); i += 2 {
			blocks = append(blocks, history.BlockEvent{RuleID: parts[i], IP: parts[i+1], RuleCategory: "c"})
		}
		ips := []history.IPActivity{{IP: "v", RequestCount: reqCount, BlockCount: blockCount}}
		src := &fakeSource{blocks: blocks, ips: ips}

		rep, err := Mine(src, time.Now(), Options{TopN: topN})
		if err != nil {
			t.Fatalf("Mine returned error on in-memory source: %v", err)
		}
		if rep == nil {
			t.Fatal("nil report")
		}
		// Effective TopN: topN<=0 falls back to the default (20).
		cap := topN
		if cap <= 0 {
			cap = 20
		}
		if len(rep.TopRules) > cap {
			t.Fatalf("TopRules %d exceeds cap %d", len(rep.TopRules), cap)
		}
		if len(rep.RepeatOffenders) > cap {
			t.Fatalf("RepeatOffenders %d exceeds cap %d", len(rep.RepeatOffenders), cap)
		}
		for _, o := range rep.RepeatOffenders {
			if math.IsNaN(o.BlockRatio) || math.IsInf(o.BlockRatio, 0) {
				t.Fatalf("non-finite block ratio %v for %s (req=%d block=%d)", o.BlockRatio, o.IP, o.RequestCount, o.BlockCount)
			}
		}
	})
}

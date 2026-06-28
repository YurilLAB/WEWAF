package intel

import "sync"

// Consensus enforces the documented multi-source rule for feed-driven bans:
// "block only when >=2 sources agree OR the source is rated high confidence".
//
// The feed sink is invoked once PER SOURCE (see Manager fetch), so a single
// sink call only ever sees one source's entries — cross-source agreement can't
// be computed within one call. Consensus carries the per-value distinct-source
// set ACROSS sink invocations so medium-confidence enforcement waits for real
// corroboration instead of letting one noisy or poisoned medium feed auto-ban
// arbitrary public IPs (INTEL-CONSENSUS-001).
//
// Trust model:
//   - ConfHigh:   authoritative (DROP/KEV) — enforce on a single source.
//   - ConfMedium: enforce only once >=min DISTINCT sources report the value.
//   - ConfLow:    never auto-enforces (score/log only).
//
// Poisoning resistance: the set is keyed by source NAME, so one source
// repeating a value can't manufacture consensus.
type Consensus struct {
	mu   sync.Mutex
	min  int
	cap  int
	seen map[string]map[string]struct{} // value -> set of distinct source names
}

// NewConsensus returns a consensus tracker requiring minSources distinct
// sources before a medium-confidence value enforces. minSources<1 is treated
// as 1 (medium behaves like high).
func NewConsensus(minSources int) *Consensus {
	if minSources < 1 {
		minSources = 1
	}
	return &Consensus{
		min:  minSources,
		cap:  1 << 20, // bound memory against a feed flooding unique values
		seen: make(map[string]map[string]struct{}),
	}
}

// Enforce reports whether a feed entry should be auto-enforced (banned) now.
// High confidence enforces immediately; medium only once enough distinct
// sources corroborate; low never. It records (value, source) for medium
// entries so a later distinct source can reach the threshold.
//
// Bounded: once the tracked-value cap is hit, NEW medium values are not
// recorded and therefore not enforced (fail toward NOT banning — the FP-safe
// direction), so a feed dumping millions of unique values can't exhaust memory
// or force bans.
func (c *Consensus) Enforce(value, source string, conf Confidence) bool {
	switch conf {
	case ConfHigh:
		return true
	case ConfMedium:
		// fall through to source-counting below
	default:
		return false
	}
	if value == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	srcs := c.seen[value]
	if srcs == nil {
		if len(c.seen) >= c.cap {
			return false
		}
		srcs = make(map[string]struct{}, c.min)
		c.seen[value] = srcs
	}
	srcs[source] = struct{}{}
	return len(srcs) >= c.min
}

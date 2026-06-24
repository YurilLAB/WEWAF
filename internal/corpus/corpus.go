// Package corpus mines WEWAF's persisted block history to surface signals an
// operator can act on — the "get better by running" feedback loop, on-box and
// without any ML. It is strictly READ-ONLY: it queries the history store and
// computes rankings, never mutating state or touching the request path.
//
// Three signals come out of a mining pass:
//   - Top rules (TopRules): rules ranked by raw block VOLUME — the "busiest
//     rules" activity view.
//   - FP candidates (FPCandidates): rules ranked by the BREADTH of the client
//     population they block (DISTINCT IPs first). A rule firing across a huge,
//     diverse population is the false-positive candidate to review or move to
//     shadow mode (S2); a rule firing many times on a handful of IPs is doing
//     its job. Ranking these by volume (as the activity view does) buries the
//     diverse-population FP candidate below busy-but-correct scanner rules and
//     the TopN cut drops it — so this is a SEPARATE, diversity-first ranking.
//     (Cloudflare's blocked-corpus feedback loop, on-box.)
//   - Repeat offenders: IPs ranked by block ratio (blocks ÷ requests) over a
//     minimum request volume — promotion candidates for a longer ban.
package corpus

import (
	"sort"
	"time"

	"wewaf/internal/history"
)

// Source is the read-only history surface a mining pass needs. *history.Store
// satisfies it; tests inject a deterministic fake.
type Source interface {
	QueryBlocks(from, to time.Time, limit int) ([]history.BlockEvent, error)
	QueryIPs(from, to time.Time, limit int) ([]history.IPActivity, error)
}

// RuleStat is one rule's footprint over the mined window.
type RuleStat struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	BlockCount  int    `json:"block_count"`
	DistinctIPs int    `json:"distinct_ips"`
}

// OffenderStat is one IP's block behaviour over the mined window.
type OffenderStat struct {
	IP           string  `json:"ip"`
	BlockCount   int64   `json:"block_count"`
	RequestCount int64   `json:"request_count"`
	BlockRatio   float64 `json:"block_ratio"`
}

// Report is the result of one mining pass.
type Report struct {
	From            time.Time      `json:"from"`
	To              time.Time      `json:"to"`
	TotalBlocks     int            `json:"total_blocks"`
	TopRules        []RuleStat     `json:"top_rules"`
	FPCandidates    []RuleStat     `json:"fp_candidates"`
	RepeatOffenders []OffenderStat `json:"repeat_offenders"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

// Options tunes a mining pass. Zero values fall back to sane defaults.
type Options struct {
	Window              time.Duration // how far back to look (default 24h)
	QueryLimit          int           // max rows to pull per query (default 5000)
	TopN                int           // cap on each ranked list (default 20)
	MinOffenderRequests int64         // min requests before an IP can be an offender (default 5)
	MinOffenderRatio    float64       // min block ratio to flag an offender (default 0.5)
}

func (o Options) withDefaults() Options {
	if o.Window <= 0 {
		o.Window = 24 * time.Hour
	}
	if o.QueryLimit <= 0 {
		o.QueryLimit = 5000
	}
	if o.TopN <= 0 {
		o.TopN = 20
	}
	if o.MinOffenderRequests <= 0 {
		o.MinOffenderRequests = 5
	}
	if o.MinOffenderRatio <= 0 {
		o.MinOffenderRatio = 0.5
	}
	return o
}

// Mine runs one analytics pass over [now-Window, now]. `now` is injected so the
// caller controls the clock (and tests stay deterministic). A nil source or a
// query error yields a non-nil empty report and the error, so a caller can log
// and carry on.
func Mine(src Source, now time.Time, opts Options) (*Report, error) {
	opts = opts.withDefaults()
	rep := &Report{
		From:            now.Add(-opts.Window),
		To:              now,
		GeneratedAt:     now,
		TopRules:        []RuleStat{},
		FPCandidates:    []RuleStat{},
		RepeatOffenders: []OffenderStat{},
	}
	if src == nil {
		return rep, nil
	}

	blocks, err := src.QueryBlocks(rep.From, rep.To, opts.QueryLimit)
	if err != nil {
		return rep, err
	}
	rep.TotalBlocks = len(blocks)
	rep.TopRules = topRules(blocks, opts.TopN)
	rep.FPCandidates = fpCandidateRules(blocks, opts.TopN)

	ips, err := src.QueryIPs(rep.From, rep.To, opts.QueryLimit)
	if err != nil {
		return rep, err
	}
	rep.RepeatOffenders = repeatOffenders(ips, opts)
	return rep, nil
}

// aggregateRules collapses blocks into one RuleStat per rule ID (total blocks +
// distinct-IP count). Shared by both rule rankings so they agree on the counts.
func aggregateRules(blocks []history.BlockEvent) []RuleStat {
	type agg struct {
		category string
		count    int
		ips      map[string]struct{}
	}
	byRule := make(map[string]*agg)
	for _, b := range blocks {
		if b.RuleID == "" {
			continue
		}
		a := byRule[b.RuleID]
		if a == nil {
			a = &agg{ips: make(map[string]struct{})}
			byRule[b.RuleID] = a
		}
		a.count++
		if b.RuleCategory != "" {
			a.category = b.RuleCategory
		}
		if b.IP != "" {
			a.ips[b.IP] = struct{}{}
		}
	}
	out := make([]RuleStat, 0, len(byRule))
	for id, a := range byRule {
		out = append(out, RuleStat{RuleID: id, Category: a.category, BlockCount: a.count, DistinctIPs: len(a.ips)})
	}
	return out
}

// topRules ranks rules by raw block VOLUME — the busiest-rules activity view.
func topRules(blocks []history.BlockEvent, topN int) []RuleStat {
	out := aggregateRules(blocks)
	// Rank by block volume, then distinct IPs, then ID for a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlockCount != out[j].BlockCount {
			return out[i].BlockCount > out[j].BlockCount
		}
		if out[i].DistinctIPs != out[j].DistinctIPs {
			return out[i].DistinctIPs > out[j].DistinctIPs
		}
		return out[i].RuleID < out[j].RuleID
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// fpCandidateRules ranks rules by the BREADTH of the client population they
// block (DISTINCT IPs first), surfacing false-positive candidates: a rule
// firing across a huge, diverse population is likely catching legitimate
// traffic and is a promote-to-shadow (S2) candidate, whereas a rule firing many
// times on a handful of IPs is doing its job. This is the ranking the package
// contract describes; topRules (volume-first) buried these candidates below
// busy-but-correct scanner rules and the TopN cut dropped them. A rule that hit
// only a single IP cannot be a diverse-population FP, so it is excluded.
func fpCandidateRules(blocks []history.BlockEvent, topN int) []RuleStat {
	agg := aggregateRules(blocks)
	out := make([]RuleStat, 0, len(agg))
	for _, r := range agg {
		if r.DistinctIPs < 2 {
			continue // single-IP rule is not a diverse-population FP candidate
		}
		out = append(out, r)
	}
	// Rank by distinct-IP breadth, then volume, then ID for a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].DistinctIPs != out[j].DistinctIPs {
			return out[i].DistinctIPs > out[j].DistinctIPs
		}
		if out[i].BlockCount != out[j].BlockCount {
			return out[i].BlockCount > out[j].BlockCount
		}
		return out[i].RuleID < out[j].RuleID
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// repeatOffenders flags IPs whose block ratio (over a minimum request volume)
// exceeds the threshold, ranked by ratio then block volume.
func repeatOffenders(ips []history.IPActivity, opts Options) []OffenderStat {
	out := make([]OffenderStat, 0)
	for _, a := range ips {
		if a.RequestCount < opts.MinOffenderRequests || a.BlockCount <= 0 {
			continue
		}
		ratio := float64(a.BlockCount) / float64(a.RequestCount)
		if ratio < opts.MinOffenderRatio {
			continue
		}
		out = append(out, OffenderStat{IP: a.IP, BlockCount: a.BlockCount, RequestCount: a.RequestCount, BlockRatio: ratio})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlockRatio != out[j].BlockRatio {
			return out[i].BlockRatio > out[j].BlockRatio
		}
		if out[i].BlockCount != out[j].BlockCount {
			return out[i].BlockCount > out[j].BlockCount
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > opts.TopN {
		out = out[:opts.TopN]
	}
	return out
}

package web

import "sync"

// Mesh replay protection. The mesh-sync endpoint authenticates peers with a
// shared key (constant-time compare) but, before this, applied whatever bans a
// peer POSTed with NO freshness check — so a captured sync message could be
// REPLAYED later to re-inject stale bans (a leaked key + a recorded message =
// cluster-wide ban re-injection). The guard requires every sync to carry a unix
// timestamp within a freshness window AND a unique nonce, and remembers recent
// nonces (bounded) so the same message can't be processed twice.

const (
	meshReplayWindowSec = 300 // accept timestamps within +/- 5 min of now
	meshReplayMaxNonces = 1 << 17
	meshMaxBansPerSync  = 4096 // bound a single peer's blast radius per message
)

type meshReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]int64 // nonce -> unix time after which it can be forgotten
	window int64
	max    int
}

func newMeshReplayGuard(windowSec int64) *meshReplayGuard {
	if windowSec <= 0 {
		windowSec = meshReplayWindowSec
	}
	return &meshReplayGuard{
		seen:   make(map[string]int64),
		window: windowSec,
		max:    meshReplayMaxNonces,
	}
}

// check validates a sync message's freshness and uniqueness. ts and now are unix
// seconds. It returns (false, reason) for a missing/stale/future timestamp, a
// missing nonce, or a replayed nonce; on success it records the nonce so a
// later replay within the window is rejected. Fail-closed: if the bounded nonce
// cache is full of still-valid entries it refuses rather than forget a nonce.
func (g *meshReplayGuard) check(nonce string, ts, now int64) (bool, string) {
	if nonce == "" {
		return false, "missing nonce"
	}
	if ts == 0 {
		return false, "missing timestamp"
	}
	skew := now - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > g.window {
		return false, "stale or future timestamp"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.seen) >= g.max {
		for k, exp := range g.seen {
			if exp < now {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= g.max {
			return false, "replay cache full"
		}
	}
	if exp, ok := g.seen[nonce]; ok && exp >= now {
		return false, "replayed nonce"
	}
	// Remember it until a message bearing this ts would no longer pass freshness.
	g.seen[nonce] = ts + g.window
	return true, ""
}

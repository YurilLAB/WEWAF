package reputation

import (
	"context"
	"math"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"wewaf/internal/clientip"
)

// Subsystem bits record WHICH independent detectors have flagged an offender.
// popcount over the bitmask is the seed for cross-subsystem "recidive"
// consensus (S3): an IP flagged by several unrelated subsystems is far more
// likely to be genuinely hostile than one tripping a single noisy detector.
const (
	SubEngine     uint16 = 1 << iota // rule engine (XSS/SQLi/...)
	SubDDoS                          // volumetric / connection-rate
	SubBruteForce                    // login brute force
	SubJA3                           // TLS fingerprint anomaly
	SubIntel                         // threat-intel feed hit
	SubSession                       // session risk band
	SubRate                          // rate limiter
	SubOther
)

// subsystemBit maps a subsystem label to its bit. Unknown labels fold into
// SubOther so an unrecognised source still contributes to the offense record
// without silently vanishing.
func subsystemBit(name string) uint16 {
	switch name {
	case "engine":
		return SubEngine
	case "ddos":
		return SubDDoS
	case "bruteforce", "brute-force":
		return SubBruteForce
	case "ja3", "ja4":
		return SubJA3
	case "intel":
		return SubIntel
	case "session":
		return SubSession
	case "rate", "ratelimit", "rate-limit":
		return SubRate
	default:
		return SubOther
	}
}

// scorePerBlock is the reputation-score increment added per observed block,
// before decay. The score is a continuous, decaying signal (0..scoreCap) used
// on the hot path to raise the friction (PoW tier / session band) applied to a
// known-bad IP; it is deliberately distinct from the discrete escalation
// offense count, which drives ban DURATION.
const (
	scorePerBlock = 10.0
	scoreCap      = 100.0
)

// Config is the reputation engine's hot-swappable policy. All durations come
// from the operator config; the engine itself only enforces sane internal
// floors. Mirrors the BanList.allowlist atomic-pointer reload pattern.
type Config struct {
	Enabled       bool
	Window        time.Duration // sliding window for the block-count auto-ban trigger
	Threshold     int           // blocks within Window that auto-ban an IP (<=0 disables the trigger)
	BaseDuration  time.Duration // base auto-ban duration
	Factor        float64       // escalation base (duration = base * Factor^(offenses-1))
	MaxDuration   time.Duration // hard ceiling on any escalated duration
	OffenseWindow time.Duration // a repeat ban within this window escalates; outside it resets to tier 1
	HalfLife      time.Duration // score decay half-life
	Jitter        time.Duration // rndtime: random padding added to a ban so the unban instant is unpredictable
	PurgeAge      time.Duration // quiet offenders with no active ban are purged after this
}

func (c Config) sane() Config {
	if c.Factor < 1 {
		c.Factor = 2
	}
	if c.BaseDuration <= 0 {
		c.BaseDuration = 600 * time.Second
	}
	if c.MaxDuration <= 0 {
		c.MaxDuration = 7 * 24 * time.Hour
	}
	if c.OffenseWindow <= 0 {
		c.OffenseWindow = 24 * time.Hour
	}
	if c.HalfLife <= 0 {
		c.HalfLife = 24 * time.Hour
	}
	if c.Window <= 0 {
		c.Window = 10 * time.Minute
	}
	if c.PurgeAge <= 0 {
		c.PurgeAge = 30 * 24 * time.Hour
	}
	return c
}

// entry is the in-memory authoritative view of one offender. It is always
// up-to-date even when the durable write is still queued or was dropped.
type entry struct {
	key         string
	offenses    int       // escalation tier: count of bans recorded (drives duration)
	lastBanned  time.Time // most recent ban time (anchors the OffenseWindow reset)
	firstSeen   time.Time
	lastOffense time.Time // most recent block/flag
	blockCount  int       // blocks accumulated in the current window
	windowStart time.Time
	subsystems  uint16
	score       float64 // raw score at lastDecay; decay applied lazily on read
	lastDecay   time.Time
	banUntil    time.Time // current active ban expiry (zero = none)
}

// Reputation is the hot-path snapshot returned by Consult.
type Reputation struct {
	Known      bool
	Offenses   int
	Score      float64 // decayed to now
	BanUntil   time.Time
	Subsystems uint16
}

// Decision is what RecordBlock returns: whether this block tripped the
// auto-ban threshold and, if so, the escalated duration to ban for.
type Decision struct {
	BlockCount int
	Ban        bool
	Duration   time.Duration
	Reason     string
}

// Restored is one active ban to re-seed into the live BanList on startup.
type Restored struct {
	Key       string
	Reason    string
	ExpiresAt time.Time
	Offenses  int
}

// Options configures Open.
type Options struct {
	Path       string // path to reputation.sqlite
	Config     Config
	BufferSize int
	FlushEvery time.Duration
	FlushBatch int
}

// Engine is the durable per-IP reputation ledger. The zero value is unusable;
// construct via Open. A nil *Engine is a valid no-op (every method tolerates
// it) so callers can hold an optional engine without nil-guards everywhere.
type Engine struct {
	mu    sync.RWMutex
	cache map[string]*entry
	store *store
	cfg   atomic.Pointer[Config]

	autoBans   atomic.Uint64
	restoredN  atomic.Uint64
	maxEntries int
}

const defaultMaxEntries = 200_000

// Open opens (creating if needed) the reputation store at opts.Path and loads
// the active set into memory. A load failure is NOT fatal: the engine still
// returns, running on an empty in-memory cache, because reputation is a
// best-effort enhancement and must never stop the daemon from starting.
func Open(opts Options) (*Engine, error) {
	st, err := openStore(storeOptions{
		Path:       opts.Path,
		BufferSize: opts.BufferSize,
		FlushEvery: opts.FlushEvery,
		FlushBatch: opts.FlushBatch,
	})
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cache:      make(map[string]*entry),
		store:      st,
		maxEntries: defaultMaxEntries,
	}
	cfg := opts.Config.sane()
	e.cfg.Store(&cfg)

	if rows, err := st.loadAll(); err == nil {
		for _, p := range rows {
			e.cache[p.Key] = &entry{
				key:         p.Key,
				offenses:    p.Offenses,
				lastBanned:  p.LastBanned,
				firstSeen:   p.FirstSeen,
				lastOffense: p.LastOffense,
				subsystems:  p.Subsystems,
				score:       p.Score,
				lastDecay:   p.LastDecay,
				banUntil:    p.BanUntil,
			}
		}
	}
	return e, nil
}

// Start launches the write-behind writer goroutine. Idempotent.
func (e *Engine) Start(_ context.Context) {
	if e == nil {
		return
	}
	e.store.start()
}

// Close flushes and closes the store.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	return e.store.close()
}

// SetConfig atomically swaps the policy. Hot-reload safe.
func (e *Engine) SetConfig(c Config) {
	if e == nil {
		return
	}
	cfg := c.sane()
	e.cfg.Store(&cfg)
}

func (e *Engine) config() Config {
	if c := e.cfg.Load(); c != nil {
		return *c
	}
	return Config{}.sane()
}

// Enabled reports whether reputation policy is active.
func (e *Engine) Enabled() bool {
	return e != nil && e.config().Enabled
}

// repKey returns the canonical reputation key for an address — BYTE-IDENTICAL
// to clientip.NormalizeIPKey (v4 /32, v6 /64) so a ban issued from a reputation
// decision matches BanList.IsBanned, which keys the same way. Non-IP input
// returns ok=false: garbage must never become a key that could later reach the
// firewall sink. This invariant is asserted by FuzzRepKey.
func repKey(ip string) (string, bool) {
	if net.ParseIP(ip) == nil {
		return "", false
	}
	k := clientip.NormalizeIPKey(ip)
	if k == "" || net.ParseIP(k) == nil {
		return "", false
	}
	return k, true
}

// decayedScore returns e's score decayed to now without mutating it (pure, so
// it is safe under an RLock on the hot path).
func decayedScore(raw float64, lastDecay, now time.Time, halfLife time.Duration) float64 {
	if raw <= 0 || lastDecay.IsZero() || halfLife <= 0 {
		return raw
	}
	elapsed := now.Sub(lastDecay)
	if elapsed <= 0 {
		return raw
	}
	return raw * math.Pow(0.5, float64(elapsed)/float64(halfLife))
}

// RecordBlock is THE offense funnel: every block decision in the proxy calls it
// once with the triggering subsystem. It updates the in-memory entry (windowed
// block count, decaying score, subsystem bitmask, last-offense time), queues a
// durable upsert off the hot path, and reports whether the windowed block count
// crossed the auto-ban threshold this call. Non-blocking and fail-open: a full
// write buffer drops the durable write but never the in-memory update.
func (e *Engine) RecordBlock(ip, subsystem, reason string) Decision {
	if e == nil {
		return Decision{}
	}
	cfg := e.config()
	if !cfg.Enabled {
		return Decision{}
	}
	key, ok := repKey(ip)
	if !ok {
		return Decision{}
	}
	now := time.Now().UTC()

	e.mu.Lock()
	en := e.cache[key]
	if en == nil {
		en = &entry{key: key, firstSeen: now, windowStart: now, lastDecay: now}
		e.evictIfFullLocked(now)
		e.cache[key] = en
	}
	// Fold accrued decay into the stored score, then add this block's weight.
	en.score = decayedScore(en.score, en.lastDecay, now, cfg.HalfLife)
	en.lastDecay = now
	en.score += scorePerBlock
	if en.score > scoreCap {
		en.score = scoreCap
	}
	en.subsystems |= subsystemBit(subsystem)
	en.lastOffense = now
	if en.firstSeen.IsZero() {
		en.firstSeen = now
	}
	// Sliding-window block accumulation for the auto-ban trigger.
	if en.windowStart.IsZero() || now.Sub(en.windowStart) > cfg.Window {
		en.windowStart = now
		en.blockCount = 0
	}
	en.blockCount++

	dec := Decision{BlockCount: en.blockCount}
	// Trigger an auto-ban when the windowed block count reaches the threshold
	// and the IP is not already serving an active reputation ban (so a steady
	// stream of blocks doesn't re-fire every request — the gate's own IsBanned
	// short-circuit also covers this once the ban lands).
	if cfg.Threshold > 0 && en.blockCount >= cfg.Threshold && !now.Before(en.banUntil) {
		dec.Ban = true
		// Return the BASE duration, not an escalated one: the caller bans via
		// core.BanList, which is the single escalator (it reads this engine's
		// durable offense count through the OffenseLedger hook and applies the
		// backoff multiplier). Escalating here too would double-count.
		dec.Duration = cfg.BaseDuration
		dec.Reason = reason
		if dec.Reason == "" {
			dec.Reason = "reputation: block threshold exceeded"
		}
		// Reset the window so the next ban needs a fresh burst of blocks.
		en.windowStart = now
		en.blockCount = 0
		e.autoBans.Add(1)
	}
	p := snapshot(en)
	e.mu.Unlock()

	e.store.enqueue(p)
	return dec
}

// escalatedDuration computes base * Factor^(offenses-1), clamped to max, plus
// up to `jitter` of random padding. offenses is 1-based (1 => base). The math
// mirrors core.BanList's overflow-safe saturating loop so reputation-driven and
// BanList-driven escalation agree. Pure and deterministic except for jitter,
// which FuzzEscalatedDuration bounds.
func escalatedDuration(offenses int, base, max time.Duration, factor float64, jitter time.Duration) time.Duration {
	if base <= 0 {
		base = 600 * time.Second
	}
	// Reject NaN/Inf/<1 factors (NaN fails every comparison, so guard it
	// explicitly) — a degenerate factor must not poison the arithmetic below.
	if math.IsNaN(factor) || math.IsInf(factor, 0) || factor < 1 {
		factor = 2
	}
	if offenses < 1 {
		offenses = 1
	}
	if offenses > 32 {
		offenses = 32 // Factor>=1; 2^31 already saturates any realistic max
	}
	// Saturating ceiling in float space. With no explicit max we clamp at
	// 1<<62 ns (~146 years) — the SAME saturating fallback core.BanList uses —
	// which stays well below math.MaxInt64, so time.Duration(dur) can never
	// overflow into a negative duration (the float64(MaxInt64)->int64 trap).
	maxF := float64(time.Duration(1 << 62))
	if max > 0 && float64(max) < maxF {
		maxF = float64(max)
	}
	dur := float64(base)
	if dur > maxF {
		dur = maxF
	}
	for i := 1; i < offenses; i++ {
		dur *= factor
		if dur >= maxF {
			dur = maxF
			break
		}
	}
	out := time.Duration(dur)
	if out < 0 {
		out = 0
	}
	if jitter > 0 {
		out += time.Duration(mrand.Int64N(int64(jitter)))
		if max > 0 && out > max {
			out = max
		}
	}
	return out
}

// EscalatedDuration returns the duration a ban on ip should last given its
// durable offense history. Used by the ban-issuance path so manual, intel, and
// auto bans all escalate from the SAME persisted offense count.
func (e *Engine) EscalatedDuration(ip string, base time.Duration) time.Duration {
	cfg := e.config()
	if base <= 0 {
		base = cfg.BaseDuration
	}
	if e == nil {
		return escalatedDuration(1, base, cfg.MaxDuration, cfg.Factor, cfg.Jitter)
	}
	key, ok := repKey(ip)
	if !ok {
		return escalatedDuration(1, base, cfg.MaxDuration, cfg.Factor, cfg.Jitter)
	}
	now := time.Now().UTC()
	e.mu.RLock()
	n := 0
	if en := e.cache[key]; en != nil {
		n = en.offenses
		if !en.lastBanned.IsZero() && now.Sub(en.lastBanned) > cfg.OffenseWindow {
			n = 0
		}
	}
	e.mu.RUnlock()
	return escalatedDuration(n+1, base, cfg.MaxDuration, cfg.Factor, cfg.Jitter)
}

// Offenses implements the core.OffenseLedger read: the raw stored offense count
// and last-ban time for key. The CALLER (BanList) applies its own backoff-
// window reset, so this returns the durable value untouched. ok=false => no
// record (treated as zero offenses).
func (e *Engine) Offenses(key string) (int, time.Time, bool) {
	if e == nil {
		return 0, time.Time{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if en := e.cache[key]; en != nil {
		return en.offenses, en.lastBanned, true
	}
	return 0, time.Time{}, false
}

// RecordBan implements the core.OffenseLedger write: persist that key was
// banned at now, resulting in `offenses` total bans, expiring at `expires`.
// Non-blocking. This is what makes escalation durable across restarts.
func (e *Engine) RecordBan(key, reason string, offenses int, now, expires time.Time) {
	if e == nil || key == "" {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.mu.Lock()
	en := e.cache[key]
	if en == nil {
		en = &entry{key: key, firstSeen: now, windowStart: now, lastDecay: now}
		e.evictIfFullLocked(now)
		e.cache[key] = en
	}
	if offenses > en.offenses {
		en.offenses = offenses
	}
	en.lastBanned = now
	en.lastOffense = now
	en.banUntil = expires
	if en.firstSeen.IsZero() {
		en.firstSeen = now
	}
	p := snapshot(en)
	e.mu.Unlock()
	e.store.enqueue(p)
}

// Consult returns the hot-path reputation snapshot for ip (score decayed to
// now). RLock + arithmetic only — never does I/O, so it is safe to call on
// every request without serialising the proxy.
func (e *Engine) Consult(ip string) Reputation {
	if e == nil {
		return Reputation{}
	}
	key, ok := repKey(ip)
	if !ok {
		return Reputation{}
	}
	now := time.Now().UTC()
	cfg := e.config()
	e.mu.RLock()
	defer e.mu.RUnlock()
	en := e.cache[key]
	if en == nil {
		return Reputation{}
	}
	return Reputation{
		Known:      true,
		Offenses:   en.offenses,
		Score:      decayedScore(en.score, en.lastDecay, now, cfg.HalfLife),
		BanUntil:   en.banUntil,
		Subsystems: en.subsystems,
	}
}

// RestoreActive returns the still-active bans (banUntil in the future) so the
// caller can re-seed the live BanList after a restart. Lapsed bans are skipped.
// This is the restart-amnesia fix: an attacker mid-ban stays banned across a
// daemon restart.
func (e *Engine) RestoreActive() []Restored {
	if e == nil {
		return nil
	}
	now := time.Now().UTC()
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Restored
	for _, en := range e.cache {
		if en.banUntil.IsZero() || !en.banUntil.After(now) {
			continue
		}
		out = append(out, Restored{
			Key:       en.key,
			Reason:    "reputation: restored active ban",
			ExpiresAt: en.banUntil,
			Offenses:  en.offenses,
		})
	}
	e.restoredN.Store(uint64(len(out)))
	return out
}

// Purge drops quiet, unbanned offenders older than the configured PurgeAge from
// both memory and disk. Intended to run on a slow ticker / rotation hook.
func (e *Engine) Purge() {
	if e == nil {
		return
	}
	cfg := e.config()
	now := time.Now().UTC()
	cutoff := now.Add(-cfg.PurgeAge)
	e.mu.Lock()
	for k, en := range e.cache {
		if en.lastOffense.Before(cutoff) && !en.banUntil.After(now) {
			delete(e.cache, k)
		}
	}
	e.mu.Unlock()
	_, _ = e.store.purgeOlderThan(cutoff, now)
}

// evictIfFullLocked bounds the in-memory cache the same way core.BanList bounds
// its entries map: when at the cap, drop a small budget of the least-recently-
// offending entries that hold no active ban. Caller must hold e.mu.
func (e *Engine) evictIfFullLocked(now time.Time) {
	if len(e.cache) < e.maxEntries {
		return
	}
	budget := e.maxEntries / 1000
	if budget < 16 {
		budget = 16
	}
	// First pass: evict entries with a lapsed/absent ban (cheap, correct).
	for k, en := range e.cache {
		if !en.banUntil.After(now) {
			delete(e.cache, k)
			budget--
			if budget <= 0 {
				return
			}
		}
	}
	// Still full (all entries actively banned — pathological): drop anything.
	for k := range e.cache {
		delete(e.cache, k)
		budget--
		if budget <= 0 {
			return
		}
	}
}

// Stats returns a snapshot for the admin API / logs.
func (e *Engine) Stats() map[string]interface{} {
	if e == nil {
		return map[string]interface{}{"enabled": false}
	}
	e.mu.RLock()
	tracked := len(e.cache)
	e.mu.RUnlock()
	dropped, written := e.store.stats()
	return map[string]interface{}{
		"enabled":         e.config().Enabled,
		"tracked":         tracked,
		"auto_bans_total": e.autoBans.Load(),
		"restored":        e.restoredN.Load(),
		"dropped_writes":  dropped,
		"written":         written,
	}
}

// snapshot copies an entry into its durable form. Caller holds e.mu.
func snapshot(en *entry) persisted {
	return persisted{
		Key:         en.key,
		Offenses:    en.offenses,
		Score:       en.score,
		FirstSeen:   en.firstSeen,
		LastOffense: en.lastOffense,
		LastBanned:  en.lastBanned,
		LastDecay:   en.lastDecay,
		Subsystems:  en.subsystems,
		BanUntil:    en.banUntil,
	}
}

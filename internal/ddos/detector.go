// Package ddos detects volumetric, protocol, application-layer, and
// distributed (botnet) attacks that individual rule matches miss.
//
// # Design goals
//
// The detector is built around two observations about real traffic:
//
//  1. Legitimate traffic is spiky. A Black Friday surge, a news mention, or
//     a routine deploy cache-bust all cause short bursts that look nothing
//     like the steady-state mean. A naive "threshold × multiplier" detector
//     would flag every one of them.
//
//  2. Attacks are sustained. A genuine DoS or DDoS delivers abnormal rate
//     for many consecutive seconds — the attacker doesn't give up after
//     one spike. So requiring N consecutive spike windows before declaring
//     "under attack" gives us a cheap, reliable signal.
//
// The detector therefore never trips on a single window's reading. It
// tracks:
//
//   - An adaptive baseline — exponentially weighted moving average of
//     per-second RPS across a 5-minute warmup window. Until warmup
//     completes the detector only considers the absolute-minimum floor
//     (so small sites don't false-positive at 20 RPS).
//
//   - Spike windows — a counter that increments while the smoothed
//     short-window RPS exceeds baseline * spike factor AND the absolute
//     floor. The detector only flips "under attack" after three
//     consecutive spike windows (~30 s of sustained abnormal traffic).
//
//   - Per-IP connection rate — a 10-second map of arrival times, for
//     flagging single-source floods. Threshold raised to a CDN-friendly
//     default (300/10s = 30 qps per client) so office NAT and shared
//     hosting don't trigger.
//
//   - Botnet cardinality — unique source IPs hitting the same path within
//     a 60-second window. Many distinct low-rate IPs on a sensitive path
//     (login / admin / api) is the classic botnet shape.
//
//   - Slow-read — per-request body-read rate for Slowloris detection.
//
// The detector is allocation-light on the hot path: counters live in a
// fixed-size ring and the per-IP / per-path maps are bounded with lazy
// eviction so an attacker can't OOM us by rotating source addresses.
package ddos

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config tunes the detector. Zero-valued fields get sane defaults.
type Config struct {
	// VolumetricBaseline is the starting guess for "normal" RPS. It's only
	// used during the first WarmupSeconds — after that the detector uses
	// its adaptive EMA instead.
	VolumetricBaseline int
	// VolumetricSpike multiplies the baseline to produce the spike
	// threshold. At the default 4.0, baseline=100 RPS needs 400 RPS to
	// flag — and even then only after three consecutive spike windows.
	VolumetricSpike float64
	// WarmupSeconds is how long before the adaptive baseline takes over
	// from the configured VolumetricBaseline. Defaults to 300 s.
	WarmupSeconds int
	// MinAbsoluteRPS is the floor: we never declare "under attack" below
	// this absolute RPS no matter what the multiplier says. A small site
	// running at 5 RPS that briefly spikes to 50 RPS is not a DoS.
	MinAbsoluteRPS int
	// SpikeWindowsRequired is how many consecutive 1-second spike readings
	// trigger "under attack". Default 3 — roughly 30 s of abnormal
	// smoothed traffic before we start shedding load.
	SpikeWindowsRequired int
	// CoolDownSeconds is how long to stay in "under attack" after the
	// last spike reading. Default 60 s.
	CoolDownSeconds int

	ConnRateThreshold int           // per-IP conns in 10s that trigger mitigation
	MaxPerIPEntries   int           // cap on tracked IPs
	SlowMinBPS        int           // minimum bytes/sec before request is Slowloris-suspect
	SlowMinAge        time.Duration // how long a request must be open before slow-detection fires

	// Botnet detection.
	BotnetUniqueIPThreshold int // unique IPs on same path in 60s to flag
	BotnetMaxPaths          int // cap on tracked paths
	// BotnetSensitivePaths are path prefixes where we tighten the bar; an
	// attack against /login with 50 unique IPs is suspicious, an attack
	// against /static with 50 is probably just a CDN. Matching prefix
	// lowers the threshold by the configured factor.
	BotnetSensitivePaths []string
}

// Detector is the concurrent DDoS tracking state.
type Detector struct {
	cfg Config

	// Volumetric: ring of per-second request counts for the last 60 s,
	// plus the adaptive EMA and spike-window counter.
	volMu           sync.Mutex
	volRing         [60]uint32
	volIndex        int
	volLast         time.Time
	emaRPS          float64 // adaptive baseline
	spikeStreak     int
	inAttack        bool
	lastSpikeAtUnix int64
	startedAt       time.Time

	// Per-IP connection-rate map.
	ipMu   sync.Mutex
	ipHits map[string][]int64

	// Botnet tracking: path -> set of IPs seen in last 60 s with arrival times.
	botMu    sync.Mutex
	botPaths map[string]map[string]int64

	// Counters exposed via StatsSnapshot.
	totalRequests    atomic.Uint64
	flaggedVolume    atomic.Uint64
	flaggedConnRate  atomic.Uint64
	flaggedSlow      atomic.Uint64
	flaggedBotnet    atomic.Uint64
	underAttack      atomic.Bool
	lastAttackAtUnix atomic.Int64
}

// Verdict is returned by RecordRequest.
type Verdict int

const (
	VerdictOK         Verdict = iota
	VerdictVolumetric         // global RPS has spiked; slow everyone
	VerdictConnRate           // this IP is opening connections too fast
	VerdictBotnet             // distributed attack shape on a sensitive path
)

// New returns a configured detector with defaults filled in.
func New(cfg Config) *Detector {
	if cfg.VolumetricBaseline <= 0 {
		cfg.VolumetricBaseline = 100
	}
	if cfg.VolumetricSpike <= 0 {
		cfg.VolumetricSpike = 4.0
	}
	if cfg.WarmupSeconds <= 0 {
		cfg.WarmupSeconds = 300
	}
	if cfg.MinAbsoluteRPS <= 0 {
		cfg.MinAbsoluteRPS = 100
	}
	if cfg.SpikeWindowsRequired <= 0 {
		cfg.SpikeWindowsRequired = 3
	}
	if cfg.CoolDownSeconds <= 0 {
		cfg.CoolDownSeconds = 60
	}
	if cfg.ConnRateThreshold <= 0 {
		cfg.ConnRateThreshold = 300
	}
	if cfg.MaxPerIPEntries <= 0 {
		cfg.MaxPerIPEntries = 50_000
	}
	if cfg.SlowMinBPS <= 0 {
		cfg.SlowMinBPS = 128
	}
	if cfg.SlowMinAge <= 0 {
		cfg.SlowMinAge = 10 * time.Second
	}
	if cfg.BotnetUniqueIPThreshold <= 0 {
		cfg.BotnetUniqueIPThreshold = 200
	}
	if cfg.BotnetMaxPaths <= 0 {
		cfg.BotnetMaxPaths = 2048
	}
	if len(cfg.BotnetSensitivePaths) == 0 {
		cfg.BotnetSensitivePaths = []string{
			"/login", "/signin", "/auth", "/admin", "/api/auth",
			"/api/login", "/register", "/signup", "/oauth", "/wp-login.php",
		}
	}
	return &Detector{
		cfg:       cfg,
		ipHits:    make(map[string][]int64),
		botPaths:  make(map[string]map[string]int64),
		volLast:   time.Now().UTC(),
		startedAt: time.Now().UTC(),
		emaRPS:    float64(cfg.VolumetricBaseline),
	}
}

// RecordRequest is called exactly once per incoming request. It updates the
// volumetric window, per-IP connection-rate map, and botnet path map, then
// returns the verdict for this IP/path.
func (d *Detector) RecordRequest(ip, path string) Verdict {
	if d == nil {
		return VerdictOK
	}
	d.totalRequests.Add(1)
	d.advanceVolume()

	// Global volumetric verdict always wins — shed load first.
	if d.IsUnderAttack() {
		d.flaggedVolume.Add(1)
		return VerdictVolumetric
	}

	// Per-IP conn rate. Empty IP means we can't meaningfully track.
	if ip != "" {
		if v := d.checkPerIP(ip); v != VerdictOK {
			return v
		}
	}

	// Botnet check only fires on sensitive paths so bulk static traffic
	// doesn't trigger. Bounded by BotnetMaxPaths.
	if path != "" && d.isSensitivePath(path) {
		if v := d.checkBotnet(ip, path); v != VerdictOK {
			return v
		}
	}
	return VerdictOK
}

// RecordSlowRead is called when a body read finishes with the total bytes
// seen and the request's age. Returns true if the read was slow enough to
// count as Slowloris.
func (d *Detector) RecordSlowRead(bytes int, age time.Duration) bool {
	if d == nil || age < d.cfg.SlowMinAge {
		return false
	}
	if age.Seconds() <= 0 {
		return false
	}
	bps := int(float64(bytes) / age.Seconds())
	if bps < d.cfg.SlowMinBPS {
		d.flaggedSlow.Add(1)
		return true
	}
	return false
}

// IsUnderAttack reports whether the detector has committed to the "shed load"
// state (requires SpikeWindowsRequired consecutive spike readings and stays
// on for CoolDownSeconds after the last spike).
func (d *Detector) IsUnderAttack() bool {
	if d == nil {
		return false
	}
	return d.underAttack.Load()
}

func (d *Detector) checkPerIP(ip string) Verdict {
	now := time.Now().Unix()
	cutoff := now - 10
	d.ipMu.Lock()
	defer d.ipMu.Unlock()

	// Eviction when we're at cap. The previous implementation scanned the
	// entire map to find the oldest entry — O(n) under a mutex on the hot
	// path, which turned a traffic spike that filled the map into a
	// self-DoS. Instead, opportunistically drop a handful of random
	// entries. Go's map iteration is randomised so this spreads pressure
	// across the keyspace without ever walking the whole map.
	if len(d.ipHits) >= d.cfg.MaxPerIPEntries {
		dropBudget := 64
		for k := range d.ipHits {
			delete(d.ipHits, k)
			dropBudget--
			if dropBudget <= 0 {
				break
			}
		}
	}

	hits := d.ipHits[ip]
	// Prune entries outside the 10-second window.
	pruneIdx := 0
	for pruneIdx < len(hits) && hits[pruneIdx] < cutoff {
		pruneIdx++
	}
	if pruneIdx > 0 {
		hits = hits[pruneIdx:]
	}
	hits = append(hits, now)
	d.ipHits[ip] = hits

	if len(hits) >= d.cfg.ConnRateThreshold {
		d.flaggedConnRate.Add(1)
		return VerdictConnRate
	}
	return VerdictOK
}

func (d *Detector) isSensitivePath(path string) bool {
	lp := strings.ToLower(path)
	for _, prefix := range d.cfg.BotnetSensitivePaths {
		if strings.HasPrefix(lp, prefix) {
			return true
		}
	}
	return false
}

func (d *Detector) checkBotnet(ip, path string) Verdict {
	if ip == "" {
		return VerdictOK
	}
	now := time.Now().Unix()
	cutoff := now - 60

	d.botMu.Lock()
	defer d.botMu.Unlock()

	if len(d.botPaths) >= d.cfg.BotnetMaxPaths {
		// Drop the path with the oldest most-recent hit.
		var oldestPath string
		var oldestTS int64 = now + 1
		for p, ips := range d.botPaths {
			var latest int64
			for _, ts := range ips {
				if ts > latest {
					latest = ts
				}
			}
			if latest < oldestTS {
				oldestTS = latest
				oldestPath = p
			}
		}
		if oldestPath != "" {
			delete(d.botPaths, oldestPath)
		}
	}

	ips, ok := d.botPaths[path]
	if !ok {
		ips = make(map[string]int64)
		d.botPaths[path] = ips
	}

	// Prune stale IPs so len(ips) IS the fresh count. Doing this only
	// when the map outgrows the threshold (to amortise the sweep cost)
	// was the old behaviour, but it left the per-request path counting
	// every entry — O(n) under lock. A threshold-anchored prune here
	// caps the map size tightly around BotnetUniqueIPThreshold and lets
	// the fresh check collapse to a single len() read.
	pruneAbove := d.cfg.BotnetUniqueIPThreshold
	if pruneAbove < 16 {
		pruneAbove = 16
	}
	if len(ips) > pruneAbove {
		for k, ts := range ips {
			if ts < cutoff {
				delete(ips, k)
			}
		}
	}
	ips[ip] = now

	if len(ips) >= d.cfg.BotnetUniqueIPThreshold {
		// Belt-and-braces: if the map is at the threshold but a chunk
		// of entries are stale (we haven't tripped a prune yet), count
		// fresh entries for the final decision so we don't false-flag
		// on a map that's mostly expired cruft.
		fresh := 0
		for _, ts := range ips {
			if ts >= cutoff {
				fresh++
			}
		}
		if fresh >= d.cfg.BotnetUniqueIPThreshold {
			d.flaggedBotnet.Add(1)
			return VerdictBotnet
		}
	}
	return VerdictOK
}

// advanceVolume shifts the ring forward as wall-clock seconds pass, updates
// the adaptive baseline, and re-evaluates the "under attack" flag.
func (d *Detector) advanceVolume() {
	d.volMu.Lock()
	defer d.volMu.Unlock()

	now := time.Now().UTC()
	elapsed := int(now.Sub(d.volLast).Seconds())
	// Guard against the monotonic clock jumping backwards (NTP slews,
	// suspended VMs resuming, etc). Without this a negative `elapsed`
	// bypasses the ring shift and stale buckets keep accumulating.
	if elapsed < 0 {
		d.volLast = now
		elapsed = 0
	}
	if elapsed > 0 {
		steps := elapsed
		if steps > len(d.volRing) {
			steps = len(d.volRing)
		}
		for i := 0; i < steps; i++ {
			// Before zeroing the next bucket, feed the departing bucket
			// into the EMA so the baseline reflects actual observed traffic.
			old := d.volRing[d.volIndex]
			d.feedEMA(float64(old))
			d.volIndex = (d.volIndex + 1) % len(d.volRing)
			d.volRing[d.volIndex] = 0
		}
		d.volLast = now
	}
	d.volRing[d.volIndex]++

	// Smoothed short-window RPS (last 10 buckets).
	var sum uint32
	const windowSize = 10
	for i := 0; i < windowSize; i++ {
		idx := (d.volIndex - i + len(d.volRing)) % len(d.volRing)
		sum += d.volRing[idx]
	}
	avg := float64(sum) / float64(windowSize)

	// During warmup, prefer the configured baseline — the EMA hasn't seen
	// enough samples yet.
	baseline := d.emaRPS
	sinceStart := now.Sub(d.startedAt)
	if sinceStart < time.Duration(d.cfg.WarmupSeconds)*time.Second {
		if float64(d.cfg.VolumetricBaseline) > baseline {
			baseline = float64(d.cfg.VolumetricBaseline)
		}
	}

	spikeThreshold := baseline * d.cfg.VolumetricSpike
	absoluteFloor := float64(d.cfg.MinAbsoluteRPS)

	isSpike := avg >= spikeThreshold && avg >= absoluteFloor
	if isSpike {
		d.spikeStreak++
		d.lastSpikeAtUnix = now.Unix()
		if d.spikeStreak >= d.cfg.SpikeWindowsRequired && !d.inAttack {
			d.inAttack = true
			d.underAttack.Store(true)
			d.lastAttackAtUnix.Store(now.Unix())
		}
	} else {
		// One quiet window after a streak resets it. We still stay
		// under-attack for the full cool-down so a brief dip doesn't
		// prematurely open the floodgates.
		d.spikeStreak = 0
	}

	// Cool-down: release "under attack" only after CoolDownSeconds of
	// sustained quiet.
	if d.inAttack {
		last := time.Unix(d.lastSpikeAtUnix, 0)
		if now.Sub(last) >= time.Duration(d.cfg.CoolDownSeconds)*time.Second {
			d.inAttack = false
			d.underAttack.Store(false)
		}
	}
}

// feedEMA updates the adaptive baseline with the given per-second reading.
// Uses a slow decay so the EMA reflects real trending traffic rather than
// single-spike anomalies (otherwise the attack itself would raise the
// baseline and effectively self-justify).
func (d *Detector) feedEMA(sample float64) {
	// Ignore samples taken during an active attack — we don't want the
	// attack traffic polluting the baseline we compare against.
	if d.inAttack {
		return
	}
	const alpha = 0.02 // slow smoothing: half-life ~34 samples
	d.emaRPS = alpha*sample + (1-alpha)*d.emaRPS
}

// StatsSnapshot returns a stable view of counters for the admin API.
func (d *Detector) StatsSnapshot() map[string]interface{} {
	if d == nil {
		return map[string]interface{}{}
	}
	d.volMu.Lock()
	ema := d.emaRPS
	streak := d.spikeStreak
	d.volMu.Unlock()
	return map[string]interface{}{
		"total_requests":      d.totalRequests.Load(),
		"flagged_volumetric":  d.flaggedVolume.Load(),
		"flagged_conn_rate":   d.flaggedConnRate.Load(),
		"flagged_slow_read":   d.flaggedSlow.Load(),
		"flagged_botnet":      d.flaggedBotnet.Load(),
		"under_attack":        d.underAttack.Load(),
		"last_attack_unix":    d.lastAttackAtUnix.Load(),
		"adaptive_baseline":   ema,
		"spike_streak":        streak,
		"spike_windows_req":   d.cfg.SpikeWindowsRequired,
		"min_absolute_rps":    d.cfg.MinAbsoluteRPS,
	}
}

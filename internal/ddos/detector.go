// Package ddos detects volumetric, protocol, and application-layer flooding
// attacks that individual rule matches miss.
//
// The detector keeps three concurrent views of request flow:
//
//  1. Volumetric — a rolling 60-second window of total requests. If the
//     current window's rate exceeds a configured baseline by more than
//     the spike factor, the WAF enters "under attack" mode and narrower
//     rate limits kick in.
//  2. Connection rate — per-IP counter of new TCP-level requests within the
//     last 10 seconds. Used to catch connection-establishment floods that
//     never make it to the request-body phase.
//  3. Slow-read — tracks the byte-read rate of each in-flight request.
//     If a request reads slower than minBytesPerSecond and has been open
//     for more than slowMinAge, it is classified as Slowloris-style.
//
// The detector is allocation-light: counters live in a small ring and the
// per-IP map is bounded and evicted lazily so an attacker can't OOM it by
// rotating source addresses.
package ddos

import (
	"sync"
	"sync/atomic"
	"time"
)

// Config tunes the detector. Zero-valued fields get sane defaults.
type Config struct {
	VolumetricBaseline int           // requests/sec considered "normal"
	VolumetricSpike    float64       // multiplier over baseline that trips "under attack"
	ConnRateThreshold  int           // per-IP connections in last 10s that trigger mitigation
	MaxPerIPEntries    int           // cap on tracked IPs
	SlowMinBPS         int           // minimum bytes/sec before request is Slowloris-suspect
	SlowMinAge         time.Duration // how long a request must be open before slow-detection fires
}

// Detector is the concurrent DDoS tracking state.
type Detector struct {
	cfg Config

	// Volumetric: ring of per-second request counts for the last 60s.
	volMu    sync.Mutex
	volRing  [60]uint32
	volIndex int
	volLast  time.Time

	// Per-IP connection-rate map. Values are unix-seconds of the last 10
	// request arrivals per IP (oldest first). Bounded by MaxPerIPEntries.
	ipMu   sync.Mutex
	ipHits map[string][]int64

	// Counters exposed via StatsSnapshot.
	totalRequests    atomic.Uint64
	flaggedVolume    atomic.Uint64
	flaggedConnRate  atomic.Uint64
	flaggedSlow      atomic.Uint64
	underAttack      atomic.Bool
	lastAttackAtUnix atomic.Int64
}

// New returns a configured detector. Missing values get sensible defaults.
func New(cfg Config) *Detector {
	if cfg.VolumetricBaseline <= 0 {
		cfg.VolumetricBaseline = 500
	}
	if cfg.VolumetricSpike <= 0 {
		cfg.VolumetricSpike = 4.0
	}
	if cfg.ConnRateThreshold <= 0 {
		cfg.ConnRateThreshold = 100
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
	return &Detector{
		cfg:     cfg,
		ipHits:  make(map[string][]int64),
		volLast: time.Now().UTC(),
	}
}

// RecordRequest is called exactly once per incoming request, before any body
// is read. It updates the volumetric window and per-IP connection-rate map
// atomically and returns a verdict. Callers that see Volumetric or ConnRate
// verdicts SHOULD tighten their rate limits or early-reject.
type Verdict int

const (
	VerdictOK         Verdict = iota
	VerdictVolumetric         // global RPS has spiked; slow everyone
	VerdictConnRate           // this IP is opening connections too fast
)

// RecordRequest updates counters and returns the verdict for this IP.
func (d *Detector) RecordRequest(ip string) Verdict {
	if d == nil {
		return VerdictOK
	}
	d.totalRequests.Add(1)
	d.advanceVolume()

	// Check global volumetric spike first so a flood from many small IPs
	// still triggers mitigation before the per-IP check runs.
	if d.IsUnderAttack() {
		d.flaggedVolume.Add(1)
		return VerdictVolumetric
	}

	if ip == "" {
		return VerdictOK
	}

	now := time.Now().Unix()
	cutoff := now - 10 // 10-second window
	d.ipMu.Lock()
	defer d.ipMu.Unlock()

	// Lazy eviction — if we're at cap, drop the oldest-touched entry we
	// can find. This is O(cap) once per full table, acceptable for a
	// defensive path that only runs when already under pressure.
	if len(d.ipHits) >= d.cfg.MaxPerIPEntries {
		var oldestIP string
		var oldestTS int64 = now + 1
		for k, hits := range d.ipHits {
			if len(hits) == 0 {
				oldestIP = k
				break
			}
			if hits[len(hits)-1] < oldestTS {
				oldestTS = hits[len(hits)-1]
				oldestIP = k
			}
		}
		if oldestIP != "" {
			delete(d.ipHits, oldestIP)
		}
	}

	hits := d.ipHits[ip]
	// Trim outside window.
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

// RecordSlowRead is called when a body read finishes (or a request errors
// out) with the total bytes seen and the request's age. If the rate is too
// low and the age exceeds SlowMinAge the slow-read counter is bumped.
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

// IsUnderAttack returns whether the last-second RPS exceeded baseline × spike
// factor. Exposed so the proxy can tighten rate limits adaptively.
func (d *Detector) IsUnderAttack() bool {
	if d == nil {
		return false
	}
	return d.underAttack.Load()
}

// advanceVolume shifts the ring forward as wall clock seconds pass and
// re-evaluates the "under attack" flag.
func (d *Detector) advanceVolume() {
	d.volMu.Lock()
	defer d.volMu.Unlock()

	now := time.Now().UTC()
	elapsed := int(now.Sub(d.volLast).Seconds())
	if elapsed > 0 {
		// Zero out any buckets we skipped.
		steps := elapsed
		if steps > len(d.volRing) {
			steps = len(d.volRing)
		}
		for i := 0; i < steps; i++ {
			d.volIndex = (d.volIndex + 1) % len(d.volRing)
			d.volRing[d.volIndex] = 0
		}
		d.volLast = now
	}
	d.volRing[d.volIndex]++

	// Evaluate baseline breach on a 10-second smoothed window.
	var sum uint32
	windowSize := 10
	for i := 0; i < windowSize; i++ {
		idx := (d.volIndex - i + len(d.volRing)) % len(d.volRing)
		sum += d.volRing[idx]
	}
	avg := float64(sum) / float64(windowSize)
	threshold := float64(d.cfg.VolumetricBaseline) * d.cfg.VolumetricSpike
	if avg >= threshold {
		d.underAttack.Store(true)
		d.lastAttackAtUnix.Store(now.Unix())
	} else if now.Sub(time.Unix(d.lastAttackAtUnix.Load(), 0)) > 30*time.Second {
		// Cool-down: only clear after 30 s of normal traffic.
		d.underAttack.Store(false)
	}
}

// StatsSnapshot returns a stable view of counters for the admin API.
func (d *Detector) StatsSnapshot() map[string]interface{} {
	if d == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"total_requests":     d.totalRequests.Load(),
		"flagged_volumetric": d.flaggedVolume.Load(),
		"flagged_conn_rate":  d.flaggedConnRate.Load(),
		"flagged_slow_read":  d.flaggedSlow.Load(),
		"under_attack":       d.underAttack.Load(),
		"last_attack_unix":   d.lastAttackAtUnix.Load(),
	}
}

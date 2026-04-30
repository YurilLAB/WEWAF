// Package audit implements a tamper-evident append-only log.
//
// # Threat model
//
// An operator wants confidence that once an event is written to the audit
// log, no attacker (including a privileged one who gains access to the
// on-disk file) can:
//
//   - delete a historical entry without detection
//   - edit a historical entry without detection
//   - insert a forged entry without detection
//   - reorder entries without detection
//
// The classic construction for this is an HMAC-chained log: every entry
// stores a MAC that covers the entry's payload AND the previous entry's
// MAC, keyed with a long-lived secret. To forge, reorder, or drop an
// entry, an attacker must also recompute every subsequent MAC — which
// requires the secret. A verifier walks the chain and flags the first
// index where the recomputed MAC disagrees with the stored one.
//
// The construction is equivalent to a hash-linked list where the link
// is authenticated. It's used in the same shape as systemd's Forward
// Secure Sealing and Audit-linked-logs in commercial SIEMs.
//
// # What this package is, and isn't
//
// It IS: an append-only log, a signer, and a verifier.
//
// It IS NOT: a secret store. The key lives in memory; if an attacker can
// read the running process's memory they can forge too. For stronger
// guarantees the secret should be rotated periodically and/or come from
// an HSM. We expose enough hooks that such a rotation can happen.
//
// # File format
//
// One JSON object per line, trailing newline. Designed to be grep-able
// in incident response. A truncated trailing line is skipped on load
// rather than treated as corruption — partial writes from a power loss
// shouldn't invalidate everything before them.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is the on-disk / on-wire shape of one audit record.
//
// Seq starts at 1 and increments monotonically. A gap in Seq after a
// Verify() pass is the loudest possible "someone deleted an entry"
// signal we can give — MACs would fail after the gap too, but Seq is
// easier for humans to spot.
type Entry struct {
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`              // e.g. "block", "config_change", "session_rotate"
	Actor     string    `json:"actor,omitempty"`   // client IP, operator name, "system"
	Message   string    `json:"message"`           // short human-readable summary
	Meta      string    `json:"meta,omitempty"`    // free-form JSON blob, not verified structurally
	PrevMAC   string    `json:"prev_mac"`          // hex-encoded MAC of the previous entry (empty for seq=1)
	MAC       string    `json:"mac"`               // hex-encoded HMAC-SHA256 over the other fields
}

// Chain is the append-only log. It owns the signing secret, serialises
// writes, and optionally mirrors each entry to a file on disk.
//
// All methods are safe for concurrent use. Append is the hot path; it
// takes the mutex long enough to compute one HMAC and do one buffered
// file write.
type Chain struct {
	mu      sync.Mutex
	secret  []byte
	seq     uint64
	prevMAC string

	// File persistence. Nil file → in-memory only (useful for tests /
	// ephemeral deployments). We hold an open FD for the life of the
	// chain to avoid re-open-per-append costs.
	file *os.File
	bw   *bufio.Writer

	// In-memory ring for quick /api/audit/tail access. Older entries
	// still live on disk if the file path is configured.
	ring      []Entry
	ringMax   int
	ringHead  int // next slot to write (circular)
	ringSize  int // populated slots, up to ringMax

	// Stats — surfaced to the admin API.
	statsAppends     atomic.Uint64
	statsVerifyFails atomic.Uint64
	firstBadSeq      atomic.Uint64 // 0 = clean chain
}

// Config tunes a Chain. Zero/empty fields get sane defaults.
type Config struct {
	// Secret is the HMAC key. Leave empty to auto-generate — in which case
	// restarting the daemon invalidates the whole historical log's MACs.
	// For persistent audit trails the operator MUST supply a stable secret
	// (e.g. mounted secret file).
	Secret string
	// FilePath is the on-disk mirror. Empty string = in-memory only.
	FilePath string
	// RingSize is the in-memory tail buffer. Default 256.
	RingSize int
}

// New creates (or resumes) a Chain. If the file exists and is non-empty,
// the last entry's MAC becomes the prev-MAC for the next Append so the
// chain continues seamlessly across process restarts.
//
// An empty Secret triggers a cryptographically random 32-byte auto-key.
// Callers that care about cross-restart verifiability MUST set a Secret
// themselves — see package docs.
func New(cfg Config) (*Chain, error) {
	secret := []byte(cfg.Secret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("audit: entropy failure: %w", err)
		}
	}
	ringMax := cfg.RingSize
	if ringMax <= 0 {
		ringMax = 256
	}
	c := &Chain{
		secret:  secret,
		ringMax: ringMax,
		ring:    make([]Entry, ringMax),
	}

	if cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, fmt.Errorf("audit: open %q: %w", cfg.FilePath, err)
		}
		// Scan forward to the end of the file, capturing the last
		// valid entry's seq + MAC so we can continue the chain.
		if err := c.resume(f); err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: seek end: %w", err)
		}
		c.file = f
		c.bw = bufio.NewWriter(f)
	}
	return c, nil
}

// resume reads the existing file, validates as much of the chain as it
// can, and sets c.seq / c.prevMAC so further Appends land on the right
// link. A truncated trailing line is tolerated (power-loss during write
// is a real scenario); a bad MAC mid-stream is surfaced via
// statsVerifyFails AND firstBadSeq so operators see it on the admin UI.
//
// Note: after the first MAC mismatch, every subsequent entry will also
// fail (the chain is broken once tampered) — we still scan to the end
// so the in-memory ring is populated, but only the FIRST bad seq is
// recorded so it stands out cleanly in the dashboard.
func (c *Chain) resume(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Use a Scanner with a larger buffer so oversize entries don't choke.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var (
		lastSeq uint64
		lastMAC string
		prev    string
		seenBad bool
	)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// Incomplete / corrupt tail line — stop scanning rather
			// than abort resume (the power-cut case is the common
			// reason). Track that we observed corruption so callers
			// can surface it: a truncated trailing line is benign,
			// but a corrupt entry mid-file means downstream entries
			// would be silently lost from the in-memory ring (and
			// from any audit verification done before disk recovery).
			c.statsVerifyFails.Add(1)
			if c.firstBadSeq.Load() == 0 {
				c.firstBadSeq.Store(lastSeq + 1)
			}
			fmt.Fprintf(os.Stderr,
				"audit: resume halted by malformed entry after seq %d (%v)\n",
				lastSeq, err)
			break
		}
		// Verify against the prev we've tracked so far.
		want := c.computeMAC(&e, prev)
		if !hmac.Equal([]byte(want), []byte(e.MAC)) {
			if !seenBad {
				c.firstBadSeq.Store(e.Seq)
				seenBad = true
			}
			c.statsVerifyFails.Add(1)
		}
		c.pushRing(e)
		lastSeq = e.Seq
		lastMAC = e.MAC
		prev = e.MAC
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("audit: resume scan: %w", err)
	}
	c.seq = lastSeq
	c.prevMAC = lastMAC
	return nil
}

// computeMAC returns the hex-encoded HMAC-SHA256 over a canonical byte
// serialisation of the entry minus the MAC field itself. Using a fixed
// separator byte between fields prevents field-boundary ambiguity
// attacks (e.g., an attacker splitting a payload across field bounds to
// produce identical MACs).
func (c *Chain) computeMAC(e *Entry, prev string) string {
	h := hmac.New(sha256.New, c.secret)
	var seqBuf [8]byte
	for i := 0; i < 8; i++ {
		seqBuf[i] = byte(e.Seq >> (uint(7-i) * 8))
	}
	h.Write(seqBuf[:])
	h.Write([]byte{0x1f})
	h.Write([]byte(e.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0x1f})
	h.Write([]byte(e.Kind))
	h.Write([]byte{0x1f})
	h.Write([]byte(e.Actor))
	h.Write([]byte{0x1f})
	h.Write([]byte(e.Message))
	h.Write([]byte{0x1f})
	h.Write([]byte(e.Meta))
	h.Write([]byte{0x1f})
	h.Write([]byte(prev))
	return hex.EncodeToString(h.Sum(nil))
}

// Append writes a new entry. Never returns an error for the MAC
// computation itself; a returned error means the file write failed.
//
// IMPORTANT: c.seq and c.prevMAC are only committed after a successful
// disk write (or when running in memory-only mode). Without this, a
// failed write would leave the in-memory chain pointing past an entry
// that doesn't exist on disk — causing every subsequent entry's PrevMAC
// to mis-link against the on-disk record. The cost is one extra write
// of the previous values into local variables; the safety win is
// clean-recovery from a transient I/O error.
func (c *Chain) Append(kind, actor, message, metaJSON string) (Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prevSeq := c.seq
	prevMAC := c.prevMAC
	e := Entry{
		Seq:       prevSeq + 1,
		Timestamp: time.Now().UTC(),
		Kind:      kind,
		Actor:     actor,
		Message:   message,
		Meta:      metaJSON,
		PrevMAC:   prevMAC,
	}
	e.MAC = c.computeMAC(&e, prevMAC)

	if c.bw != nil {
		buf, err := json.Marshal(&e)
		if err != nil {
			// State unchanged — a retry will reuse the same seq + prevMAC.
			return e, fmt.Errorf("audit: marshal: %w", err)
		}
		buf = append(buf, '\n')
		if _, werr := c.bw.Write(buf); werr != nil {
			return e, fmt.Errorf("audit: write: %w", werr)
		}
		// Fsync would be ideal but is expensive; Flush the buffered
		// writer so at least an orderly Stop() persists everything.
		if err := c.bw.Flush(); err != nil {
			return e, fmt.Errorf("audit: flush: %w", err)
		}
	}

	// Commit chain state only after a successful write (or when memory-only).
	c.seq = e.Seq
	c.prevMAC = e.MAC
	c.pushRingLocked(e)
	c.statsAppends.Add(1)
	return e, nil
}

// Verify re-walks either the file (if configured) or the in-memory ring
// and reports the first index whose stored MAC doesn't match the
// recomputed one. Returns (ok, badSeq, total) — badSeq==0 when ok.
func (c *Chain) Verify() (ok bool, badSeq uint64, total uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		return c.verifyFromFileLocked()
	}
	return c.verifyFromRingLocked()
}

func (c *Chain) verifyFromFileLocked() (ok bool, badSeq uint64, total uint64) {
	// Flush before we read so the latest writes are on disk.
	if c.bw != nil {
		_ = c.bw.Flush()
	}
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		c.statsVerifyFails.Add(1)
		return false, 0, 0
	}
	sc := bufio.NewScanner(c.file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var prev string
	var expectSeq uint64
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// Trailing incomplete line — acceptable only as the last one.
			continue
		}
		expectSeq++
		total++
		if e.Seq != expectSeq {
			// Gap — the chain was truncated or entries were deleted.
			c.statsVerifyFails.Add(1)
			return false, expectSeq, total
		}
		if e.PrevMAC != prev {
			c.statsVerifyFails.Add(1)
			return false, e.Seq, total
		}
		want := c.computeMAC(&e, prev)
		if !hmac.Equal([]byte(want), []byte(e.MAC)) {
			c.statsVerifyFails.Add(1)
			return false, e.Seq, total
		}
		prev = e.MAC
	}
	// Restore write position so subsequent Appends still go to the end.
	if _, err := c.file.Seek(0, io.SeekEnd); err != nil {
		return false, 0, total
	}
	return true, 0, total
}

func (c *Chain) verifyFromRingLocked() (ok bool, badSeq uint64, total uint64) {
	count := c.ringSize
	if count == 0 {
		return true, 0, 0
	}
	// Iterate in seq order — the ring is circular, so the oldest slot
	// follows the newest one modulo capacity. Once the ring has wrapped
	// past seq 1 the oldest entry's PrevMAC is whatever came before it
	// on disk; we can't recompute that here, so bootstrap `prev` from
	// the oldest visible entry's stored PrevMAC. We still verify each
	// entry's MAC matches its declared payload + PrevMAC and that the
	// chain links forward consistently — what the in-memory verifier
	// can soundly check. A tamperer who edits an entry inside the ring
	// is still caught by the MAC mismatch on the entry they touched.
	// Without this bootstrap, a clean wrapped ring was reported as
	// corrupt because the loop started prev="" while the oldest
	// entry's PrevMAC was the MAC of the (already evicted) prior seq.
	start := (c.ringHead - count + c.ringMax) % c.ringMax
	prev := c.ring[start].PrevMAC
	for i := 0; i < count; i++ {
		e := c.ring[(start+i)%c.ringMax]
		total++
		if e.PrevMAC != prev {
			c.statsVerifyFails.Add(1)
			return false, e.Seq, total
		}
		want := c.computeMAC(&e, prev)
		if !hmac.Equal([]byte(want), []byte(e.MAC)) {
			c.statsVerifyFails.Add(1)
			return false, e.Seq, total
		}
		prev = e.MAC
	}
	return true, 0, total
}

// Tail returns up to n newest entries, oldest-first.
func (c *Chain) Tail(n int) []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || c.ringSize == 0 {
		return nil
	}
	if n > c.ringSize {
		n = c.ringSize
	}
	out := make([]Entry, 0, n)
	start := (c.ringHead - n + c.ringMax) % c.ringMax
	for i := 0; i < n; i++ {
		out = append(out, c.ring[(start+i)%c.ringMax])
	}
	return out
}

// Stats returns cumulative counters.
func (c *Chain) Stats() (appends uint64, verifyFails uint64) {
	return c.statsAppends.Load(), c.statsVerifyFails.Load()
}

// FirstBadSeq returns the seq number of the first entry that failed MAC
// validation during resume(), or 0 if the chain was clean. Surfaced via
// the admin /api/audit/stats so operators can audit corruption windows.
func (c *Chain) FirstBadSeq() uint64 {
	return c.firstBadSeq.Load()
}

// Close flushes + closes the backing file. Safe to call multiple times.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bw != nil {
		_ = c.bw.Flush()
		c.bw = nil
	}
	if c.file != nil {
		err := c.file.Close()
		c.file = nil
		return err
	}
	return nil
}

func (c *Chain) pushRing(e Entry) {
	c.mu.Lock()
	c.pushRingLocked(e)
	c.mu.Unlock()
}

func (c *Chain) pushRingLocked(e Entry) {
	c.ring[c.ringHead] = e
	c.ringHead = (c.ringHead + 1) % c.ringMax
	if c.ringSize < c.ringMax {
		c.ringSize++
	}
}

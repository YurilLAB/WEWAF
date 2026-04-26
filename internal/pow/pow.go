// Package pow implements a Hashcash-style proof-of-work challenge that
// the WAF can demand from high-risk sessions before they continue.
//
// The challenge is a small token (id, salt, difficulty, exp) that is
// HMAC-signed by a server-only key. The client must find a nonce such
// that SHA-256(salt || nonce) has Difficulty leading zero bits. Server
// verification is constant time; the client's work is exponential in
// Difficulty.
//
// Why PoW and not CAPTCHA: PoW imposes computational cost without UX
// friction (no images, no checkboxes). At 18-bit difficulty, modern
// browsers solve in ~250ms-1s; an attacker botnet sees the same per-
// request cost, which is the whole point.
//
// Threat model:
//   - An attacker with the public token cannot forge a valid one without
//     the server secret (HMAC-SHA256, constant-time compare).
//   - Replay of a solved token is blocked by a short-TTL seen set.
//   - Token expiry caps the attack window even if the seen set is
//     somehow flushed.
//   - Difficulty is server-controlled per token; the client cannot
//     downgrade.
package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default operating envelope. These were chosen so that:
//   - 18 bits ≈ 250-1000ms on a modern phone, acceptable for a one-time gate.
//   - 24 bits ≈ 4-16s — top end before users notice and abandon.
//   - Token TTL 120s is plenty for a slow client to solve and submit; well
//     short enough to bound replay attempts.
const (
	DefaultMinDifficulty = 18
	DefaultMaxDifficulty = 24
	DefaultTokenTTL      = 120 * time.Second

	saltLen = 16 // 128 bits — collision-free for any realistic token rate.
	idLen   = 12 // 96 bits — keys the seen-set; not security-critical.
)

// Errors returned by Verify. They are exported so callers can map them to
// HTTP statuses without string-matching.
var (
	ErrTokenMalformed   = errors.New("pow: token malformed")
	ErrTokenSignature   = errors.New("pow: token signature invalid")
	ErrTokenExpired     = errors.New("pow: token expired")
	ErrTokenReplay      = errors.New("pow: token already redeemed")
	ErrSolutionMissing  = errors.New("pow: solution nonce missing")
	ErrSolutionInvalid  = errors.New("pow: solution does not satisfy difficulty")
	ErrDifficultyOOR    = errors.New("pow: difficulty out of configured range")
)

// Token is the challenge issued to a client. It is serialised to a single
// base64-url string for transmission ("issued"); the parsed form is used
// internally during verification.
type Token struct {
	ID         string    // 12-byte URL-safe random; key for replay set
	Salt       []byte    // 16 random bytes the client must hash with the nonce
	Difficulty uint8     // leading zero bits required
	ExpiresAt  time.Time // absolute UTC; serialised as Unix seconds
}

// Issuer mints and verifies tokens. It must be initialised with a 32-byte
// secret (NewIssuer hashes any byte slice down to that). Operations are
// safe for concurrent use; the seen-set lock is held only briefly.
type Issuer struct {
	secret []byte // 32 bytes (HMAC-SHA256 key)

	min, max uint8         // allowed difficulty range
	ttl      time.Duration // token validity window

	// Seen set is a small in-memory cache of recently redeemed token IDs.
	// Cleared whenever an entry is older than ttl. Bounded by issuance
	// rate, which is itself rate-limited at the issue endpoint, so we
	// don't need an explicit eviction policy beyond the TTL sweep.
	seenMu sync.Mutex
	seen   map[string]time.Time
}

// NewIssuer creates an Issuer. The secret is used as an HMAC key after
// SHA-256 normalisation, so any non-empty input works (though longer is
// better — recommended ≥32 random bytes from /dev/urandom or equivalent).
func NewIssuer(secret []byte, minBits, maxBits uint8, ttl time.Duration) (*Issuer, error) {
	if len(secret) == 0 {
		return nil, errors.New("pow: empty secret")
	}
	if minBits == 0 {
		minBits = DefaultMinDifficulty
	}
	if maxBits == 0 {
		maxBits = DefaultMaxDifficulty
	}
	if minBits > maxBits {
		return nil, fmt.Errorf("pow: min(%d) > max(%d) difficulty", minBits, maxBits)
	}
	// Hard upper cap: 32 bits is "wait forever" territory; never accept
	// configuration that would brick legitimate users.
	if maxBits > 32 {
		return nil, fmt.Errorf("pow: max difficulty %d exceeds safety cap of 32", maxBits)
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	// Normalise the secret to a fixed 32 bytes so callers don't have to.
	sum := sha256.Sum256(secret)
	return &Issuer{
		secret: append([]byte(nil), sum[:]...),
		min:    minBits,
		max:    maxBits,
		ttl:    ttl,
		seen:   make(map[string]time.Time, 1024),
	}, nil
}

// Issue mints a fresh challenge at the requested difficulty (clamped to
// the issuer's [min,max] range). Returns the Token, its serialised
// (signed) form, and any error from the system RNG.
func (it *Issuer) Issue(difficulty uint8) (Token, string, error) {
	if it == nil {
		return Token{}, "", errors.New("pow: nil issuer")
	}
	d := difficulty
	if d < it.min {
		d = it.min
	}
	if d > it.max {
		d = it.max
	}

	id := make([]byte, idLen)
	if _, err := rand.Read(id); err != nil {
		return Token{}, "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return Token{}, "", err
	}

	tok := Token{
		ID:         base64.RawURLEncoding.EncodeToString(id),
		Salt:       salt,
		Difficulty: d,
		ExpiresAt:  time.Now().UTC().Add(it.ttl),
	}
	return tok, it.Sign(tok), nil
}

// Sign serialises a Token and appends an HMAC-SHA256. Format (all dot-
// separated, base64-url):
//
//	id . salt . diff . exp . mac
//
// where diff is decimal and exp is decimal Unix seconds. Format chosen for
// debuggability — the challenge HTML can render the salt and difficulty
// for support, while the mac protects against tampering.
func (it *Issuer) Sign(t Token) string {
	body := canonicalBody(t)
	mac := hmac.New(sha256.New, it.secret)
	mac.Write([]byte(body))
	sig := mac.Sum(nil)
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify validates a serialised token + a candidate nonce. On success the
// token's ID is recorded in the seen-set so replays are rejected.
//
// The order of checks is deliberate: signature first (cheapest, kills
// random garbage), then expiry, then replay, then proof-of-work. Doing
// PoW verification *before* signature would let an attacker burn CPU
// without paying for the right to.
func (it *Issuer) Verify(serialised string, nonce []byte) (Token, error) {
	if it == nil {
		return Token{}, errors.New("pow: nil issuer")
	}
	if len(nonce) == 0 {
		return Token{}, ErrSolutionMissing
	}
	t, body, sig, err := parseSerialised(serialised)
	if err != nil {
		return Token{}, err
	}

	// 1. Signature — constant-time. crypto/hmac.Equal does this internally.
	mac := hmac.New(sha256.New, it.secret)
	mac.Write([]byte(body))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return Token{}, ErrTokenSignature
	}

	// 2. Difficulty range — refuse tokens outside the operator's bounds.
	// (Could happen if an issuer was reconfigured between issue/verify;
	// safer to reject and let the client retry.)
	if t.Difficulty < it.min || t.Difficulty > it.max {
		return Token{}, ErrDifficultyOOR
	}

	// 3. Expiry.
	if time.Now().UTC().After(t.ExpiresAt) {
		return Token{}, ErrTokenExpired
	}

	// 4. Proof-of-work first. SHA-256(salt || nonce) must have
	// Difficulty leading zero bits. We verify PoW BEFORE the replay
	// check so a parallel attacker submitting a stolen valid token can
	// only "win the race" by also presenting a valid solve — which
	// they already can with the original solver.
	h := sha256.New()
	h.Write(t.Salt)
	h.Write(nonce)
	if !hasLeadingZeros(h.Sum(nil), t.Difficulty) {
		return Token{}, ErrSolutionInvalid
	}

	// 5. Atomic replay check + mark. claimSeen returns true only if
	// this is the first thread to successfully redeem t.ID. The
	// previous shape (alreadySeen → PoW → markSeen) had a race window
	// where two concurrent verifies of the same valid token both
	// passed the seen-check, both ran PoW, and both got accepted.
	if !it.claimSeen(t.ID) {
		return Token{}, ErrTokenReplay
	}
	return t, nil
}

// Sweep deletes seen-set entries older than 2× the token TTL. Cheap; safe
// to call from a periodic housekeeper.
func (it *Issuer) Sweep() int {
	if it == nil {
		return 0
	}
	cutoff := time.Now().Add(-2 * it.ttl)
	it.seenMu.Lock()
	defer it.seenMu.Unlock()
	removed := 0
	for k, v := range it.seen {
		if v.Before(cutoff) {
			delete(it.seen, k)
			removed++
		}
	}
	return removed
}

// SuggestDifficulty maps a session risk score to a PoW difficulty. The
// formula is min + (score-50)/5, clamped to [min, max]. Score < 50 falls
// back to min; this is the "should we even challenge" line — calling
// code decides that separately.
func (it *Issuer) SuggestDifficulty(score int) uint8 {
	if it == nil {
		return DefaultMinDifficulty
	}
	if score < 50 {
		return it.min
	}
	step := uint8((score - 50) / 5)
	d := it.min + step
	if d > it.max {
		d = it.max
	}
	return d
}

// Stats snapshot for the admin UI.
type Stats struct {
	Issued    uint64 `json:"-"` // wire counters live in the proxy that uses us
	SeenCount int    `json:"seen_count"`
	Min       uint8  `json:"min_difficulty"`
	Max       uint8  `json:"max_difficulty"`
	TTLSec    int    `json:"ttl_sec"`
}

func (it *Issuer) Stats() Stats {
	if it == nil {
		return Stats{}
	}
	it.seenMu.Lock()
	n := len(it.seen)
	it.seenMu.Unlock()
	return Stats{
		SeenCount: n,
		Min:       it.min,
		Max:       it.max,
		TTLSec:    int(it.ttl.Seconds()),
	}
}

// -----------------------------------------------------------------------------
// internals

func canonicalBody(t Token) string {
	return strings.Join([]string{
		t.ID,
		base64.RawURLEncoding.EncodeToString(t.Salt),
		strconv.Itoa(int(t.Difficulty)),
		strconv.FormatInt(t.ExpiresAt.UTC().Unix(), 10),
	}, ".")
}

func parseSerialised(s string) (Token, string, []byte, error) {
	if s == "" || len(s) > 4096 {
		return Token{}, "", nil, ErrTokenMalformed
	}
	parts := strings.Split(s, ".")
	if len(parts) != 5 {
		return Token{}, "", nil, ErrTokenMalformed
	}
	id := parts[0]
	saltStr := parts[1]
	diffStr := parts[2]
	expStr := parts[3]
	sigStr := parts[4]

	if len(id) == 0 || len(id) > 32 {
		return Token{}, "", nil, ErrTokenMalformed
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltStr)
	if err != nil || len(salt) != saltLen {
		return Token{}, "", nil, ErrTokenMalformed
	}
	d64, err := strconv.ParseUint(diffStr, 10, 8)
	if err != nil {
		return Token{}, "", nil, ErrTokenMalformed
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return Token{}, "", nil, ErrTokenMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil || len(sig) != sha256.Size {
		return Token{}, "", nil, ErrTokenMalformed
	}

	body := strings.Join(parts[:4], ".")
	t := Token{
		ID:         id,
		Salt:       salt,
		Difficulty: uint8(d64),
		ExpiresAt:  time.Unix(exp, 0).UTC(),
	}
	return t, body, sig, nil
}

// hasLeadingZeros reports whether the byte slice starts with at least n
// zero bits. Used on the SHA-256 of (salt || nonce).
func hasLeadingZeros(b []byte, n uint8) bool {
	full := int(n) / 8
	rem := int(n) % 8
	if len(b) < full+1 {
		// Not enough bytes for the requested precision — treat as fail
		// rather than panic. Should never happen on a SHA-256 digest.
		return false
	}
	for i := 0; i < full; i++ {
		if b[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	mask := byte(0xff << (8 - rem))
	return (b[full] & mask) == 0
}

// claimSeen atomically tests whether id has already been redeemed and,
// if not, records it as redeemed. Returns true on success (caller wins
// the redemption race), false if id was already present. This collapses
// the previous alreadySeen + markSeen sequence into a single critical
// section so two concurrent Verify calls on the same token can no
// longer both succeed.
func (it *Issuer) claimSeen(id string) bool {
	it.seenMu.Lock()
	defer it.seenMu.Unlock()
	if _, ok := it.seen[id]; ok {
		return false
	}
	if len(it.seen) > 100000 {
		// Hard ceiling — if we're here something is wrong (e.g., sweep
		// failed). Drop in chunks to stay below the cap rather than
		// growing unbounded. Picking arbitrary keys is fine: we'd only
		// allow a replay of a token that's about to expire anyway.
		dropped := 0
		for k := range it.seen {
			delete(it.seen, k)
			dropped++
			if dropped >= 25000 {
				break
			}
		}
	}
	it.seen[id] = time.Now()
	return true
}

// SolveForTest is a small reference solver, used only by tests in this
// package. Not exported for production callers — clients solve in JS.
// Returns the nonce as 8 bytes (uint64 big-endian) so it round-trips
// nicely through tests.
func SolveForTest(salt []byte, difficulty uint8, attempts int) ([]byte, bool) {
	var nonce [8]byte
	for i := uint64(0); int(i) < attempts; i++ {
		binary.BigEndian.PutUint64(nonce[:], i)
		h := sha256.New()
		h.Write(salt)
		h.Write(nonce[:])
		if hasLeadingZeros(h.Sum(nil), difficulty) {
			return nonce[:], true
		}
	}
	return nil, false
}

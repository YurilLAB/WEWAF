package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestComputeMatchesCanonicalReference computes JA3 for a known input
// and verifies the algorithm by independently reconstructing the canonical
// string and MD5'ing it. If either side drifts the test fails — this is
// the strongest possible "the algorithm is correct" check we can write
// without depending on an external reference implementation.
func TestComputeMatchesCanonicalReference(t *testing.T) {
	in := FingerprintInput{
		Version:         771, // TLS 1.2
		CipherSuites:    []uint16{4865, 4866, 4867, 49195, 49199},
		Extensions:      []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513},
		SupportedCurves: []uint16{29, 23, 24},
		SupportedPoints: []uint8{0},
	}
	got, hash := Compute(in)
	want := "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	if got != want {
		t.Fatalf("canonical string mismatch:\n got: %s\nwant: %s", got, want)
	}
	sum := md5.Sum([]byte(want))
	wantHash := hex.EncodeToString(sum[:])
	if hash != wantHash {
		t.Fatalf("hash mismatch: got %s want %s", hash, wantHash)
	}
}

// TestComputeStripsGREASE proves that GREASE values don't change the
// fingerprint — two ClientHellos that differ only in GREASE picks must
// produce identical hashes. This is mandatory per RFC 8701; if it
// regresses, real Chrome will appear as a unique fingerprint per
// handshake and the whole detector becomes useless.
func TestComputeStripsGREASE(t *testing.T) {
	base := FingerprintInput{
		Version:      771,
		CipherSuites: []uint16{4865, 49195},
		Extensions:   []uint16{0, 10, 43},
	}
	withGrease := FingerprintInput{
		Version: 771,
		// 0x0a0a, 0x1a1a, 0x2a2a are GREASE codepoints.
		CipherSuites: []uint16{0x0a0a, 4865, 0x1a1a, 49195},
		Extensions:   []uint16{0x2a2a, 0, 10, 0x3a3a, 43},
	}
	_, h1 := Compute(base)
	_, h2 := Compute(withGrease)
	if h1 != h2 {
		t.Fatalf("GREASE should be filtered; got distinct hashes %s vs %s", h1, h2)
	}
}

// TestIsGREASE exercises the predicate directly so a bad bit-twiddle
// can't slip past Compute (where it's hidden behind the larger pipeline).
func TestIsGREASE(t *testing.T) {
	cases := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0xfafa: true, 0xeaea: true,
		0x0000: false, 0x0a0b: false, 0x1a0a: false, 4865: false,
	}
	for v, want := range cases {
		if got := IsGREASE(v); got != want {
			t.Errorf("IsGREASE(0x%04x) = %v, want %v", v, got, want)
		}
	}
}

// TestComputeRejectsEmptyInput confirms we don't return a real-looking
// hash for the all-zero input — that would be a magic value that real
// scanners could exploit by stripping their ClientHello to nothing.
func TestComputeRejectsEmptyInput(t *testing.T) {
	s, h := Compute(FingerprintInput{})
	if s != "" || h != "" {
		t.Fatalf("empty input should return empties; got %q / %q", s, h)
	}
}

func TestCachePutGetExpiry(t *testing.T) {
	c := NewCache(8, 50*time.Millisecond)
	fp := Fingerprint{Hash: "abc", String: "771,...", SeenAt: time.Now()}
	c.Put("203.0.113.5:443", fp)

	got, ok := c.Get("203.0.113.5:443")
	if !ok || got.Hash != "abc" {
		t.Fatalf("expected cached entry; got %+v ok=%v", got, ok)
	}
	// Wait past TTL and confirm lazy expiry kicks in.
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get("203.0.113.5:443"); ok {
		t.Fatalf("entry should have expired")
	}
	st := c.Stats()
	if st.Hits == 0 || st.Misses == 0 {
		t.Fatalf("expected both a hit and a miss in stats: %+v", st)
	}
}

// TestCacheCapacityEviction proves the bounded-size guarantee. If this
// regresses we've got an unbounded map — DoS via fingerprint flooding.
func TestCacheCapacityEviction(t *testing.T) {
	c := NewCache(4, time.Hour)
	for i := 0; i < 10; i++ {
		c.Put(makeAddr(i), Fingerprint{Hash: "h", SeenAt: time.Now()})
	}
	st := c.Stats()
	if st.Size > 4 {
		t.Fatalf("cache exceeded capacity: %d > 4", st.Size)
	}
	if st.Evicted == 0 {
		t.Fatalf("expected at least one eviction with 10 inserts into a 4-slot cache")
	}
}

// TestCacheHandlesNilReceiver — defensive: lots of plumbing passes the
// cache around as *Cache and we must never NPE if it's not configured.
func TestCacheHandlesNilReceiver(t *testing.T) {
	var c *Cache
	c.Put("1.2.3.4:1", Fingerprint{Hash: "x"})
	if _, ok := c.Get("1.2.3.4:1"); ok {
		t.Fatal("nil cache returned a hit")
	}
	if got := c.Sweep(); got != 0 {
		t.Fatalf("nil sweep returned %d", got)
	}
	_ = c.Stats()
}

func TestDetectorAllowAndDeny(t *testing.T) {
	d := NewDetector()
	// Built-in bad entry: Go net/http default.
	v := d.Evaluate("e7d705a3286e19ea42f587b344ee6865")
	if v.Match != "bad" || v.Reason == "" {
		t.Fatalf("expected bad match; got %+v", v)
	}
	if v.Blocked {
		t.Fatal("hard-block should default to OFF")
	}
	d.SetHardBlock(true)
	v = d.Evaluate("e7d705a3286e19ea42f587b344ee6865")
	if !v.Blocked {
		t.Fatal("hard-block ON did not produce Blocked verdict")
	}
	// Unknown hash → no match.
	v = d.Evaluate(strings.Repeat("0", 32))
	if v.Match != "" {
		t.Fatalf("expected no-match verdict for unknown hash; got %+v", v)
	}
}

func TestDetectorGoodTakesPrecedence(t *testing.T) {
	d := NewDetector()
	// Force the same hash into BOTH lists; "good" must win to prevent
	// a curated-list collision from harming a legitimate client.
	d.SetLists(
		map[string]string{"deadbeefdeadbeefdeadbeefdeadbeef": "bad"},
		map[string]string{"deadbeefdeadbeefdeadbeefdeadbeef": "good"},
	)
	v := d.Evaluate("deadbeefdeadbeefdeadbeefdeadbeef")
	if v.Match != "good" {
		t.Fatalf("good entry should win; got %+v", v)
	}
}

func TestTrustCheckerAllowsCIDR(t *testing.T) {
	tc := NewTrustChecker([]string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/32"})
	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3:443", true},
		{"203.0.113.7:443", true},
		{"203.0.113.8:443", false},
		{"8.8.8.8:443", false},
		{"[2001:db8::1]:443", true},
		{"[2001:dead::1]:443", false},
		{"", false},
		{"not-an-address", false},
	}
	for _, c := range cases {
		if got := tc.Trusts(c.addr); got != c.want {
			t.Errorf("Trusts(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestTrustCheckerEmptyDefaultsToDeny(t *testing.T) {
	tc := NewTrustChecker(nil)
	if tc.Trusts("10.1.2.3:443") {
		t.Fatal("empty trust list must deny by default")
	}
}

// TestHashFromHeaderRequiresTrust is the security-critical test: a header
// MUST NOT be honored from an untrusted source. If this regresses, any
// internet client can spoof its own JA3 hash and bypass detection.
func TestHashFromHeaderRequiresTrust(t *testing.T) {
	tc := NewTrustChecker([]string{"127.0.0.1/32"})

	// Trusted source — header honored.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-JA3", "e7d705a3286e19ea42f587b344ee6865")
	if h := HashFromHeader(r, "X-JA3", tc); h == "" {
		t.Fatal("trusted source should yield the header hash")
	}

	// Untrusted source — header silently ignored.
	r.RemoteAddr = "8.8.8.8:443"
	if h := HashFromHeader(r, "X-JA3", tc); h != "" {
		t.Fatalf("untrusted source must not yield a hash; got %q", h)
	}
}

func TestHashFromHeaderRejectsMalformed(t *testing.T) {
	tc := NewTrustChecker([]string{"127.0.0.1/32"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"

	for _, val := range []string{
		"", "deadbeef",                    // too short
		strings.Repeat("z", 32),           // non-hex
		strings.Repeat("a", 33),           // wrong length
		"E7D705A3286E19EA42F587B344EE6865", // uppercase OK if normalised
	} {
		r.Header.Set("X-JA3", val)
		got := HashFromHeader(r, "X-JA3", tc)
		switch {
		case strings.EqualFold(val, "E7D705A3286E19EA42F587B344EE6865"):
			if got == "" {
				t.Errorf("uppercase hex should have been accepted")
			}
			if !strings.EqualFold(got, val) {
				t.Errorf("uppercase hash should canonicalise; got %q", got)
			}
		default:
			if got != "" {
				t.Errorf("malformed value %q should be rejected; got %q", val, got)
			}
		}
	}
}

func TestHashFromHeaderEmptyHeaderName(t *testing.T) {
	tc := NewTrustChecker([]string{"0.0.0.0/0"}) // trust everything
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "8.8.8.8:1"
	r.Header.Set("X-JA3", "e7d705a3286e19ea42f587b344ee6865")
	if h := HashFromHeader(r, "", tc); h != "" {
		t.Fatal("empty header name must disable the path entirely")
	}
	if h := HashFromHeader(nil, "X-JA3", tc); h != "" {
		t.Fatal("nil request must return empty string")
	}
}

func TestDetectorStatsCounts(t *testing.T) {
	d := NewDetector()
	for i := 0; i < 5; i++ {
		d.Evaluate("e7d705a3286e19ea42f587b344ee6865") // bad
	}
	for i := 0; i < 3; i++ {
		d.Evaluate("cd08e31494f9531f560d64c695473da8") // good
	}
	d.Evaluate(strings.Repeat("1", 32)) // miss

	st := d.Stats()
	if st.Checks != 9 {
		t.Errorf("checks: got %d want 9", st.Checks)
	}
	if st.MatchBad != 5 {
		t.Errorf("bad: got %d want 5", st.MatchBad)
	}
	if st.MatchOK != 3 {
		t.Errorf("good: got %d want 3", st.MatchOK)
	}
}

// TestRequestRoundTripFromBareIPInTrustList verifies that the trust
// checker accepts a bare IP entry (no /mask) as the operator would type
// it in the config UI.
func TestRequestRoundTripFromBareIPInTrustList(t *testing.T) {
	tc := NewTrustChecker([]string{"203.0.113.7"}) // bare IP; checker promotes to /32
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("Cf-JA3", "e7d705a3286e19ea42f587b344ee6865")
	if h := HashFromHeader(r, "Cf-JA3", tc); h == "" {
		t.Fatal("bare IP allowlist entry should match exact source")
	}
}

// helper
func makeAddr(i int) string {
	return "10.0.0." + intToStr(i) + ":443"
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	n := 0
	for i > 0 {
		b[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = b[n-1-j]
	}
	return string(out)
}

// Unused but keeps `net/http` import lean during refactors.
var _ = http.MethodGet

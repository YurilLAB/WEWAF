package ja3

import (
	"strings"
	"testing"
)

// TestJA4FormatStructure proves the section-A layout: 10 chars,
// transport+version+sni+cipher_count+ext_count+alpn, with sections B/C
// each 12 lowercase hex chars.
func TestJA4FormatStructure(t *testing.T) {
	out := ComputeJA4(JA4Input{
		Version:          0x0304, // TLS 1.3
		HasSNI:           true,
		CipherSuites:     []uint16{0x1301, 0x1302, 0x1303},
		Extensions:       []uint16{0x0000, 0x0010, 0x002b, 0x002d, 0x000a},
		SignatureSchemes: []uint16{0x0403, 0x0804},
		ALPN:             []string{"h2"},
	})
	parts := strings.Split(out, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 must have 3 underscore-separated sections; got %q", out)
	}
	if len(parts[0]) != 10 {
		t.Fatalf("section A must be 10 chars; got %q (%d)", parts[0], len(parts[0]))
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Fatalf("sections B/C must be 12 hex; got %q,%q", parts[1], parts[2])
	}
	for _, h := range []string{parts[1], parts[2]} {
		for i := 0; i < len(h); i++ {
			c := h[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-lowercase-hex char %q in %q", c, h)
			}
		}
	}
	if !strings.HasPrefix(parts[0], "t13d") {
		t.Fatalf("section A prefix expected t13d (TCP, TLS1.3, SNI=domain); got %q", parts[0])
	}
	if !strings.HasSuffix(parts[0], "h2") {
		t.Fatalf("section A should end with ALPN h2; got %q", parts[0])
	}
}

func TestJA4StableUnderExtensionShuffle(t *testing.T) {
	in1 := JA4Input{
		Version:      0x0304,
		HasSNI:       true,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []uint16{0x002b, 0x002d, 0x000a, 0x0017},
		ALPN:         []string{"h2"},
	}
	in2 := in1
	in2.Extensions = []uint16{0x0017, 0x000a, 0x002d, 0x002b} // reverse
	a := ComputeJA4(in1)
	b := ComputeJA4(in2)
	if a != b {
		t.Fatalf("JA4 must be stable under ext shuffle; %q != %q", a, b)
	}
}

func TestJA4StripsGREASE(t *testing.T) {
	with := JA4Input{
		Version:      0x0303,
		HasSNI:       true,
		CipherSuites: []uint16{0x1301, 0x0a0a /* GREASE */, 0x1302},
		Extensions:   []uint16{0x002b, 0xdada /* GREASE */, 0x000a},
		ALPN:         []string{"h2"},
	}
	without := JA4Input{
		Version:      0x0303,
		HasSNI:       true,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []uint16{0x002b, 0x000a},
		ALPN:         []string{"h2"},
	}
	if ComputeJA4(with) != ComputeJA4(without) {
		t.Fatalf("GREASE must be stripped before hashing")
	}
}

func TestJA4ALPNFirstLastChar(t *testing.T) {
	cases := map[string]string{
		"h2":          "h2",
		"http/1.1":    "h1",
		"acme-tls/1":  "a1",
		"":            "00",
	}
	for alpn, want := range cases {
		var alpnList []string
		if alpn != "" {
			alpnList = []string{alpn}
		}
		out := ComputeJA4(JA4Input{
			Version:      0x0303,
			HasSNI:       true,
			CipherSuites: []uint16{0x1301},
			Extensions:   []uint16{0x002b},
			ALPN:         alpnList,
		})
		got := out[8:10]
		if got != want {
			t.Errorf("ALPN %q: want tag %q, got %q (full %q)", alpn, want, got, out)
		}
	}
}

func TestJA4SNIMarker(t *testing.T) {
	d := ComputeJA4(JA4Input{Version: 0x0303, HasSNI: true, CipherSuites: []uint16{0x1301}, Extensions: []uint16{0x002b}, ALPN: []string{"h2"}})
	i := ComputeJA4(JA4Input{Version: 0x0303, HasSNI: false, CipherSuites: []uint16{0x1301}, Extensions: []uint16{0x002b}, ALPN: []string{"h2"}})
	if d[3] != 'd' || i[3] != 'i' {
		t.Fatalf("SNI marker wrong: domain=%c ip=%c", d[3], i[3])
	}
}

func TestJA4VersionMapping(t *testing.T) {
	cases := map[uint16]string{
		0x0304: "13",
		0x0303: "12",
		0x0302: "11",
		0x0301: "10",
		0x0299: "00", // unknown
	}
	for v, want := range cases {
		out := ComputeJA4(JA4Input{Version: v, HasSNI: true, CipherSuites: []uint16{0x1301}, Extensions: []uint16{0x002b}, ALPN: []string{"h2"}})
		got := out[1:3]
		if got != want {
			t.Errorf("version %#x: want %q, got %q", v, want, got)
		}
	}
}

func TestJA4ExcludesSNIAndALPNFromExtCount(t *testing.T) {
	// 5 raw exts, but SNI(0x0000) and ALPN(0x0010) must be excluded → count=3.
	in := JA4Input{
		Version:      0x0303,
		HasSNI:       true,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x0000, 0x0010, 0x002b, 0x002d, 0x000a},
		ALPN:         []string{"h2"},
	}
	out := ComputeJA4(in)
	count := out[6:8] // chars 6-7 are ext count
	if count != "03" {
		t.Fatalf("expected ext count 03 (SNI+ALPN excluded); got %q in %q", count, out)
	}
}

func TestJA4EmptyInputReturnsEmpty(t *testing.T) {
	if ComputeJA4(JA4Input{}) != "" {
		t.Fatal("empty input must return empty fingerprint")
	}
}

func TestJA3NSortsExtensions(t *testing.T) {
	in1 := FingerprintInput{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []uint16{43, 13, 10, 23},
	}
	in2 := in1
	in2.Extensions = []uint16{13, 23, 43, 10}
	_, h1 := ComputeJA3N(in1)
	_, h2 := ComputeJA3N(in2)
	if h1 == "" || h1 != h2 {
		t.Fatalf("JA3N must be order-independent on extensions: %q vs %q", h1, h2)
	}
}

func TestJA3NDiffersFromJA3WhenExtsUnsorted(t *testing.T) {
	in := FingerprintInput{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []uint16{43, 13, 10, 23, 35},
	}
	_, ja3Hash := Compute(in)
	_, ja3nHash := ComputeJA3N(in)
	// They COULD coincide if the input was already sorted; here we
	// deliberately gave reverse order so they must differ.
	if ja3Hash == ja3nHash {
		t.Fatal("with shuffled exts, JA3 and JA3N hashes must differ")
	}
}

func TestEvaluateAllPrefersGood(t *testing.T) {
	d := NewDetector()
	d.SetLists(
		map[string]string{"deadbeefdeadbeefdeadbeefdeadbeef": "fake-bad-ja3"},
		map[string]string{"cafebabecafebabecafebabecafebabe": "fake-good-ja4"},
	)
	v := d.EvaluateAll(Fingerprint{
		Hash: "deadbeefdeadbeefdeadbeefdeadbeef",
		JA4:  "cafebabecafebabecafebabecafebabe",
	})
	if v.Match != "good" {
		t.Fatalf("good must win when JA3 says bad and JA4 says good: %+v", v)
	}
}

func TestEvaluateAllReportsVariant(t *testing.T) {
	d := NewDetector()
	d.SetLists(map[string]string{"abc123": "headless build X"}, nil)
	v := d.EvaluateAll(Fingerprint{JA4: "abc123"})
	if v.Match != "bad" {
		t.Fatalf("expected bad match, got %+v", v)
	}
	if !strings.HasPrefix(v.Reason, "ja4:") {
		t.Fatalf("reason should be tagged with variant; got %q", v.Reason)
	}
}

func TestMergeBadAddsButPreservesExisting(t *testing.T) {
	d := NewDetector()
	d.SetLists(map[string]string{"aaaa": "curated reason"}, nil)
	added := d.MergeBad(map[string]string{
		"aaaa": "feed reason",  // already present → must not overwrite
		"bbbb": "new from feed",
	})
	if added != 1 {
		t.Fatalf("MergeBad should report 1 added; got %d", added)
	}
	v := d.Evaluate("aaaa")
	if v.Reason != "curated reason" {
		t.Fatalf("existing entry was overwritten: %q", v.Reason)
	}
	if d.Evaluate("bbbb").Match != "bad" {
		t.Fatal("new feed entry not picked up")
	}
}

func TestAnomalyUAClaimsBrowserButJA3Curl(t *testing.T) {
	a := NewAnomalyDetector()
	r := a.Check(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Fingerprint{Hash: "6fa3244afc6bb6f9fad207b6b52af26b" /* curl */},
	)
	if r.ScoreBump == 0 {
		t.Fatal("UA-claims-browser + JA3-curl must produce score bump")
	}
	if len(r.Tags) == 0 || !strings.Contains(strings.Join(r.Tags, ","), "ja3-curl") {
		t.Fatalf("expected ja3-curl anomaly tag; got %v", r.Tags)
	}
}

func TestAnomalyAllowsLegitChrome(t *testing.T) {
	a := NewAnomalyDetector()
	// Real-Chrome-ish JA4 with browser UA — must NOT bump.
	r := a.Check(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
		Fingerprint{
			Hash: "cd08e31494f9531f560d64c695473da8", // good list entry
			JA4:  "t13d1516h2_8daaf6152771_b186095e22b6",
		},
	)
	if r.ScoreBump != 0 {
		t.Fatalf("legit Chrome must not produce anomaly: %+v", r)
	}
}

func TestAnomalyEmptyInputIsNoop(t *testing.T) {
	a := NewAnomalyDetector()
	if r := a.Check("", Fingerprint{}); r.ScoreBump != 0 {
		t.Fatal("empty input must be a no-op")
	}
	if r := a.Check("Mozilla/5.0", Fingerprint{}); r.ScoreBump != 0 {
		t.Fatal("missing fingerprint must be a no-op")
	}
}

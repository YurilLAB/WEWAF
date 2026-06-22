package engine

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// These fuzz targets exercise the request canonicalizer — the most
// security-load-bearing byte manipulation in the WAF. A panic here is a
// remote DoS (the WAF crashes on a crafted URI/arg), and a decode that
// diverges from what the backend does is a rule bypass. None of these
// functions has an internal recover(), so the fuzzer's panic/hang/OOM
// detection is the real assertion; the explicit invariants below catch the
// subtler "produced garbage / grew unboundedly" class.
//
// Run one with, e.g.:
//   go test -run=^$ -fuzz=^FuzzCanonicalize$ -fuzztime=60s ./internal/engine/

func canonSeeds() []string {
	seeds := []string{
		"",
		"/",
		"..%2f..%2f..%2fetc/passwd",
		"%2525%32%66",
		"%u003cscript%u003ealert(1)%u003c/script%u003e",
		"%c0%ae%c0%ae%c0%af",
		"%0d%0aSet-Cookie:x",
		"\x00\r\n\t",
		"%%%%%",
		"%u",
		"%uZZZZ",
		"%uD800%uDC00", // lone/paired surrogates
		"../\xff\xfe..//./",
		strings.Repeat("%25", 200),
		strings.Repeat("%u0041", 100),
	}
	// Confusable / invisible seeds built from code points so the source file
	// stays pure ASCII (a literal U+FEFF in source is an illegal BOM).
	seeds = append(seeds,
		string([]rune{0x202e, 0x200b, 0xfeff})+"admin",                  // RTL override + ZWSP + BOM
		string([]rune{0xff33, 0xff25, 0xff2c, 0xff25, 0xff23, 0xff34}),  // fullwidth SELECT
		string([]rune{0x0440, 0x0430, 0x0455, 0x0455})+"word",          // cyrillic homoglyphs
	)
	return seeds
}

// FuzzCanonicalize lives in fuzz_targets_test.go (merged from the parallel
// fuzz-harness line). The targets below cover the canonicalizer helpers that
// file does not.

func FuzzCanonicalizePath(f *testing.F) {
	for _, s := range canonSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := CanonicalizePath(s)
		if !strings.HasPrefix(out, "/") {
			t.Fatalf("CanonicalizePath result must be rooted: %q -> %q", s, out)
		}
		if !utf8.ValidString(out) {
			t.Fatalf("CanonicalizePath produced invalid UTF-8: %q -> %q", s, out)
		}
		// No ".." segment may survive resolution — that is the whole point of
		// the segment walk; a surviving "/../" would mean a traversal the WAF
		// normalised away on paper but not in fact.
		for _, seg := range strings.Split(out, "/") {
			if seg == ".." {
				t.Fatalf("unresolved .. segment in CanonicalizePath(%q) = %q", s, out)
			}
		}
	})
}

func FuzzDecodePercentU(f *testing.F) {
	for _, s := range canonSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := decodePercentU(s)
		// %uXXXX (6 ASCII bytes) collapses to at most a 4-byte rune; every
		// other byte is copied verbatim. So the output can never be longer than
		// the input — a regression that expands would be an amplification / loop
		// bug. (decodePercentU intentionally preserves any invalid-UTF-8 bytes
		// it did not decode; UTF-8 validity is restored later in Canonicalize.)
		if len(out) > len(s) {
			t.Fatalf("decodePercentU expanded %d -> %d for %q", len(s), len(out), s)
		}
	})
}

func FuzzFoldHomoglyphs(f *testing.F) {
	for _, s := range canonSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := FoldHomoglyphs(s)
		if utf8.ValidString(s) && !utf8.ValidString(out) {
			t.Fatalf("FoldHomoglyphs broke UTF-8 validity for %q", s)
		}
	})
}

func FuzzHasObfuscatedTransferEncoding(f *testing.F) {
	for _, s := range []string{"chunked", "chunked, chunked", "\tchunked", "gzip, chunked", "identity", "x\vchunked", ""} {
		f.Add(s, "")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		// Two header values — mirrors how net/http surfaces repeated headers.
		_ = HasObfuscatedTransferEncoding([]string{a, b})
	})
}

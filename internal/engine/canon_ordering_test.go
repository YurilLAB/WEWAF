package engine

import "testing"

const zwsp = "​"       // U+200B zero-width space
const softHyphen = "­" // format char, also stripped

// TestCanonZeroWidthSchemeSeparator pins the canonicalizer-ordering bug the
// equivalence fuzzer (FuzzCanonicalizeReversal) surfaced: a zero-width / format
// rune inserted between a scheme ':' and its '//' must be stripped BEFORE slash
// collapsing, so the "://" the scheme-anchored rules (SSRF / open-redirect /
// gopher / CRS-931130) depend on survives — it previously collapsed to ":/".
func TestCanonZeroWidthSchemeSeparator(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https:" + zwsp + "//evil.ru/", "https://evil.ru/"},
		{"http:" + softHyphen + "//169.254.169.254/", "http://169.254.169.254/"},
		{"gopher:" + zwsp + "//127.0.0.1:6379/", "gopher://127.0.0.1:6379/"},
		// A plain scheme separator is unchanged (regression guard for the
		// collapseSlashes ':// preservation' that this reorder must not disturb).
		{"https://evil.com/a", "https://evil.com/a"},
		// Non-scheme double slash still collapses.
		{"/foo//bar", "/foo/bar"},
	}
	for _, c := range cases {
		if got := Canonicalize(c.in); got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

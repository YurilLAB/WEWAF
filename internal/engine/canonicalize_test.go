package engine

import "testing"

func TestCanonicalizeCollapsesEncoding(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/%2e%2e/%2e%2e/etc/passwd", "/../../etc/passwd"},
		{"/%252e%252e/etc", "/../etc"},
		{"\\etc\\passwd", "/etc/passwd"},
		{"/foo\x00.bar", "/foo.bar"},
	}
	for _, c := range cases {
		if got := Canonicalize(c.in); got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalizePathResolvesTraversal(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/foo//bar", "/foo/bar"},
		{"/foo/./bar", "/foo/bar"},
		{"/foo/../bar", "/bar"},
		{"/../../etc", "/etc"},
	}
	for _, c := range cases {
		if got := CanonicalizePath(c.in); got != c.want {
			t.Errorf("CanonicalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFoldHomoglyphsASCIIFast(t *testing.T) {
	// Pure ASCII should return identity.
	if got := FoldHomoglyphs("/api/login"); got != "/api/login" {
		t.Errorf("ASCII input modified: %q", got)
	}
}

func TestFoldHomoglyphsCyrillic(t *testing.T) {
	// Cyrillic 'а' (U+0430) should fold to ASCII 'a'.
	in := "sеlеct" // e's are Cyrillic U+0435
	got := FoldHomoglyphs(in)
	if got != "select" {
		t.Errorf("FoldHomoglyphs(%q) = %q, want %q", in, got, "select")
	}
}

// TestCanonicalizeStripsFormatRunes documents the bypass class that
// motivated the Unicode-aware fast path: ZWJ / ZWNJ / ZWSP / BOM /
// RTL-override appear identical to the absence of any character to a
// browser, but split rule-targeted strings into mismatching byte
// sequences. Canonicalize must drop them before signature matching.
//
// We construct the inputs from \u escapes rather than embedding the
// literal runes — Go's compiler refuses a BOM at file scope, and a
// future tool that strips "invisible characters" from the source
// could silently delete the test's payload otherwise.
func TestCanonicalizeStripsFormatRunes(t *testing.T) {
	// BOM (U+FEFF) is illegal as a literal in a Go source file, so we
	// build the BOM-prefixed input string from a rune at runtime.
	bom := string(rune(0xFEFF))
	cases := []struct {
		name string
		in   string
	}{
		{"zwj_in_script", "<s‍cript>"},
		{"zwnj_in_script", "<s‌cript>"},
		{"zwsp_in_script", "<s​cript>"},
		{"rtl_override", "/admin‮"},
		{"bom_prefix", bom + "admin"},
		{"mongolian_vowel_separator", "ad᠎min"},
	}
	formatRunes := []rune{0x200D, 0x200C, 0x200B, 0x202E, 0xFEFF, 0x180E}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Canonicalize(tc.in)
			for _, r := range formatRunes {
				for _, c := range got {
					if c == r {
						t.Fatalf("U+%04X survived canonicalization in %q", r, got)
					}
				}
			}
		})
	}
}

// TestFoldHomoglyphsLowercaseGreek closes the gap an audit found in
// the original conservative map: lowercase Greek letters that look
// identical to Latin (rho/alpha/beta/epsilon/etc.) were not mapped,
// so an attacker could hide rule-targeted tokens like "ρassword" or
// "αlert" past the canonicalizer.
func TestFoldHomoglyphsLowercaseGreek(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"αlert", "alert"},   // Greek small alpha
		{"κey", "key"},       // Greek small kappa
		{"ρassword", "password"},
		{"μser", "user"},     // Greek small mu (looks like Latin u)
		{"νode", "vode"},     // Greek small nu (looks like v)
		{"τest", "test"},     // Greek small tau
		{"χss", "xss"},       // Greek small chi
	}
	for _, tc := range cases {
		got := FoldHomoglyphs(tc.in)
		if got != tc.want {
			t.Errorf("FoldHomoglyphs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasObfuscatedTransferEncoding(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"clean chunked", []string{"chunked"}, false},
		{"clean identity", []string{"identity"}, false},
		{"gzip + chunked", []string{"gzip, chunked"}, false},
		{"duplicated chunked", []string{"chunked, chunked"}, true},
		{"tab padded", []string{"\tchunked"}, true},
		{"garbage + chunked", []string{"xchunked"}, true},
	}
	for _, c := range cases {
		if got := HasObfuscatedTransferEncoding(c.in); got != c.want {
			t.Errorf("%s: HasObfuscatedTransferEncoding(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

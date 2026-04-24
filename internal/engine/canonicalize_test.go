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

package engine

import (
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Canonicalize collapses common attacker encoding tricks into a single
// comparable form before rule matching.
//
// The transforms applied, in order:
//  1. Recursive URL decoding (bounded to 3 passes so "%2525" → "%25" → "%")
//  2. Backslash → forward slash (Windows path confusion)
//  3. Null-byte stripping
//  4. Unicode NFKC compat normalization (fullwidth / ligature tricks)
//  5. Collapse consecutive slashes and resolve "./" and "../" segments
//  6. Lowercase when applied to header names
//
// This is applied to URL paths, query arguments, and body strings so that
// pattern rules only have to match one representation. Without this, a
// double-encoded "%2E%2E%2F" or a fullwidth "．．／" slips past the regex.
//
// The function allocates one new string per call; callers can cheaply retain
// the original value if they also want to log what came over the wire.
func Canonicalize(s string) string {
	if s == "" {
		return s
	}
	out := s
	for i := 0; i < 3; i++ {
		dec, err := url.QueryUnescape(out)
		if err != nil || dec == out {
			break
		}
		out = dec
	}
	out = strings.ReplaceAll(out, "\\", "/")
	if strings.IndexByte(out, 0) >= 0 {
		out = strings.ReplaceAll(out, "\x00", "")
	}
	out = norm.NFKC.String(out)
	out = collapseSlashes(out)
	out = stripControlChars(out)
	return out
}

// CanonicalizePath normalises a URL path so that "..//foo/./bar", "//foo/bar"
// and the fullwidth "／foo／bar" all reduce to "/foo/bar". Path-traversal
// attempts that escape the server root are preserved (they should still
// match SECURITY rules) but every path has exactly one canonical form.
func CanonicalizePath(p string) string {
	p = Canonicalize(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Resolve "." and ".." segments.
	segments := strings.Split(p, "/")
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

// CanonicalizeHeaderName returns the MIME-canonical form of a header name.
// We don't use http.CanonicalMIMEHeaderKey here because we want lowercase
// for consistent map keys in match targets.
func CanonicalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func collapseSlashes(s string) string {
	if !strings.Contains(s, "//") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSlash := false
	for _, r := range s {
		if r == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// stripControlChars removes ASCII control characters that attackers use to
// split headers, smuggle requests, or break rule-matching (\r, \n, \x7f).
// Tab and space are preserved — they're legitimate in form data.
func stripControlChars(s string) string {
	hasControl := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' {
			hasControl = true
			break
		}
		if c == 0x7f {
			hasControl = true
			break
		}
	}
	if !hasControl {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			continue
		}
		if r == 0x7f {
			continue
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

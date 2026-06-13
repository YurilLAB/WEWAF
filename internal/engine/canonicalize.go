package engine

import (
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
	// Strip raw NUL bytes BEFORE decoding: a NUL embedded mid-escape
	// ("%<NUL>3c") would otherwise break the percent-escape and hide the
	// following %XX from the decoder, while a backend that simply drops NULs
	// still decodes it. (Surfaced by the canonicalizer fuzzer.)
	if strings.IndexByte(out, 0) >= 0 {
		out = strings.ReplaceAll(out, "\x00", "")
	}
	for i := 0; i < 3; i++ {
		// Lenient percent-decoding: decode every valid %XX and pass malformed
		// escapes through literally. url.QueryUnescape is all-or-nothing — it
		// errors on the FIRST bad escape and decodes NOTHING — so a payload
		// like "%zz%3cscript%3e" reached canonicalization fully encoded and
		// bypassed the rules, while a per-character-decoding backend still saw
		// "<script>". (Surfaced by the canonicalizer fuzzer.)
		if dec, changed := lenientUnescape(out); changed {
			out = dec
			continue
		}
		// Then IIS / .NET %uXXXX, which percent-decoding does not cover. A
		// payload like %u003cscript%u003e survives standard decoding unchanged
		// but classic IIS / ASP.NET backends decode it to <script>; decoding it
		// here lets the existing signatures match. Bounded by the same 3-pass
		// loop so %25u003c (double-encoded) unfolds.
		if u := decodePercentU(out); u != out {
			out = u
			continue
		}
		break
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

// FoldHomoglyphs rewrites visually-confusable Cyrillic / Greek letters that
// look like ASCII so rules that match e.g. "script" still catch obfuscated
// payloads that use Cyrillic small-letter-es (U+0441) where "c" would be.
// NFKC alone doesn't collapse these because they're distinct code points —
// only their glyphs overlap. This list targets the handful of confusables
// that show up in real WAF-bypass attempts and not the full Unicode chart.
func FoldHomoglyphs(s string) string {
	// Fast path: pure ASCII needs no replacement.
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := homoglyphMap[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// homoglyphMap is a conservative subset of the Unicode confusables that are
// commonly used to bypass WAF string matching. We keep it small and ASCII-
// only on the right side so mapped strings remain regex-compatible.
//
// Fullwidth punctuation (／ ＼ ＜ ＞ etc.) is NOT in this map because NFKC
// normalisation — applied earlier in Canonicalize — already collapses
// them to ASCII. Only code points NFKC leaves alone belong here.
var homoglyphMap = map[rune]rune{
	// Cyrillic lookalikes — the lowercase block is the realistic attack
	// surface (matches "select", "admin", "script" word-shapes); we add
	// uppercase confusables for completeness.
	'а': 'a',
	'А': 'A',
	'В': 'B',
	'е': 'e',
	'Е': 'E',
	'о': 'o',
	'О': 'O',
	'р': 'p',
	'Р': 'P',
	'с': 'c',
	'С': 'C',
	'у': 'y',
	'У': 'Y',
	'х': 'x',
	'Х': 'X',
	'Ѕ': 'S',
	'І': 'I',
	'Ј': 'J',
	'К': 'K',
	'Н': 'H',
	'М': 'M',
	'Т': 'T',
	// Greek capital lookalikes
	'Α': 'A',
	'Β': 'B',
	'Ε': 'E',
	'Ζ': 'Z',
	'Η': 'H',
	'Κ': 'K',
	'Μ': 'M',
	'Ν': 'N',
	'Ο': 'O',
	'Ρ': 'P',
	'Τ': 'T',
	'Χ': 'X',
	// Greek lowercase lookalikes — the audit gap. ρassword / αlert /
	// μser variants previously slipped past the canonicalizer because
	// NFKC doesn't normalise these to ASCII.
	'α': 'a',
	'β': 'b',
	'ε': 'e',
	'ι': 'i',
	'κ': 'k',
	'μ': 'u', // visually closer to u than to m in most fonts
	'ν': 'v',
	'ο': 'o',
	'ρ': 'p',
	'τ': 't',
	'υ': 'u',
	'χ': 'x',
	'ζ': 'z',
}

// HasObfuscatedTransferEncoding returns true if a Transfer-Encoding header
// uses smuggling tricks like "chunked, chunked", whitespace padding around
// the value, or an obfuscated keyword. This extends the basic TE+CL mismatch
// detection with variants several smuggling PoCs use in practice.
func HasObfuscatedTransferEncoding(values []string) bool {
	for _, raw := range values {
		// Inspect the raw value first — tab/vtab/form-feed around the token
		// is itself a smuggling signal, and TrimSpace would hide it.
		for i := 0; i < len(raw); i++ {
			if raw[i] == '\t' || raw[i] == '\v' || raw[i] == '\f' {
				return true
			}
		}
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || v == "identity" || v == "chunked" || v == "gzip" || v == "deflate" {
			continue
		}
		// "chunked, chunked", "chunked , chunked" — duplicate signal.
		if strings.Count(v, "chunked") >= 2 {
			return true
		}
		// Any unrecognised encoding on a request path smells suspicious.
		switch v {
		case "gzip, chunked", "chunked, gzip",
			"deflate, chunked", "chunked, deflate",
			"identity, chunked", "chunked, identity",
			"br, chunked", "chunked, br":
			// Legitimate combinations per RFC 9112 §7.1.
		default:
			if strings.Contains(v, "chunked") {
				return true
			}
		}
	}
	return false
}

// lenientUnescape percent-decodes every valid %XX sequence and passes
// malformed ones through literally, and (matching the previous
// url.QueryUnescape behaviour) treats '+' as a space. Unlike
// url.QueryUnescape it never gives up on the whole string: a single bad
// escape no longer prevents decoding of the valid escapes around it, which
// was a rule-bypass (see Canonicalize). Returns (decoded, changed).
func lenientUnescape(s string) (string, bool) {
	if !strings.ContainsAny(s, "%+") {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]):
			b.WriteByte(unhexByte(s[i+1])<<4 | unhexByte(s[i+2]))
			i += 2
			changed = true
		case c == '+':
			b.WriteByte(' ')
			changed = true
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), changed
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// decodePercentU rewrites IIS / .NET %uXXXX sequences into their code point.
// %u003c -> '<'. url.QueryUnescape does not handle this non-standard form, so
// without it a %u-encoded payload reaches a decoding backend uninspected. Only
// well-formed %u + exactly four hex digits are decoded; everything else is
// copied through byte-for-byte so the function never corrupts normal input.
func decodePercentU(s string) string {
	// Fast path — no %u / %U present.
	if !strings.Contains(s, "%u") && !strings.Contains(s, "%U") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+6 <= len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if r, ok := hex4(s[i+2 : i+6]); ok {
				b.WriteRune(r)
				i += 6
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hex4 parses exactly four hex digits into a rune. Returns ok=false on any
// non-hex byte or wrong length so the caller leaves the input untouched.
func hex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var v rune
	for i := 0; i < 4; i++ {
		c := s[i]
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
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
// split headers, smuggle requests, or break rule-matching (\r, \n, \x7f),
// AND multi-byte format-class characters (zero-width joiners, RTL
// overrides, byte-order marks) that attackers use to render rule-evading
// payloads in the browser while presenting different bytes to the
// canonicalizer. Tab and space are preserved — they're legitimate in
// form data.
//
// Algorithm note: the previous fast-path scanned for ASCII control bytes
// only (`< 0x20`), which let UTF-8-encoded ZWJ (E2 80 8D), ZWSP (E2 80
// 8B), RTL-override (E2 80 AE) and similar slip through unchanged. The
// fast-path now also flags any byte ≥ 0x80 — i.e. any non-ASCII rune —
// so the slow-path runs whenever the string contains characters whose
// printability we have to decide via Unicode tables.
func stripControlChars(s string) string {
	needsScan := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' {
			needsScan = true
			break
		}
		if c == 0x7f {
			needsScan = true
			break
		}
		if c >= 0x80 {
			// Any non-ASCII byte forces the Unicode-aware scan below
			// so format-class runes (Cf) get filtered.
			needsScan = true
			break
		}
	}
	if !needsScan {
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
			// IsPrint returns false for Unicode category Cf (format),
			// which covers ZWJ (U+200D), ZWNJ (U+200C), ZWSP (U+200B),
			// LRM/RLM, RTL/LTR override (U+202D / U+202E), Mongolian
			// vowel separator, and the BOM (U+FEFF). Stripping them
			// kills the "looks like X but matches as Y" bypass class.
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

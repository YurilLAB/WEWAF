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
	out = foldOverlongUTF8(out)
	out = strings.ReplaceAll(out, "\\", "/")
	if strings.IndexByte(out, 0) >= 0 {
		out = strings.ReplaceAll(out, "\x00", "")
	}
	out = norm.NFKC.String(out)
	out = collapseSlashes(out)
	out = normalizeControlAndSpace(out)
	return out
}

// NormalizeForMatch applies the Unicode + whitespace + zero-width
// normalization used for rule matching WITHOUT the URL-decode / slash-collapse
// steps that only make sense for paths and query args. It is meant for request
// body strings (which are otherwise matched raw):
//
//   - NFKC compatibility normalization folds fullwidth / ligature / circled
//     look-alikes to ASCII (ＵＮＩＯＮ → UNION), matching what frameworks that
//     normalize user input before using it will do;
//   - homoglyph folding maps Cyrillic/Greek look-alikes to ASCII;
//   - whitespace-class runes collapse to a space and zero-width/format runes
//     are dropped (defeats "UNION\vSELECT" and "U​NION").
//
// It does NOT URL-decode (that would corrupt a JSON/XML body) or collapse
// slashes. The result is used as an additional "body.norm" target alongside
// the verbatim body, so structural rules that depend on exact bytes still see
// the original.
func NormalizeForMatch(s string) string {
	s = norm.NFKC.String(s)
	s = FoldHomoglyphs(s)
	return normalizeControlAndSpace(s)
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

// foldOverlongUTF8 maps the overlong / invalid UTF-8 encodings of '/', '\'
// and '.' to their ASCII forms so path-traversal rules still match after the
// canonicalizer's URL-decode pass. Attackers send "%c0%af" / "%e0%80%af" etc.
// because url.QueryUnescape decodes them into raw invalid bytes (0xC0 0xAF …)
// that no longer match the literal "../" patterns; legacy backends (old IIS /
// Tomcat) then re-interpret them as a slash. These exact byte sequences are
// invalid UTF-8 and never occur in legitimate text, so the mapping cannot
// introduce false positives.
func foldOverlongUTF8(s string) string {
	if strings.IndexByte(s, 0xC0) < 0 && strings.IndexByte(s, 0xC1) < 0 &&
		!strings.Contains(s, "\xe0\x80") && !strings.Contains(s, "\xf0\x80\x80") {
		return s
	}
	replacer := strings.NewReplacer(
		// overlong '/'
		"\xc0\xaf", "/",
		"\xe0\x80\xaf", "/",
		"\xf0\x80\x80\xaf", "/",
		// overlong '\' (incl. the classic IIS %c1%9c)
		"\xc1\x9c", "/",
		"\xc0\x9c", "/",
		"\xe0\x80\x9c", "/",
		// overlong '.'
		"\xc0\xae", ".",
		"\xe0\x80\xae", ".",
		"\xf0\x80\x80\xae", ".",
	)
	return replacer.Replace(s)
}

// collapseSlashes squeezes runs of consecutive forward slashes down to one,
// which normalises path-confusion tricks like "/foo//bar" and "//foo". The
// one exception is the "://" scheme separator: collapsing it to ":/" turned
// "http://169.254.169.254" into "http:/169.254.169.254" and silently defeated
// every scheme-anchored rule (https?://, gopher://, the decimal-IP SSRF rule,
// open-redirect rules, …) whenever they matched a canonicalised arg/uri. The
// second slash of a "://" run is therefore preserved.
func collapseSlashes(s string) string {
	if !strings.Contains(s, "//") {
		return s
	}
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '/' && i > 0 && runes[i-1] == '/' {
			// 2nd+ slash of a run. Keep it only when it is the 2nd slash of a
			// "://" scheme separator (the char before the run is ':').
			if i >= 2 && runes[i-2] == ':' {
				b.WriteRune(r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalizeControlAndSpace rewrites a string so signature matching sees one
// canonical whitespace form and no zero-width obfuscation:
//
//   - Every whitespace-class rune (\t \n \v \f \r, NBSP, NEL, and Unicode
//     space separators) becomes a single ASCII space. The previous code
//     *deleted* control chars, which merged "UNION\nSELECT" into
//     "UNIONSELECT" and defeated every rule that requires a token separator;
//     worse, vertical-tab (\v, 0x0B) and form-feed (\f, 0x0C) are NOT in Go's
//     RE2 \s class ([\t\n\f\r ] — note \f is in, \v is not), so "UNION\vSELECT"
//     sailed past \s-based rules entirely while still parsing as whitespace in
//     backends such as MySQL. Replacing with a space neutralises CR/LF
//     splitting AND keeps keyword boundaries intact for matching.
//   - Zero-width / format runes (ZWSP, ZWJ, ZWNJ, BOM, RTL/LTR override, soft
//     hyphen, Mongolian vowel separator — Unicode category Cf) are deleted so
//     "U​NION" reassembles to "UNION".
//   - Other non-printing control bytes and DEL (0x7F) are deleted.
//
// The forwarded request is unaffected — this is only the representation the
// rule engine matches against.
func normalizeControlAndSpace(s string) string {
	needsScan := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Any control byte (incl. \t), DEL, or non-ASCII byte forces the
		// Unicode-aware pass below. A run of plain ASCII printables + spaces
		// needs no work.
		if c < 0x20 || c == 0x7f || c >= 0x80 {
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
		switch {
		case r == ' ':
			b.WriteByte(' ')
		case unicode.IsSpace(r):
			// \t \n \v \f \r, NBSP (U+00A0), NEL (U+0085), and every Unicode
			// Zs/Zl/Zp separator collapse to one ASCII space.
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// Non-whitespace C0 control / DEL → drop.
			continue
		case !unicode.IsPrint(r):
			// Unicode category Cf (format): ZWJ/ZWNJ/ZWSP, LRM/RLM, RTL/LTR
			// override, Mongolian vowel separator, BOM, soft hyphen → drop.
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

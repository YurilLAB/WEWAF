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

// blockedRawArg places the payload in a query arg WITHOUT extra url-encoding
// of the value beyond what url.Values does, so byte-level tricks (control
// chars, etc.) survive into the canonicalizer the way a real client sends
// them via ?x=<percent-encoded>.
func blockedRawArg(eng *Engine, payload string) bool {
	q := url.Values{"x": {payload}}.Encode()
	req := httptest.NewRequest(http.MethodGet, "/probe?"+q, nil)
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil
}

// transform is a named payload mutation representing an evasion *technique*.
type transform struct {
	name string
	fn   func(string) string
}

// techniqueTransforms apply, to a payload that contains ASCII spaces, the
// common ways attackers obfuscate the separators / keywords while keeping the
// payload semantically valid to the backend parser.
func techniqueTransforms() []transform {
	repl := func(old, new string) func(string) string {
		return func(s string) string { return strings.ReplaceAll(s, old, new) }
	}
	return []transform{
		{"baseline", func(s string) string { return s }},
		{"ws->tab", repl(" ", "\t")},
		{"ws->newline", repl(" ", "\n")},
		{"ws->cr", repl(" ", "\r")},
		{"ws->formfeed", repl(" ", "\x0c")},
		{"ws->vtab", repl(" ", "\x0b")},
		{"ws->nbsp", repl(" ", " ")},
		{"ws->comment", repl(" ", "/**/")},
		{"ws->doublespace", repl(" ", "  ")},
		{"ws->plus", repl(" ", "+")},
		{"upper", strings.ToUpper},
		{"null-in-space", repl(" ", "\x00 ")},
		{"zwsp-in-space", repl(" ", "​ ")},
		{"fullwidth", toFullwidth},
		{"cyrillic-homoglyph", cyrillicHomoglyph},
	}
}

// toFullwidth maps ASCII letters/digits to their Unicode fullwidth forms
// (U+FF01..U+FF5E). A framework that NFKC-normalizes user input before use
// will see the ASCII payload, so the WAF must normalize too.
func toFullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '!' && r <= '~' {
			b.WriteRune(r - 0x21 + 0xFF01)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cyrillicHomoglyph swaps a few ASCII letters for visually identical Cyrillic
// code points (the classic homoglyph evasion).
func cyrillicHomoglyph(s string) string {
	rep := strings.NewReplacer(
		"e", "е", "o", "о", "a", "а", "c", "с", "p", "р", "x", "х",
		"E", "Е", "O", "О", "A", "А", "C", "С", "P", "Р", "X", "Х",
	)
	return rep.Replace(s)
}

// keywordSplits insert obfuscation INSIDE keywords (the second technique
// class): a control/zero-width char between letters that the WAF might strip
// (merging or breaking the token) but the backend tokenizer ignores.
func keywordSplits() []transform {
	return []transform{
		{"baseline", func(s string) string { return s }},
		{"null-split", func(s string) string { return splitFirstAlpha(s, "\x00") }},
		{"zwsp-split", func(s string) string { return splitFirstAlpha(s, "​") }},
	}
}

// splitFirstAlpha inserts sep after the first alphabetic character.
func splitFirstAlpha(s, sep string) string {
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return s[:i+1] + sep + s[i+1:]
		}
	}
	return s
}

// techniqueBases are payloads that MUST be blocked at baseline; the test then
// verifies each evasion technique does not defeat detection.
func techniqueBases() []fuzzAttack {
	return []fuzzAttack{
		{"sqli", "UNION SELECT pass FROM users"},
		{"sqli", "1 OR 1=1"},
		{"rce", "; ping evil.com"},
		{"xss", "<svg onload=alert(1)>"},
		{"traversal", "/etc/passwd"},
	}
}

// evasionArtifacts are transform/placement combinations that look like a
// bypass in the harness but are NOT real — the backend would not execute them
// either, so blocking is neither possible nor desirable:
//
//   - "ws->plus body": in a raw text/plain body "+" is a literal plus, not
//     whitespace; it only means "space" in an x-www-form-urlencoded body, and
//     that path is decoded into args by ProcessRequestBody (and IS caught).
//   - "rce ws->comment arg": "/**/" is a SQL comment, not a shell token
//     separator — ";/**/ping" is not a valid shell command-injection.
var evasionArtifacts = map[string]bool{
	"sqli|ws->plus|body":  true,
	"rce|ws->plus|body":   true,
	"rce|ws->comment|arg": true,
}

// collectTechniqueEvasions returns every (base, transform, placement) where a
// placement that blocked the baseline payload fails to block the transformed
// one, excluding documented artifacts.
func collectTechniqueEvasions(t *testing.T, eng *Engine) []string {
	t.Helper()
	var misses []string
	check := func(base fuzzAttack, transforms []transform, kind string) {
		baseArg := blockedRawArg(eng, base.payload)
		baseBody := blockedInRawBody(eng, base.payload)
		if !baseArg && !baseBody {
			misses = append(misses, fmt.Sprintf("BASELINE-FAIL [%s] %q", base.class, base.payload))
			return
		}
		for _, tr := range transforms {
			if tr.name == "baseline" {
				continue
			}
			p := tr.fn(base.payload)
			if p == base.payload {
				continue
			}
			if baseArg && !blockedRawArg(eng, p) && !evasionArtifacts[base.class+"|"+tr.name+"|arg"] {
				misses = append(misses, fmt.Sprintf("[%-9s %-14s %s arg ] %q", base.class, tr.name, kind, p))
			}
			if baseBody && !blockedInRawBody(eng, p) && !evasionArtifacts[base.class+"|"+tr.name+"|body"] {
				misses = append(misses, fmt.Sprintf("[%-9s %-14s %s body] %q", base.class, tr.name, kind, p))
			}
		}
	}
	for _, b := range techniqueBases() {
		check(b, techniqueTransforms(), "ws")
		check(b, keywordSplits(), "kw")
	}
	return misses
}

// TestNoTechniqueEvasions is the regression guard: no evasion technique may
// defeat a rule in a placement that blocked the un-obfuscated payload.
func TestNoTechniqueEvasions(t *testing.T) {
	eng := newFuzzEngine(t)
	if misses := collectTechniqueEvasions(t, eng); len(misses) > 0 {
		for _, m := range misses {
			t.Errorf("technique evasion: %s", m)
		}
	}
}

// TestTechniqueEvasionReport is exploratory: it logs evasions (incl. the
// documented artifacts) so new ones surface during development. Never fails.
func TestTechniqueEvasionReport(t *testing.T) {
	eng := newFuzzEngine(t)
	misses := collectTechniqueEvasions(t, eng)
	if len(misses) == 0 {
		t.Logf("no technique evasions beyond documented artifacts")
		return
	}
	t.Logf("=== %d technique evasions ===", len(misses))
	for _, m := range misses {
		t.Logf("%s", m)
	}
}

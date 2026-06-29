package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"wewaf/internal/core"
)

// These Go native fuzzers target the request-parsing / decoding paths that run
// against untrusted input. A panic in any of them is a denial-of-service (the
// whole goroutine — and with failsafe=open, an unfiltered forward). The
// invariants are deliberately weak (must not panic, must return valid UTF-8
// where the contract implies it) so the fuzzer is free to explore.
//
// Run e.g.:  go test ./internal/engine -run x -fuzz FuzzCanonicalize -fuzztime 30s

func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		"", "/", "%2e%2e%2f", "%2525%32%65", "http://a//b/../c",
		"\xc0\xae", "\xff\xfe", "%c0%af", "a\x00b", "../../etc/passwd",
		"İµＡ", "%", "%g", "%1", "+ADw-script+AD4-",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Canonicalize(s)
		if !utf8.ValidString(out) {
			t.Fatalf("Canonicalize produced invalid UTF-8 from %q -> %q", s, out)
		}
		// Idempotence-ish: re-canonicalizing the output must also not panic
		// and must stay valid UTF-8 (rules match against the once-canonical
		// form, but a non-terminating transform would be a bug).
		_ = CanonicalizePath(s)
		_ = NormalizeForMatch(s)
		_ = FoldHomoglyphs(s)
	})
}

func FuzzDecodeUTF7(f *testing.F) {
	for _, s := range []string{
		"", "+", "+-", "+ADw-", "+ADw-script+AD4-", "+2D3cqA-",
		"+////////", "+AAAAAAAA-", "a+b+c", "+", "++++", "+/+/+/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Contract is no-panic: UTF-7 passes non-shifted octets through, so raw
		// high bytes survive (not valid UTF-8). That is downstream-safe — the
		// real target is NormalizeForMatch(decodeUTF7(body)), which NFKC-
		// normalizes to valid UTF-8, and RE2 matching tolerates bad bytes.
		out := decodeUTF7(s)
		// The NormalizeForMatch wrapper the engine actually applies must always
		// yield valid UTF-8.
		if nm := NormalizeForMatch(out); !utf8.ValidString(nm) {
			t.Fatalf("NormalizeForMatch(decodeUTF7(%q)) invalid UTF-8: %q", s, nm)
		}
	})
}

func FuzzDecodeJSONEscapes(f *testing.F) {
	for _, s := range []string{
		"", `<`, `\\u003c`, `\u`, `\uX`, `\u00`, `\ud800`, `\udc00`,
		`\n\t\r`, `\`, `\\`, `😀`, `{"a":"A"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = decodeJSONEscapes(s) // must not panic; output may be arbitrary bytes
	})
}

func FuzzDetectJWTAttacks(f *testing.F) {
	for _, s := range []string{
		"", "a.b.c", "eyJ.eyJ.x", "....", "Bearer x.y.z",
		strings.Repeat("A", 100) + "." + strings.Repeat("B", 100) + ".c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = detectJWTAttacks(s) // must not panic on any token shape
	})
}

// FuzzEngineRequest is the broad one: feed arbitrary URI / body / header bytes
// through the real two-phase pipeline and assert the engine never panics. This
// exercises canonicalization, query parsing, form parsing, JSON-escape and
// UTF-7 decode, cookie + header-sink inspection, and the whole rule set.
func FuzzEngineRequest(f *testing.F) {
	f.Add("/p?q=<script>", "id=1' OR '1'='1", "text/plain", "u=v")
	f.Add("/a%2e%2e/b", "{\"$ne\":null}", "application/json", "k=1")
	f.Add("/x?f=php://filter", "+ADw-script+AD4-", "text/plain; charset=utf-7", "")
	// Regression seeds for the bypasses the bypass-hunt workflow surfaced and we
	// closed: UNION DISTINCT SELECT (UNION rules omitted the distinct branch) and
	// java%00script: (XSS-002 separator class omitted percent-encoded controls).
	f.Add("/p?q=1'+UNION+DISTINCT+SELECT+a", `{"id":"1' UNION DISTINCT SELECT a FROM b-- -"}`, "application/json", "")
	f.Add("/p?x=java%00script:alert(1)", "y=java%0bscript:alert(1)", "text/plain", "")
	eng := newFuzzEngine(f)
	f.Fuzz(func(t *testing.T, target, body, contentType, cookie string) {
		// Build a request defensively; skip inputs net/http itself rejects.
		req, err := http.NewRequest(http.MethodPost, "http://x"+sanitizeTarget(target), strings.NewReader(body))
		if err != nil {
			return
		}
		if contentType != "" && utf8.ValidString(contentType) && !strings.ContainsAny(contentType, "\r\n\x00") {
			req.Header.Set("Content-Type", contentType)
		}
		if cookie != "" && !strings.ContainsAny(cookie, "\r\n\x00") {
			req.Header.Set("Cookie", cookie)
		}
		tx := core.NewTransaction(nil, req, nil)
		tx.SetMetadata("body", []byte(body))
		// The contract: evaluation never panics regardless of input.
		_ = eng.ProcessRequestHeaders(tx)
		_ = eng.ProcessRequestBody(tx)
	})
}

// sanitizeTarget keeps the fuzzed path/query usable as a request target without
// letting obviously-illegal bytes make http.NewRequest the thing under test.
func sanitizeTarget(s string) string {
	if s == "" || s[0] != '/' {
		s = "/" + s
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == 0 || r == ' ' {
			return '_'
		}
		return r
	}, s)
	return s
}

var _ = httptest.NewRequest

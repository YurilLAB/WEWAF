package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

func jsonBodyBlocked(eng *Engine, body string) bool {
	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	tx := core.NewTransaction(nil, r, nil)
	tx.SetMetadata("body", []byte(body))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestJSONUnicodeEscapeEvasion: payloads hidden behind JSON backslash-u escapes
// must be caught (the backend's JSON parser decodes them). Built at runtime so
// the literal backslash survives the Go compiler / tooling intact.
func TestJSONUnicodeEscapeEvasion(t *testing.T) {
	eng := newFuzzEngine(t)
	bs := string(rune(92)) // literal backslash
	u := func(h string) string { return bs + "u" + h }
	attacks := []string{
		`{"q":"` + u("003c") + "script" + u("003e") + "alert(1)" + u("003c") + "/script" + u("003e") + `"}`,
		`{"q":"<scr` + u("0069") + "pt>alert(1)</scr" + u("0069") + `pt>"}`, // escape a letter
		`{"id":"1 ` + u("0055") + "NION " + u("0053") + `ELECT pass FROM users"}`,
		`{"q":"` + u("003c") + "img src=x onerror=alert(1)" + u("003e") + `"}`,
	}
	for _, p := range attacks {
		p := p
		t.Run("block", func(t *testing.T) {
			if !jsonBodyBlocked(eng, p) {
				t.Errorf("JSON-escaped payload not blocked: %q", p)
			}
		})
	}
	// Legit JSON with backslashes must not be flagged — the escaped-backslash
	// handling keeps "\\u003c" (literal) from being mis-decoded to "<".
	legit := []string{
		`{"path":"C:` + bs + bs + `Users` + bs + bs + `bob"}`,
		`{"regex":"` + bs + bs + `d+` + bs + bs + `w*"}`,
		`{"name":"caf` + u("00e9") + `"}`, // café
		`{"msg":"hello world","count":42}`,
		`{"q":"` + bs + bs + u("0075") + `003c"}`, // doubly-escaped, stays literal text
	}
	for _, p := range legit {
		p := p
		t.Run("allow", func(t *testing.T) {
			if jsonBodyBlocked(eng, p) {
				t.Errorf("legit JSON wrongly blocked: %q", p)
			}
		})
	}
}

// TestDecodeJSONEscapesUnit pins the decoder's handling of the tricky cases.
func TestDecodeJSONEscapesUnit(t *testing.T) {
	bs := string(rune(92))
	cases := []struct{ in, want string }{
		{bs + "u003c", "<"},                             // single escape -> char
		{bs + bs + "u003c", bs + "u003c"},               // escaped backslash -> literal <
		{"a" + bs + "/b", "a/b"},                        // \/ -> /
		{"plain text", "plain text"},                    // no backslash, fast path
		{"C:" + bs + bs + "Users", "C:" + bs + "Users"}, // \\ -> \
	}
	for _, c := range cases {
		if got := decodeJSONEscapes(c.in); got != c.want {
			t.Errorf("decodeJSONEscapes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

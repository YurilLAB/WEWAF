package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// utf7Body posts a raw body with the given Content-Type and reports whether
// either request phase blocks it.
func utf7Body(eng *Engine, body, contentType string) bool {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(body))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestUTF7DecodeUnit checks the modified-UTF-7 decoder against the canonical
// XSS smuggle vectors plus the "+-" literal-plus and surrogate-pair cases.
func TestUTF7DecodeUnit(t *testing.T) {
	cases := map[string]string{
		"+ADw-script+AD4-": "<script>",
		"+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-": "<img src=x onerror=alert(1)>",
		"plain text": "plain text",
		"a+-b":       "a+b",        // "+-" => literal '+'
		"+AGE-+AGI-": "ab",         // two shifted runs
		"price +- 5": "price + 5",  // literal plus, no run
		"+2D3cqA-":   "\U0001f4a8", // surrogate pair (💨)
	}
	for in, want := range cases {
		if got := decodeUTF7(in); got != want {
			t.Errorf("decodeUTF7(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUTF7EvasionBlocked is the regression for the round-8 finding: payloads
// that are inert ASCII to every signature rule but decode to live markup /
// SQL when the backend honors charset=utf-7.
func TestUTF7EvasionBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"+ADw-script+AD4-alert(1)+ADw-/script+AD4-",     // <script>alert(1)</script>
		"+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-",  // <img src=x onerror=alert(1)>
		"+ADw-svg/onload+AD0-alert(1)+AD4-",             // <svg/onload=alert(1)>
		"1+ACc- UNION SELECT password FROM users+AC0--", // 1' UNION SELECT ... --
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !utf7Body(eng, p, "text/plain; charset=utf-7") {
				t.Errorf("UTF-7 evasion not blocked (decoded=%q)", decodeUTF7(p))
			}
		})
	}
}

// TestUTF7GatedOnCharset confirms the decode pass is reached ONLY when the
// request declares charset=utf-7. Without the declaration the same bytes are
// left untouched (no extra target, no behavior change for normal traffic).
func TestUTF7GatedOnCharset(t *testing.T) {
	eng := newFuzzEngine(t)
	payload := "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"
	if utf7Body(eng, payload, "text/plain") {
		t.Errorf("UTF-7 decode fired without a charset=utf-7 declaration")
	}
	if utf7Body(eng, payload, "application/json") {
		t.Errorf("UTF-7 decode fired for application/json")
	}
}

// TestUTF7NoFalsePositive confirms benign bodies that legitimately declare
// charset=utf-7 (and even contain '+'/'-' runs) are not blocked.
func TestUTF7NoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"hello world",         // plain text, no shift
		"+AGE-+AGI-+AGM-",     // decodes to "abc"
		"cost +- tax is fine", // literal plus
		"meeting notes for Q3",
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if utf7Body(eng, p, "text/plain; charset=utf-7") {
				t.Errorf("benign UTF-7 body wrongly blocked (decoded=%q)", decodeUTF7(p))
			}
		})
	}
}

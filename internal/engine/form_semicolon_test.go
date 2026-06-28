package engine

import "testing"

// TestFormSemicolonDoesNotBypassArgsInspection is the regression for
// WS-FORM-SEMICOLON-001: a single ';' anywhere in an
// application/x-www-form-urlencoded body made Go's url.ParseQuery return an
// error (Go 1.17+ "invalid semicolon separator in query") and an unusable map,
// so the form-decode block was skipped entirely. The percent-encoded payload
// then lived only in the raw "body" target where no signature matches — a clean
// bypass of every args/body rule (XSS/SQLi/RCE/…) on the most common attack
// content type. The engine must decode form fields the way a real backend does
// (split on '&' only, ';' is a literal byte) and keep inspecting them.
func TestFormSemicolonDoesNotBypassArgsInspection(t *testing.T) {
	eng := probeEngine(t)

	// %3Cscript%3Ealert(1)%3C%2Fscript%3E == <script>alert(1)</script>
	const enc = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	cases := []struct {
		name string
		body string
	}{
		{"control-no-semicolon", "comment=" + enc},
		{"semicolon-trailing", "comment=" + enc + ";x=1"},
		{"semicolon-leading-field", "x=1;comment=" + enc},
		{"semicolon-both-sides", "a=1;comment=" + enc + ";b=2"},
		{"semicolon-only-separator", "comment=" + enc + ";junk"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !fireBlocked(eng, probe{payload: c.body, target: "body"}) {
				t.Errorf("form body %q bypassed args/body inspection (expected XSS block)", c.body)
			}
		})
	}

	// A benign form body with a semicolon must still pass (no false positive
	// introduced by the tolerant parser).
	if fireBlocked(eng, probe{payload: "name=alice;city=paris&age=30", target: "body"}) {
		t.Errorf("benign semicolon form body was falsely blocked")
	}
}

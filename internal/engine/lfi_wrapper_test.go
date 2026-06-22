package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

func targetBlocked(eng *Engine, requestTarget string) bool {
	req := httptest.NewRequest(http.MethodGet, requestTarget, nil)
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(""))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestPHPWrapperQueryBlocked is the round-12 regression: PHP / stream wrappers
// in the QUERY STRING. LFI-011, TRAV-003 and CRS-933140 all cover the wrappers
// but run in the body phase, so they only saw form-parsed POST args — a
// GET ?file=php://filter/... or ?file=expect://id slipped straight through
// (only file:// was caught, incidentally, by the header-phase SSRF-011).
// LFI-013 mirrors the coverage in the header phase.
func TestPHPWrapperQueryBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		"/download?file=php://filter/convert.base64-encode/resource=index.php",
		"/download?file=php://input",
		"/download?file=expect://id",
		"/download?file=zip://shell.jpg%23payload.php",
		"/download?file=phar://evil.phar/x",
		"/download?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCk7Pz4=",
		"/download?file=glob://*.php",
		"/download?file=ssh2://evil/x",
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !targetBlocked(eng, p) {
				t.Errorf("PHP wrapper in query not blocked: %q", p)
			}
		})
	}
}

// TestDataURINoFalsePositive guards the CRS / cmdInjection fix: a base64 data
// URI is "data:<mime>;base64,..." and the ";base64," fragment previously
// matched the shell-command-injection rule (base64 is a Unix command). Apps
// that accept inline images / files as data URIs in query args or bodies must
// not be blocked. The wrapper rule (LFI-013) also must not fire on the
// single-colon "data:" form — only on the "data://" wrapper.
func TestDataURINoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"/u?img=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ3aGNAAAAAElFTkSuQmCC",
		"/u?f=data:application/pdf;base64,JVBERi0xLjQK",
		"/u?a=data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
		"/u?c=data:text/css;base64,Ym9keXt9",
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if targetBlocked(eng, p) {
				t.Errorf("legit data URI wrongly blocked: %q", p)
			}
		})
	}
}

// TestCmdInjectionStillBlockedAfterCommaFix confirms the comma carve-out did
// not weaken shell-command-injection detection — including base64 used as a
// real command (followed by a flag or pipe rather than a comma).
func TestCmdInjectionStillBlockedAfterCommaFix(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		";id",
		"; cat /etc/passwd",
		"&&whoami",
		"|nslookup evil.com",
		";ping -c 1 evil.com",
		";base64 -d /etc/shadow",
		";base64|sh",
		"`whoami`",
		";rm -rf /tmp/x",
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !rceBodyBlocked(eng, p) {
				t.Errorf("command injection not blocked: %q", p)
			}
		})
	}
}

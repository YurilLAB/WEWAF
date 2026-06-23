package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

// This is a RED-TEAM probe harness: it fires candidate attack payloads through
// the real engine (header + body phases, default rules + CRS, active mode) and
// reports which ones PASS unblocked. A payload tagged expectBlock=true that
// passes is a candidate bypass to verify by hand. It is intentionally a probe
// (logs, never asserts) so the full result set is visible in one run.

func probeEngine(t testing.TB) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = "active"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	raw := rules.DefaultRules()
	raw = append(raw, rules.CRSRules()...)
	rs, err := rules.NewRuleSet(raw)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	eng, err := NewEngine(cfg, rs, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

type probe struct {
	id          string
	class       string
	payload     string
	target      string // arg|argname|body|header|cookie|path|rawuri
	expectBlock bool
	note        string
}

// fireBlocked runs the payload through both request phases and reports whether
// the engine interrupted (blocked) in EITHER phase.
func fireBlocked(eng *Engine, p probe) bool {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	var bodyBytes []byte
	switch p.target {
	case "arg":
		req.URL.RawQuery = "x=" + p.payload
	case "argname":
		req.URL.RawQuery = p.payload + "=1"
	case "header":
		req.Header.Set("X-Probe", p.payload)
	case "cookie":
		req.Header.Set("Cookie", "sid="+p.payload)
	case "path", "rawuri":
		// Build the request with the payload AS the request target so url.Parse
		// populates URL.Path/RawPath/RawQuery exactly as a real request would —
		// the engine inspects r.URL.RequestURI(), which is reconstructed from
		// those fields, NOT from req.RequestURI. A target that won't parse is
		// reported as "blocked" (the proxy would reject it before the engine).
		ok := func() (parsed bool) {
			defer func() {
				if recover() != nil {
					parsed = false
				}
			}()
			req = httptest.NewRequest(http.MethodGet, p.payload, nil)
			return true
		}()
		if !ok {
			return true
		}
	case "body":
		req = httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(p.payload))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		bodyBytes = []byte(p.payload)
	default:
		req.URL.RawQuery = "x=" + p.payload
	}

	tx := core.NewTransaction(nil, req, nil)
	if bodyBytes != nil {
		tx.SetMetadata("body", bodyBytes)
	}
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	if eng.ProcessRequestBody(tx) != nil {
		return true
	}
	return false
}

// TestBypassProbe_Harness validates the harness on known cases BEFORE we trust
// the bypass results: classic attacks must block, benign input must pass.
func TestBypassProbe_Harness(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := []probe{
		{id: "xss-basic", payload: "<script>alert(1)</script>", target: "arg"},
		{id: "xss-body", payload: "q=<script>alert(1)</script>", target: "body"},
		{id: "sqli-basic", payload: "1' OR '1'='1", target: "arg"},
		{id: "sqli-union", payload: "1 UNION SELECT username,password FROM users", target: "arg"},
		{id: "lfi-basic", payload: "../../../../etc/passwd", target: "arg"},
		{id: "rce-basic", payload: ";cat /etc/passwd", target: "arg"},
	}
	for _, p := range mustBlock {
		if !fireBlocked(eng, p) {
			t.Errorf("HARNESS SANITY: %q (%s) should block but PASSED — harness or coverage problem", p.id, p.payload)
		}
	}
	benign := []probe{
		{id: "benign-1", payload: "hello world", target: "arg"},
		{id: "benign-2", payload: "user@example.com", target: "arg"},
		{id: "benign-3", payload: "/products/category/shoes", target: "path"},
	}
	for _, p := range benign {
		if fireBlocked(eng, p) {
			t.Errorf("HARNESS SANITY: benign %q (%s) should pass but was BLOCKED (false positive)", p.id, p.payload)
		}
	}
}

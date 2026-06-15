// Package integration contains black-box tests that exercise the full WAF
// HTTP surface (engine + proxy + metrics) through the real net/http stack.
// Unit tests live next to the packages they test — Go's compiler requires
// `_test.go` files to live in the same directory as the package under test
// — but these tests stay independent of any internal symbols so they go in
// their own folder.
//
// Run with: `go test ./tests/integration/...`
package integration_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/proxy"
	"wewaf/internal/rules"
	"wewaf/internal/telemetry"
)

func rawDial(addr, req string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func readStatusLine(t *testing.T, r io.Reader) string {
	t.Helper()
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatalf("read status: %v", err)
	}
	return strings.TrimSpace(line)
}

// newTestProxy wires the real proxy against an httptest backend so tests can
// observe block / allow / counter behaviour end-to-end. The returned stop
// function tears the whole stack down.
func newTestProxy(t *testing.T) (frontend, backend *httptest.Server, metrics *telemetry.Metrics, bans *core.BanList, stop func()) {
	t.Helper()

	// Backend: echoes method + path so we can verify allowed requests reach it.
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "backend-ok %s %s", r.Method, r.URL.Path)
	}))

	cfg := config.Default()
	cfg.BackendURL = backend.URL
	cfg.ListenAddr = ":0"
	cfg.AdminAddr = ":0"
	cfg.Mode = "active"
	cfg.ShaperEnabled = false
	cfg.DDoSWarmupSeconds = 1
	cfg.PerRuleCounters = true
	cfg.DecompressInspect = true
	cfg.BanBackoffEnabled = true
	cfg.BanBackoffMultiplier = 2
	cfg.BanBackoffWindowSec = 60
	cfg.MaxBanDurationSec = 3600
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	rawRules := rules.DefaultRules()
	if cfg.CRSEnabled {
		rawRules = append(rawRules, rules.CRSRules()...)
	}
	rs, err := rules.NewRuleSet(rawRules)
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}

	eng, err := engine.NewEngine(cfg, rs, &testLogger{t})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	metrics = telemetry.NewMetrics()
	bf := bruteforce.NewDetector(time.Minute)
	bans = core.NewBanList()
	bans.ConfigureBackoff(cfg.BanBackoffEnabled, cfg.BanBackoffMultiplier,
		time.Duration(cfg.BanBackoffWindowSec)*time.Second,
		time.Duration(cfg.MaxBanDurationSec)*time.Second)

	wp, err := proxy.NewWAFProxy(cfg, eng, metrics, bf)
	if err != nil {
		t.Fatalf("NewWAFProxy: %v", err)
	}
	wp.AttachBanList(bans)

	frontend = httptest.NewServer(wp)

	stop = func() {
		frontend.Close()
		backend.Close()
		bf.Stop()
	}
	return
}

// testLogger keeps engine output out of `go test` unless -v.
type testLogger struct{ t *testing.T }

func (l *testLogger) Debugf(f string, a ...interface{}) { l.t.Logf("[DEBUG] "+f, a...) }
func (l *testLogger) Infof(f string, a ...interface{})  { l.t.Logf("[INFO] "+f, a...) }
func (l *testLogger) Warnf(f string, a ...interface{})  { l.t.Logf("[WARN] "+f, a...) }
func (l *testLogger) Errorf(f string, a ...interface{}) { l.t.Logf("[ERROR] "+f, a...) }

func TestAllowsNormalTraffic(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	resp, err := http.Get(frontend.URL + "/hello")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for /hello, got %d: %s", resp.StatusCode, b)
	}
}

// TestAllowsLegitimateClients confirms the body-phase header inspection (the
// fix that catches query-string / header injection) does not false-positive on
// ordinary traffic. A standard browser Accept header contains "*/*", and API
// clients send "Accept: */*" — both must pass. This is the end-to-end guard
// for the XPATH-001 "*/*" false positive a live attack exercise surfaced
// (before the fix it blocked essentially every browser and API request).
func TestAllowsLegitimateClients(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	cases := []struct {
		name, path, ua, accept, acceptLang string
	}{
		{"browser", "/products?id=42",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
			"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-US,en;q=0.9"},
		{"api_star_accept", "/api/health", "MyApp/1.0", "*/*", "en-US"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, frontend.URL+c.path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("User-Agent", c.ua)
			req.Header.Set("Accept", c.accept)
			req.Header.Set("Accept-Language", c.acceptLang)
			// Common header values that body-phase rules used to false-positive
			// on (${} in a cookie, 0x hex ETag/token, Referer with a build id).
			// These must NOT cause a block.
			req.Header.Set("Cookie", "session=abc123; tmpl=${USER}; tok=0xDEADBEEF1234")
			req.Header.Set("If-None-Match", `"0x1a2b3c4d5e"`)
			req.Header.Set("Referer", "https://shop.example.com/build/0xdeadbeef99")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("legitimate %s request must be 200, got %d: %s", c.name, resp.StatusCode, b)
			}
		})
	}
}

func TestBlocksPathTraversal(t *testing.T) {
	frontend, _, metrics, _, stop := newTestProxy(t)
	defer stop()

	resp, err := http.Get(frontend.URL + "/../../etc/passwd")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("path traversal should not return 200")
	}
	if metrics.BlockedRequests == 0 {
		t.Fatalf("BlockedRequests counter not incremented")
	}
}

func TestBlocksSQLi(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	u := frontend.URL + "/?id=1%20UNION%20SELECT%20*%20FROM%20users"
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SQLi should return 403, got %d", resp.StatusCode)
	}
}

func TestBlocksJavaScriptProtocol(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	resp, err := http.Get(frontend.URL + "/?url=" + url.QueryEscape("javascript:alert(1)"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("javascript: protocol should return 403, got %d", resp.StatusCode)
	}
}

// TestBlocksQueryStringInjection guards the request-target coverage gap that
// let reflected payloads through the query string. The XSS / SSTI / NoSQL
// signatures are registered at the request-body phase but also declare
// "args" as a target, so a payload in the query string MUST be inspected.
// Before the fix, args.* was only populated in the request-header phase
// while these rules ran in the body phase, so GET /x?q=<script>... reached
// the backend unfiltered. UNION-SELECT and javascript: were already caught
// because duplicate header-phase rules exist for them — these cases cover
// the classes that had no header-phase twin.
func TestBlocksQueryStringInjection(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	cases := []struct {
		name string
		path string
	}{
		{"script_tag", "/search?q=" + url.QueryEscape("<script>alert(1)</script>")},
		{"img_onerror", "/p?x=" + url.QueryEscape("<img src=x onerror=alert(1)>")},
		{"svg_onload", "/p?x=" + url.QueryEscape("<svg onload=alert(1)>")},
		{"ssti_jinja", "/p?name=" + url.QueryEscape("{{7*7}}")},
		{"nosql_where", "/p?f=" + url.QueryEscape(`{"$where":"sleep(1000)"}`)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Get(frontend.URL + c.path)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("query-string %s payload should be blocked (403); got %d: %s",
					c.name, resp.StatusCode, body)
			}
		})
	}
}

// TestBlocksHeaderInjection covers the same gap for payloads delivered in a
// request header value (Referer here) — also a body-phase rule target that
// the live body phase never populated.
// TestBlocksEncodingEvasion covers the canonicalization-depth fixes: IIS/.NET
// %uXXXX decoding, percent-encoded CRLF injection, and overlong-UTF-8 path
// traversal. Before the fix the canonicalizer either didn't understand %u, or
// decoded-and-stripped the %0d%0a / %c0%af bytes before the encoding-detection
// rules (which match the raw form via the new uri_raw target) could see them.
func TestBlocksEncodingEvasion(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	cases := []struct{ name, path string }{
		// %u002e%u002e%u002f -> "../" : IIS/.NET %u traversal, caught after
		// the new decodePercentU pass feeds the uri target.
		{"iis_percent_u_traversal", "/dl?file=%u002e%u002e%u002fetc/passwd"},
		// Overlong-UTF-8 "../" — TRAV-002 / CRS now match it on uri_raw.
		{"overlong_utf8_traversal", "/dl?file=%c0%ae%c0%ae%c0%afetc/passwd"},
		// Percent-encoded CRLF response splitting — CRLF-001 / CRS-921120 on
		// uri_raw catch the raw %0d%0a + header keyword.
		{"crlf_response_split", "/redir?u=%0d%0aSet-Cookie:%20sessid=hijack"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Get(frontend.URL + c.path)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s should be blocked (403), got %d: %s", c.name, resp.StatusCode, b)
			}
		})
	}
}

// TestBlocksMalformedEscapeEvasion guards the lenient-decode fix the
// canonicalizer fuzzer surfaced. A single malformed percent-escape (%zz)
// before a real payload used to defeat inspection two ways: url.QueryUnescape
// decoded NOTHING on the bad escape, and r.URL.Query() DROPPED the whole arg —
// so the WAF never saw the payload while a per-character-decoding backend still
// decoded it. The canonicalizer now decodes valid escapes leniently and the
// query is parsed from the raw string.
func TestBlocksMalformedEscapeEvasion(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	cases := []struct{ name, path string }{
		{"xss_behind_bad_escape", "/s?q=%zz%3cscript%3ealert(1)%3c/script%3e"},
		{"sqli_behind_bad_escape", "/p?id=%gg1%20UNION%20SELECT%20pw%20FROM%20users"},
		{"traversal_behind_bad_escape", "/dl?file=%zz..%2f..%2f..%2fetc/passwd"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Get(frontend.URL + c.path)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s should be blocked (403); got %d: %s", c.name, resp.StatusCode, b)
			}
		})
	}
}

func TestBlocksHeaderInjection(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Referer", "<script>alert(document.cookie)</script>")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("header-injected script tag should be blocked (403); got %d", resp.StatusCode)
	}
}

func TestBlocksObfuscatedTransferEncodingRaw(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	// Go's http.Client sanitises Transfer-Encoding headers before sending,
	// so this case requires raw TCP to reach the WAF intact. We write a
	// minimally-valid HTTP/1.1 request with the duplicated chunked token
	// that SMUG-010 flags as smuggling.
	addr := strings.TrimPrefix(frontend.URL, "http://")
	raw := "POST / HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Transfer-Encoding: chunked, chunked\r\n" +
		"Content-Length: 3\r\n" +
		"Connection: close\r\n\r\n" +
		"x=1"

	conn, err := rawDial(addr, raw)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	status := readStatusLine(t, conn)
	if strings.Contains(status, "200") {
		t.Fatalf("obfuscated TE should not return 200; got %q", status)
	}
}

func TestPerRuleCountersPopulate(t *testing.T) {
	frontend, _, metrics, _, stop := newTestProxy(t)
	defer stop()

	// Fire three distinct malicious requests.
	urls := []string{
		frontend.URL + "/../../etc/passwd",
		frontend.URL + "/?id=1%20UNION%20SELECT",
		frontend.URL + "/?u=" + url.QueryEscape("javascript:alert(1)"),
	}
	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatalf("request %s: %v", u, err)
		}
		resp.Body.Close()
	}

	counters := metrics.RuleCountersSnapshot()
	if len(counters) == 0 {
		t.Fatalf("expected per-rule counters to populate, got empty map")
	}
}

func TestPrometheusExposition(t *testing.T) {
	frontend, _, metrics, _, stop := newTestProxy(t)
	defer stop()

	// Generate a block so the counter is non-zero.
	resp, err := http.Get(frontend.URL + "/../../etc/passwd")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	var buf bytes.Buffer
	if err := metrics.WritePrometheus(&buf); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	out := buf.String()
	required := []string{
		"# TYPE wewaf_requests_total counter",
		"# TYPE wewaf_blocked_total counter",
		"wewaf_requests_total ",
		"wewaf_blocked_total ",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Fatalf("Prometheus output missing %q; got:\n%s", want, out)
		}
	}
}

// TestBannedIPIsBlocked asserts that an IP placed in the shared ban list is
// actually rejected on the ingress path (403) before reaching the backend.
// Before ban enforcement was wired into WAFProxy.ServeHTTP, bans were purely
// decorative — listed in /api/bans and synced to peers but never blocking a
// single request. The httptest client connects from loopback, so we ban
// 127.0.0.1 and confirm the next request is forbidden, then unban and confirm
// it is allowed again.
func TestBannedIPIsBlocked(t *testing.T) {
	frontend, _, metrics, bans, stop := newTestProxy(t)
	defer stop()

	// Sanity: an un-banned request reaches the backend.
	resp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("pre-ban request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 before ban, got %d", resp.StatusCode)
	}

	bans.Ban("127.0.0.1", "integration test ban", time.Hour)

	resp, err = http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("post-ban request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("banned IP must be blocked with 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatalf("ban block should set Retry-After")
	}
	if metrics.BlockedRequests == 0 {
		t.Fatalf("ban block should increment BlockedRequests")
	}

	bans.Unban("127.0.0.1")
	resp, err = http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("post-unban request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after unban, got %d", resp.StatusCode)
	}
}

// TestGzipBodyPayloadInspected asserts the request-body decompression result
// is actually inspected. A gzip-encoded body carrying a <script> payload must
// be blocked (403) — before the engine consumed the decoded_body metadata, the
// signatures only ever saw the compressed bytes (which never match) while the
// backend would decompress and process the attack. The plaintext control is
// already caught and proves the same payload is a real body-phase block.
func TestGzipBodyPayloadInspected(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	payload := "<script>alert(document.cookie)</script>"

	// Control: the same payload sent as a plaintext body must block.
	resp, err := http.Post(frontend.URL+"/submit", "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("plaintext post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("plaintext <script> body should block (403), got %d", resp.StatusCode)
	}

	// The real test: gzip the payload and declare Content-Encoding: gzip.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(payload)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/submit", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gzip post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("gzip-encoded <script> body should block (403); got %d: %s", resp.StatusCode, b)
	}
}

// TestBanCoversIPv6Prefix confirms a ban placed on one address in an IPv6 /64
// covers any other address in that prefix — so an attacker cannot evade the
// ban by rotating the low 64 bits. Exercised at the ban-list level since the
// loopback httptest client cannot present arbitrary IPv6 sources.
func TestBanCoversIPv6Prefix(t *testing.T) {
	bl := core.NewBanList()
	bl.Ban("2001:db8:abcd:1234::5", "scanner", time.Hour)
	if !bl.IsBanned("2001:db8:abcd:1234::5") {
		t.Fatalf("banned address itself must be banned")
	}
	if !bl.IsBanned("2001:db8:abcd:1234:dead:beef:cafe:f00d") {
		t.Fatalf("a different host in the same /64 must be covered by the ban")
	}
	if bl.IsBanned("2001:db8:abcd:9999::5") {
		t.Fatalf("a host in a DIFFERENT /64 must NOT be banned")
	}
	// IPv4 bans stay exact (/32).
	bl.Ban("203.0.113.7", "scanner", time.Hour)
	if !bl.IsBanned("203.0.113.7") {
		t.Fatalf("IPv4 ban must match exactly")
	}
	if bl.IsBanned("203.0.113.8") {
		t.Fatalf("IPv4 ban must not bleed to a neighbour")
	}
}

func TestExponentialBackoffBans(t *testing.T) {
	bl := core.NewBanList()
	bl.ConfigureBackoff(true, 2, time.Minute, time.Hour)

	bl.Ban("offender", "scan", 100*time.Millisecond)
	bl.Ban("offender", "scan", 100*time.Millisecond)
	bl.Ban("offender", "scan", 100*time.Millisecond)

	list := bl.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 active ban, got %d", len(list))
	}
	if list[0].Offenses != 3 {
		t.Fatalf("expected 3 offenses recorded, got %d", list[0].Offenses)
	}
	// Third ban should last ~400 ms (100 * 2^2), i.e. clearly past 350 ms.
	if d := time.Until(list[0].ExpiresAt); d < 350*time.Millisecond {
		t.Fatalf("expected third ban to extend beyond 350 ms, got %v", d)
	}
}

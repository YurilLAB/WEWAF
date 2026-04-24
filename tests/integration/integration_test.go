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

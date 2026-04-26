package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseLinePerIPSkipsCommentsAndJunk(t *testing.T) {
	body := []byte(`# header
1.2.3.0/24
# comment
8.8.8.8
notanip
::1
2001:db8::/32
1.2.3.4 ; SBL12345
127.0.0.1
0.0.0.0/0
192.168.1.1
`)
	out, err := ParseLinePerIP(body, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// `::1` is loopback, 127.0.0.1 is loopback, 0.0.0.0/0 covers the
	// whole Internet, 192.168.1.1 is RFC1918 — these MUST be rejected
	// to defend against compromised feeds. Only the four real-world
	// public ranges should remain.
	wants := []string{"1.2.3.0/24", "8.8.8.8/32", "2001:db8::/32", "1.2.3.4/32"}
	if len(out) != len(wants) {
		t.Fatalf("want %d entries, got %d (%+v)", len(wants), len(out), out)
	}
	for i, w := range wants {
		if out[i].Value != w {
			t.Errorf("entry %d: want %q got %q", i, w, out[i].Value)
		}
	}
}

func TestClassifyIPRejectsDangerousRanges(t *testing.T) {
	cases := []string{
		"0.0.0.0/0", "::/0",
		"127.0.0.1", "127.0.0.0/8",
		"::1",
		"10.0.0.0/8", "10.1.2.3",
		"192.168.0.0/16", "192.168.1.1",
		"169.254.169.254", // EC2 metadata
		"fe80::1",
	}
	for _, c := range cases {
		if _, ok := classifyIP(c); ok {
			t.Errorf("classifyIP(%q) accepted a dangerous range", c)
		}
	}
}

func TestParseLinePerIPRejectsEmptyResult(t *testing.T) {
	if _, err := ParseLinePerIP([]byte("# only comments\n# nothing useful\n"), "test"); err == nil {
		t.Fatal("expected 'no records' error")
	}
}

func TestParseSSLBLJA3HandlesBothColumnOrderings(t *testing.T) {
	body := []byte(`# SSLBL JA3 Fingerprints
6fa3244afc6bb6f9fad207b6b52af26b,curl 7.x default
"Go net/http","e7d705a3286e19ea42f587b344ee6865"
`)
	out, err := ParseSSLBLJA3(body, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if out[0].Value != "6fa3244afc6bb6f9fad207b6b52af26b" || out[1].Value != "e7d705a3286e19ea42f587b344ee6865" {
		t.Errorf("hashes wrong: %+v", out)
	}
}

func TestParseLinePerUAStripsRegexWrappers(t *testing.T) {
	body := []byte(`# bad bots
"~*BadBotName"
"~*AnotherBad";
EvilCrawler
`)
	out, err := ParseLinePerUA(body, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	values := make([]string, 0, len(out))
	for _, e := range out {
		values = append(values, e.Value)
	}
	wants := []string{"BadBotName", "AnotherBad", "EvilCrawler"}
	for i, w := range wants {
		if i >= len(values) || values[i] != w {
			t.Errorf("entry %d: want %q got %v", i, w, values)
		}
	}
}

func TestParseCISAKEVExtractsCVEs(t *testing.T) {
	body := []byte(`{
		"catalogVersion": "1.0",
		"vulnerabilities": [
			{"cveID":"CVE-2024-1234","vendorProject":"Example","product":"Foo","vulnerabilityName":"RCE","dateAdded":"2024-01-15","dueDate":"2024-02-05"},
			{"cveID":"CVE-2024-5678","vendorProject":"Other","product":"Bar","vulnerabilityName":"SQLi","dateAdded":"2024-01-16","dueDate":"2024-02-06"}
		]
	}`)
	out, err := ParseCISAKEV(body, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 CVEs, got %d", len(out))
	}
	if out[0].Value != "CVE-2024-1234" || out[1].Value != "CVE-2024-5678" {
		t.Errorf("cves wrong: %+v", out)
	}
	if !strings.Contains(out[0].Reason, "RCE") {
		t.Errorf("reason missing vuln name: %q", out[0].Reason)
	}
}

func TestManagerFetchesAndCallsSink(t *testing.T) {
	body := "1.2.3.4\n5.6.7.8\n"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", "v1")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	var sinkCalls atomic.Int32
	var lastEntries int
	m, err := NewManager(Config{
		CacheDir:    dir,
		HTTPTimeout: 2 * time.Second,
		MinBackoff:  time.Second,
	}, func(entries []Entry) error {
		sinkCalls.Add(1)
		lastEntries = len(entries)
		return nil
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.AddSource(Source{
		Name:         "test",
		URL:          srv.URL,
		Kind:         KindIPv4,
		Confidence:   ConfMedium,
		RefreshEvery: time.Minute,
		Parser:       ParseLinePerIP,
	}); err != nil {
		t.Fatalf("AddSource: %v", err)
	}

	// Drive a fetch directly rather than waiting for the supervisor — keeps the test fast and deterministic.
	if err := m.fetchOnce(context.Background(), m.sources[0]); err != nil {
		t.Fatalf("fetchOnce: %v", err)
	}
	if sinkCalls.Load() != 1 {
		t.Fatalf("expected sink called once, got %d", sinkCalls.Load())
	}
	if lastEntries != 2 {
		t.Fatalf("expected 2 entries, got %d", lastEntries)
	}

	// A second fetch should hit the server but observe identical content; sink still called.
	if err := m.fetchOnce(context.Background(), m.sources[0]); err != nil {
		t.Fatalf("fetchOnce 2: %v", err)
	}
	if sinkCalls.Load() != 2 {
		t.Fatalf("expected sink called twice, got %d", sinkCalls.Load())
	}

	// Cache file should now exist.
	matches, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(matches) == 0 {
		t.Fatal("cache file was not written")
	}
}

func TestManagerStaleCacheFallback(t *testing.T) {
	dir := t.TempDir()
	// Pre-populate the cache.
	if err := os.WriteFile(filepath.Join(dir, "test.cache"), []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	// Server that always 500s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var sinkCalls atomic.Int32
	m, err := NewManager(Config{
		CacheDir:    dir,
		HTTPTimeout: time.Second,
		MaxStaleAge: 24 * time.Hour,
	}, func(entries []Entry) error {
		sinkCalls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_ = m.AddSource(Source{
		Name:         "test",
		URL:          srv.URL,
		Kind:         KindIPv4,
		Confidence:   ConfMedium,
		RefreshEvery: time.Minute,
		Parser:       ParseLinePerIP,
	})
	// Should succeed via stale cache.
	if err := m.fetchOnce(context.Background(), m.sources[0]); err != nil {
		t.Fatalf("fetchOnce should fall back to cache: %v", err)
	}
	if sinkCalls.Load() != 1 {
		t.Fatalf("sink should run on cache fallback")
	}
}

func TestManagerDriftThresholdRefusesUpdate(t *testing.T) {
	dir := t.TempDir()
	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		if step == 1 {
			// First load: 1000 entries — public IP so the safety
			// filter doesn't drop them. Keeping each line distinct
			// would test cardinality, but the drift check counts
			// lines, not unique entries, so 1000 of the same line
			// is sufficient signal.
			for i := 0; i < 1000; i++ {
				_, _ = w.Write([]byte("203.0.113.1\n"))
			}
		} else {
			// Second load: 1 entry — would be a -99% drift.
			_, _ = w.Write([]byte("203.0.113.1\n"))
		}
	}))
	defer srv.Close()

	m, _ := NewManager(Config{
		CacheDir:    dir,
		HTTPTimeout: 2 * time.Second,
		RecordDelta: 0.5,
	}, func(entries []Entry) error { return nil })
	_ = m.AddSource(Source{
		Name: "test", URL: srv.URL, Parser: ParseLinePerIP, RefreshEvery: time.Minute,
	})

	if err := m.fetchOnce(context.Background(), m.sources[0]); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if err := m.fetchOnce(context.Background(), m.sources[0]); err == nil {
		t.Fatal("second fetch with extreme drift should be refused")
	}
}

func TestManagerStatsReflectFetches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()
	m, _ := NewManager(Config{CacheDir: t.TempDir()}, func(entries []Entry) error { return nil })
	_ = m.AddSource(Source{Name: "s", URL: srv.URL, Parser: ParseLinePerIP, RefreshEvery: time.Minute})
	_ = m.fetchOnce(context.Background(), m.sources[0])
	st := m.Stats()
	if st.TotalFetches != 1 || st.TotalEntries != 1 {
		t.Fatalf("stats not updating: %+v", st)
	}
	if len(st.Sources) != 1 || st.Sources[0].LastEntries != 1 {
		t.Fatalf("source stat missing: %+v", st.Sources)
	}
}

func TestSanitizeFilenameSafe(t *testing.T) {
	cases := map[string]string{
		"firehol-level1":     "firehol-level1",
		"sslbl/ja3":          "sslbl_ja3",
		"../etc/passwd":      "___etc_passwd",
		"":                   "_",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q want %q", in, got, want)
		}
	}
}

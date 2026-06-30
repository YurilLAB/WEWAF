package intel

import (
	"strings"
	"testing"
	"time"
)

// TestParserEntryCapRefusesOversizeFeed pins the per-feed entry cap: a feed body
// that would yield more than maxFeedEntries records is refused outright (the
// FP-safe direction) rather than parsed into a multi-hundred-MB slice and
// applied. This bounds the first-fetch case the ±50% drift guard cannot (it has
// no prior count to compare against).
func TestParserEntryCapRefusesOversizeFeed(t *testing.T) {
	// maxFeedEntries+1 identical valid public lines — the parser counts lines,
	// not distinct entries, so duplicates exercise the cap cheaply.
	body := strings.Repeat("11.1.1.1\n", maxFeedEntries+1)
	if _, err := ParseLinePerIP([]byte(body), "compromised"); err == nil {
		t.Fatal("a feed exceeding maxFeedEntries must be refused")
	}
	// A normal-sized feed is unaffected.
	if _, err := ParseLinePerIP([]byte("203.0.113.7\n8.8.8.8\n"), "ok"); err != nil {
		t.Fatalf("normal feed wrongly refused: %v", err)
	}
}

// TestAddSourceTransportHardening pins the feed-URL transport policy added for
// the compromised/MITM-feed threat model: non-http(s) schemes are refused, and
// an enforce-capable (medium/high) feed served over plaintext http is downgraded
// to score-only (ConfLow) so an on-path attacker can't rewrite its body into
// bans. https enforce-capable feeds and already-ConfLow http feeds are untouched.
func TestAddSourceTransportHardening(t *testing.T) {
	newMgr := func() *Manager {
		m, err := NewManager(Config{CacheDir: t.TempDir()}, func([]Entry) error { return nil })
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		return m
	}
	dummy := ParseLinePerIP

	// Bad schemes are rejected.
	for _, bad := range []string{"file:///etc/passwd", "gopher://x/", "ftp://h/f", "javascript:alert(1)", "://nohost"} {
		m := newMgr()
		if err := m.AddSource(Source{Name: "s", URL: bad, Parser: dummy}); err == nil {
			t.Errorf("AddSource accepted bad-scheme URL %q", bad)
		}
	}

	// A bad mirror scheme is rejected even when the primary is fine.
	if err := newMgr().AddSource(Source{Name: "s", URL: "https://ok.example/f", Mirror: "file:///x", Parser: dummy}); err == nil {
		t.Error("AddSource accepted a bad-scheme mirror")
	}

	cases := []struct {
		name string
		url  string
		conf Confidence
		want Confidence
	}{
		{"medium-http-downgraded", "http://feed.example/list", ConfMedium, ConfLow},
		{"high-http-downgraded", "http://feed.example/list", ConfHigh, ConfLow},
		{"medium-https-kept", "https://feed.example/list", ConfMedium, ConfMedium},
		{"high-https-kept", "https://feed.example/list", ConfHigh, ConfHigh},
		{"low-http-kept", "http://feed.example/list", ConfLow, ConfLow},
	}
	for _, c := range cases {
		m := newMgr()
		if err := m.AddSource(Source{Name: c.name, URL: c.url, Confidence: c.conf, RefreshEvery: time.Hour, Parser: dummy}); err != nil {
			t.Fatalf("%s: AddSource: %v", c.name, err)
		}
		if got := m.sources[0].Confidence; got != c.want {
			t.Errorf("%s: confidence = %d, want %d (plaintext enforce-capable must downgrade)", c.name, got, c.want)
		}
	}
}

package integration_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/proxy"
	"wewaf/internal/reputation"
	"wewaf/internal/rules"
	"wewaf/internal/session"
	"wewaf/internal/telemetry"
)

// TestReputationFrictionBlocksReturningOffender is the end-to-end proof that the
// reputation score feeds hot-path friction: a known-bad IP arriving with a fresh
// session (risk ~0) is pushed over the SessionBlockThreshold by its reputation
// bump and blocked, while a clean IP making the identical request is allowed.
func TestReputationFrictionBlocksReturningOffender(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "backend-ok")
	}))
	defer backend.Close()

	cfg := config.Default()
	cfg.BackendURL = backend.URL
	cfg.Mode = "active"
	cfg.TrustXFF = true
	cfg.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
	cfg.ShaperEnabled = false
	cfg.SessionTrackingEnabled = true
	cfg.SessionCookieSecret = "test-session-secret-32-bytes-long!!"
	cfg.SessionBlockThreshold = 30
	cfg.ReputationEnabled = true
	cfg.ReputationRiskBumpMax = 50
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	rs, err := rules.NewRuleSet(rules.DefaultRules())
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	eng, err := engine.NewEngine(cfg, rs, &testLogger{t})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	bf := bruteforce.NewDetector(time.Minute)
	defer bf.Stop()

	// Reputation engine with a KNOWN-BAD IP (score accrued from prior blocks).
	const badIP = "203.0.113.66"
	repEng, err := reputation.Open(reputation.Options{
		Path:   filepath.Join(t.TempDir(), "reputation.sqlite"),
		Config: reputation.Config{Enabled: true, HalfLife: time.Hour},
	})
	if err != nil {
		t.Fatalf("reputation open: %v", err)
	}
	repEng.Start(context.Background())
	defer repEng.Close()
	for i := 0; i < 6; i++ { // ~60 score, well above the +50 cap
		repEng.RecordBlock(badIP, "engine", "prior")
	}

	st := session.NewTracker(session.Config{
		Secret:  cfg.SessionCookieSecret,
		Enabled: true,
		IdleTTL: time.Hour,
	})
	defer st.Stop()

	wp, err := proxy.NewWAFProxy(cfg, eng, telemetry.NewMetrics(), bf)
	if err != nil {
		t.Fatalf("NewWAFProxy: %v", err)
	}
	wp.AttachBanList(core.NewBanList())
	wp.AttachSessionTracker(st)
	wp.AttachReputation(repEng)
	st.SetClientIPExtractor(wp.IPExtractor())

	frontend := httptest.NewServer(wp)
	defer frontend.Close()

	get := func(clientIP string) int {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/", nil)
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request from %s: %v", clientIP, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// The known-bad IP: fresh session risk ~0 + reputation bump 50 >= threshold
	// 30 -> blocked.
	if code := get(badIP); code != http.StatusForbidden {
		t.Errorf("known-bad IP should be blocked by reputation friction; got %d want 403", code)
	}
	// A clean IP making the identical request: risk 0, no bump -> allowed.
	if code := get("198.51.100.77"); code != http.StatusOK {
		t.Errorf("clean IP must pass; got %d want 200", code)
	}
}

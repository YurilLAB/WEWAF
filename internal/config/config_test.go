package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestQuickstartConfigLoadsAndValidates asserts the config the quickstart
// scripts (scripts/quickstart.{sh,ps1}) emit is accepted by Load + Validate, so
// "front your site in one command" actually produces a runnable node.
func TestQuickstartConfigLoadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	quickstartJSON := `{
  "listen_addr": ":8080",
  "admin_addr": "127.0.0.1:8443",
  "backend_url": "http://localhost:3000",
  "mode": "active",
  "trust_xff": false,
  "ypanel_url": "https://ypanel.yurillab.dev"
}`
	if err := os.WriteFile(path, []byte(quickstartJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("quickstart config must Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("quickstart config must Validate: %v", err)
	}
	if cfg.BackendURL != "http://localhost:3000" {
		t.Errorf("backend_url not parsed: %q", cfg.BackendURL)
	}
	if cfg.AdminAddr != "127.0.0.1:8443" {
		t.Errorf("admin_addr not parsed: %q", cfg.AdminAddr)
	}
	if cfg.Mode != "active" {
		t.Errorf("mode not parsed: %q", cfg.Mode)
	}
	// Defaults must fill the fields the quickstart omits.
	if cfg.MaxConcurrentReq == 0 || cfg.RateLimitRPS == 0 {
		t.Errorf("defaults should fill omitted fields (max_concurrent_req=%d rate_limit_rps=%d)",
			cfg.MaxConcurrentReq, cfg.RateLimitRPS)
	}
}

// TestDefaultValidates is a basic sanity guard that the shipped defaults are
// internally consistent (the config package had no test coverage before).
func TestDefaultValidates(t *testing.T) {
	cfg := Default()
	cfg.BackendURL = "http://localhost:3000" // the one required field
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default()+backend must validate: %v", err)
	}
}

// TestBrowserChallengeBlockForcesDependencies closes the silent-no-op footgun:
// turning on block mode without its prerequisites must not yield a control that
// quietly does nothing. Validate has to force session tracking + PoW (the
// escalation's mechanism) + the challenge-enabled flag on.
func TestBrowserChallengeBlockForcesDependencies(t *testing.T) {
	cfg := Default()
	cfg.BackendURL = "http://localhost:3000"
	cfg.BrowserChallengeBlock = true
	// Operator left every dependency off.
	cfg.SessionTrackingEnabled = false
	cfg.PoWEnabled = false
	cfg.BrowserChallengeEnabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !cfg.SessionTrackingEnabled {
		t.Error("block mode must force SessionTrackingEnabled (no tracking → no score to escalate)")
	}
	if !cfg.PoWEnabled {
		t.Error("block mode must force PoWEnabled (PoW is the only way to shed the escalation)")
	}
	if !cfg.BrowserChallengeEnabled {
		t.Error("block mode must force BrowserChallengeEnabled")
	}
}

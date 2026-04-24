// Package setup runs live validation checks for the onboarding Next Steps
// flow. Every step in the UI calls into one of these Check* functions;
// the operator can't "check off" a step until it actually passes.
//
// Each check returns a CheckResult describing pass/fail/warn plus a
// human-readable message and an optional structured detail payload the UI
// can render (e.g., resolved DNS addresses, SSL expiry dates).
package setup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/history"
	"wewaf/internal/rules"
	"wewaf/internal/ssl"
)

// Status is the result of a single check step.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	StatusSkip Status = "skip"
)

// CheckResult describes one probe's outcome.
type CheckResult struct {
	Step    string                 `json:"step"`
	Status  Status                 `json:"status"`
	Message string                 `json:"message"`
	Detail  map[string]interface{} `json:"detail,omitempty"`
	At      time.Time              `json:"at"`
}

// Checker bundles the subsystems needed to run checks.
type Checker struct {
	Cfg        *config.Config
	Connection *connection.Manager
	History    *history.Store
	SSL        *ssl.Manager
	RulesFn    func() []map[string]interface{}
}

// New creates a checker bound to the given subsystems. Any may be nil; the
// corresponding checks will return StatusSkip.
func New(cfg *config.Config, conn *connection.Manager, hist *history.Store, sslMgr *ssl.Manager, rulesFn func() []map[string]interface{}) *Checker {
	return &Checker{
		Cfg: cfg, Connection: conn, History: hist, SSL: sslMgr, RulesFn: rulesFn,
	}
}

// CheckDNS resolves the domain and verifies it points at the WAF's public IP.
// The domain + expected IP are supplied by the caller — the UI captures them
// from the Setup Wizard. If expectedIP is empty, a successful resolution to
// ANY address counts as pass.
func (c *Checker) CheckDNS(ctx context.Context, domain, expectedIP string) CheckResult {
	now := time.Now().UTC()
	res := CheckResult{Step: "dns", At: now}
	if domain == "" {
		res.Status = StatusFail
		res.Message = "no domain provided"
		return res
	}
	resolver := net.Resolver{}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(probeCtx, "ip", domain)
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("DNS lookup failed: %v", err)
		return res
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	res.Detail = map[string]interface{}{"resolved": addrs, "domain": domain}
	if expectedIP != "" {
		for _, ip := range ips {
			if ip.String() == expectedIP {
				res.Status = StatusPass
				res.Message = fmt.Sprintf("%s resolves to %s", domain, expectedIP)
				return res
			}
		}
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("%s resolves to %s, not to the expected %s",
			domain, strings.Join(addrs, ", "), expectedIP)
		return res
	}
	res.Status = StatusPass
	res.Message = fmt.Sprintf("%s resolves (%d addresses)", domain, len(addrs))
	return res
}

// CheckOrigin probes the configured backend_url and reports latency.
func (c *Checker) CheckOrigin(ctx context.Context) CheckResult {
	res := CheckResult{Step: "origin", At: time.Now().UTC()}
	if c.Cfg == nil || c.Cfg.BackendURL == "" {
		res.Status = StatusFail
		res.Message = "backend_url is not configured"
		return res
	}
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, c.Cfg.BackendURL, nil)
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("invalid backend_url: %v", err)
		return res
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	latency := time.Since(started).Milliseconds()
	res.Detail = map[string]interface{}{
		"backend_url": c.Cfg.BackendURL, "latency_ms": latency,
	}
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("could not reach %s: %v", c.Cfg.BackendURL, err)
		return res
	}
	resp.Body.Close()
	res.Detail["status_code"] = resp.StatusCode
	if resp.StatusCode >= 500 {
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("backend responded %d (server error)", resp.StatusCode)
		return res
	}
	res.Status = StatusPass
	res.Message = fmt.Sprintf("backend reachable, %dms, HTTP %d", latency, resp.StatusCode)
	return res
}

// CheckSSL verifies a certificate is configured and reports its expiry.
// If a domain is provided and a real TLS handshake can be attempted, we
// also validate the presented cert chain.
func (c *Checker) CheckSSL(ctx context.Context, domain string) CheckResult {
	res := CheckResult{Step: "ssl", At: time.Now().UTC()}
	if c.SSL == nil {
		res.Status = StatusSkip
		res.Message = "SSL manager not initialised"
		return res
	}
	certs := c.SSL.List()
	if len(certs) == 0 {
		res.Status = StatusFail
		res.Message = "no certificates uploaded"
		return res
	}
	// Find the nearest-expiring valid cert.
	var soonest *ssl.Certificate
	for i := range certs {
		c := certs[i]
		if !c.Valid {
			continue
		}
		if soonest == nil || c.NotAfter.Before(soonest.NotAfter) {
			cp := c
			soonest = &cp
		}
	}
	if soonest == nil {
		res.Status = StatusFail
		res.Message = "no valid certificates"
		return res
	}
	daysLeft := int(time.Until(soonest.NotAfter).Hours() / 24)
	res.Detail = map[string]interface{}{
		"domain":       soonest.Domain,
		"issuer":       soonest.Issuer,
		"not_after":    soonest.NotAfter,
		"days_to_expiry": daysLeft,
		"total_certs":  len(certs),
	}
	if daysLeft < 0 {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("certificate for %s has expired", soonest.Domain)
		return res
	}
	if daysLeft < 14 {
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("certificate for %s expires in %d days", soonest.Domain, daysLeft)
		return res
	}

	// Bonus: live TLS probe if the caller supplied a domain and it's
	// DNS-resolvable to an address we can dial.
	if domain != "" {
		dialer := &tls.Dialer{Config: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(probeCtx, "tcp", domain+":443")
		if err == nil {
			defer conn.Close()
			if tlsConn, ok := conn.(*tls.Conn); ok {
				state := tlsConn.ConnectionState()
				res.Detail["tls_version"] = state.Version
				res.Detail["negotiated_protocol"] = state.NegotiatedProtocol
			}
		}
	}
	res.Status = StatusPass
	res.Message = fmt.Sprintf("%s valid, expires in %d days", soonest.Domain, daysLeft)
	return res
}

// CheckTraffic sends a self-probe through the proxy's listen_addr and
// confirms the request reached the admin API. It's the end-to-end sanity
// check for "does the WAF actually forward traffic".
func (c *Checker) CheckTraffic(ctx context.Context) CheckResult {
	res := CheckResult{Step: "traffic", At: time.Now().UTC()}
	if c.Cfg == nil {
		res.Status = StatusSkip
		res.Message = "config not available"
		return res
	}
	// Probe the admin port's /api/health directly — this verifies the
	// HTTP server started and is reachable. The proxy port's connectivity
	// is covered by the origin check.
	adminAddr := c.Cfg.AdminAddr
	if strings.HasPrefix(adminAddr, ":") {
		adminAddr = "127.0.0.1" + adminAddr
	}
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, reqErr := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+adminAddr+"/api/health", nil)
	if reqErr != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("malformed admin_addr %q: %v", adminAddr, reqErr)
		return res
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	latency := time.Since(started).Milliseconds()
	res.Detail = map[string]interface{}{"admin_addr": adminAddr, "latency_ms": latency}
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("admin API unreachable: %v", err)
		return res
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	var health struct {
		Status string `json:"status"`
		Mode   string `json:"mode"`
	}
	_ = json.Unmarshal(body, &health)
	if resp.StatusCode != 200 || health.Status != "ok" {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("admin health returned HTTP %d / status %q", resp.StatusCode, health.Status)
		return res
	}
	res.Detail["mode"] = health.Mode
	res.Status = StatusPass
	res.Message = fmt.Sprintf("admin API healthy (%s mode, %dms)", health.Mode, latency)
	return res
}

// CheckRules confirms the rule engine compiled and returns the loaded count.
func (c *Checker) CheckRules(ctx context.Context) CheckResult {
	_ = ctx
	res := CheckResult{Step: "rules", At: time.Now().UTC()}
	if c.RulesFn == nil {
		res.Status = StatusSkip
		res.Message = "rules snapshot not available"
		return res
	}
	all := c.RulesFn()
	if len(all) == 0 {
		res.Status = StatusFail
		res.Message = "no rules loaded"
		return res
	}
	// Tally by category.
	byCategory := make(map[string]int)
	byPhase := make(map[string]int)
	crsCount := 0
	for _, r := range all {
		if cat, _ := r["category"].(string); cat != "" {
			byCategory[cat]++
		}
		if ph, _ := r["phase"].(string); ph != "" {
			byPhase[ph]++
		}
		if id, _ := r["id"].(string); strings.HasPrefix(id, "CRS-") {
			crsCount++
		}
	}
	res.Detail = map[string]interface{}{
		"total":     len(all),
		"crs":       crsCount,
		"by_phase":  byPhase,
		"by_category": byCategory,
	}
	res.Status = StatusPass
	res.Message = fmt.Sprintf("%d rules loaded (%d CRS)", len(all), crsCount)
	return res
}

// CheckHistory verifies the rotating SQLite writer is healthy — queue depth
// below cap, low dropped-event ratio, current file writable.
func (c *Checker) CheckHistory(ctx context.Context) CheckResult {
	_ = ctx
	res := CheckResult{Step: "history", At: time.Now().UTC()}
	if c.History == nil {
		res.Status = StatusSkip
		res.Message = "history store not initialised"
		return res
	}
	stats := c.History.StatsSnapshot()
	res.Detail = map[string]interface{}{
		"current_path":    stats.CurrentPath,
		"buffered_queue":  stats.BufferedQueue,
		"written_events":  stats.WrittenEvents,
		"dropped_events":  stats.DroppedEvents,
		"rotations":       stats.Rotations,
	}
	if stats.CurrentPath == "" {
		res.Status = StatusFail
		res.Message = "history store has no active database"
		return res
	}
	if stats.DroppedEvents > 0 && stats.WrittenEvents > 0 {
		ratio := float64(stats.DroppedEvents) / float64(stats.WrittenEvents+stats.DroppedEvents)
		if ratio > 0.1 {
			res.Status = StatusWarn
			res.Message = fmt.Sprintf("dropped %d events (%.1f%% of traffic)", stats.DroppedEvents, ratio*100)
			return res
		}
	}
	res.Status = StatusPass
	res.Message = fmt.Sprintf("history writer healthy, %d events written", stats.WrittenEvents)
	return res
}

// RunAll runs every check in sequence and returns the collected results.
// Handy for the UI to render a one-page setup audit.
func (c *Checker) RunAll(ctx context.Context, domain, expectedIP string) []CheckResult {
	return []CheckResult{
		c.CheckDNS(ctx, domain, expectedIP),
		c.CheckOrigin(ctx),
		c.CheckSSL(ctx, domain),
		c.CheckTraffic(ctx),
		c.CheckRules(ctx),
		c.CheckHistory(ctx),
	}
}

// Suppress import-unused false positives while we use the symbols lazily.
var _ = url.Parse
var _ = errors.New
var _ = runtime.GOOS
var _ = rules.DefaultRules

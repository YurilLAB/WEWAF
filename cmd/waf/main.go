package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"wewaf/internal/audit"
	"wewaf/internal/bruteforce"
	"wewaf/internal/clientip"
	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/firewall"
	"wewaf/internal/graphql"
	"wewaf/internal/history"
	"wewaf/internal/host"
	"wewaf/internal/intel"
	"wewaf/internal/ja3"
	"wewaf/internal/limits"
	"wewaf/internal/pow"
	"wewaf/internal/proxy"
	"wewaf/internal/reputation"
	"wewaf/internal/rules"
	"wewaf/internal/session"
	"wewaf/internal/ssl"
	"wewaf/internal/telemetry"
	"wewaf/internal/watchdog"
	"wewaf/internal/web"
)

// meshMaxResponseBytes caps the size of a peer's gossip response. A malicious
// or misbehaving peer returning an unbounded stream would otherwise OOM the
// daemon; 4 MB is more than enough for thousands of ban entries.
const meshMaxResponseBytes = 4 * 1024 * 1024

const wafVersion = "0.2.0"

// simpleLogger adapts Go's standard log to the engine.Logger interface.
type simpleLogger struct{}

func (s *simpleLogger) Debugf(format string, args ...interface{}) { log.Printf("[DEBUG] "+format, args...) }
func (s *simpleLogger) Infof(format string, args ...interface{})  { log.Printf("[INFO] "+format, args...) }
func (s *simpleLogger) Warnf(format string, args ...interface{})  { log.Printf("[WARN] "+format, args...) }
func (s *simpleLogger) Errorf(format string, args ...interface{}) { log.Printf("[ERROR] "+format, args...) }

// banListLister adapts *core.BanList to firewall.Lister so the host-firewall
// reconcile loop can read the active ban set without firewall importing core.
type banListLister struct{ bl *core.BanList }

func (l banListLister) ActiveBans() []firewall.Ban {
	entries := l.bl.List()
	out := make([]firewall.Ban, 0, len(entries))
	for _, e := range entries {
		out = append(out, firewall.Ban{IP: e.IP, ExpiresAt: e.ExpiresAt})
	}
	return out
}

// shadowUncoverable maps pseudo-rule IDs that are enforced by separate proxy
// subsystems (NOT the rule engine) to the operator control that actually
// governs them. Shadow mode only suppresses rule-engine matches, so listing one
// of these in shadow_rule_ids is a no-op; main warns when it sees one so the
// operator isn't misled into thinking a detection is being canaried when it
// isn't (audit finding S2-2).
var shadowUncoverable = map[string]string{
	"GRPC-DPI":         "grpc_block_on_error",
	"GRAPHQL-VALIDATE": "the graphql_* settings",
	"SESSION-RISK":     "session_block_threshold",
	"BRUTE-FORCE":      "brute_force_* settings / mode",
}

// reputationConfigFrom maps the operator config onto the reputation engine's
// policy. Escalation Factor / MaxDuration / OffenseWindow are deliberately
// shared with the ban-backoff knobs so the reputation-driven and BanList-driven
// escalation ladders agree.
func reputationConfigFrom(cfg *config.Config) reputation.Config {
	return reputation.Config{
		Enabled:       cfg.ReputationEnabled,
		Window:        time.Duration(cfg.ReputationWindowSec) * time.Second,
		Threshold:     cfg.ReputationThreshold,
		BaseDuration:  time.Duration(cfg.ReputationBanDurationSec) * time.Second,
		Factor:        float64(cfg.BanBackoffMultiplier),
		MaxDuration:   time.Duration(cfg.MaxBanDurationSec) * time.Second,
		OffenseWindow: time.Duration(cfg.BanBackoffWindowSec) * time.Second,
		HalfLife:      time.Duration(cfg.RepHalfLifeSec) * time.Second,
		Jitter:        time.Duration(cfg.RepJitterSec) * time.Second,
		PurgeAge:      time.Duration(cfg.RepPurgeAgeSec) * time.Second,

		Recidive:          cfg.RecidiveEnabled,
		RecidiveThreshold: cfg.RecidiveThreshold,
		RecidiveBan:       time.Duration(cfg.RecidiveBanDurationSec) * time.Second,
	}
}

// reputationSubsystem classifies a block's rule ID / category into the
// detection subsystem that raised it, so the reputation ledger can record WHICH
// independent subsystems have flagged an IP (the bitmask that seeds future
// cross-subsystem "recidive" consensus). Unknown sources fold into "engine".
func reputationSubsystem(ruleID, category string) string {
	id := strings.ToUpper(ruleID)
	switch {
	case strings.HasPrefix(id, "DDOS"):
		return "ddos"
	case strings.HasPrefix(id, "BRUTE"):
		return "bruteforce"
	case strings.HasPrefix(id, "JA3") || strings.HasPrefix(id, "JA4"):
		return "ja3"
	case strings.HasPrefix(id, "RATE"):
		return "rate"
	case strings.HasPrefix(id, "INTEL"):
		return "intel"
	case strings.HasPrefix(id, "SESSION"):
		return "session"
	default:
		return "engine"
	}
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to JSON config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("WEWaf starting...")

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	log.Printf("config loaded: listen=%s backend=%s mode=%s", cfg.ListenAddr, cfg.BackendURL, cfg.Mode)

	// The admin server has no built-in authentication beyond the
	// X-API-Key header check. Binding it to every interface (the
	// default for ":8443"-style addrs) means anyone on the same VPC,
	// container network, or shared host can hammer the API. Surface a
	// loud warning so operators on a lab box see it the first time
	// they start the daemon and tune AdminAddr to "127.0.0.1:8443"
	// or a private interface before exposing the WAF.
	if isWildcardListenAddr(cfg.AdminAddr) {
		log.Printf("WARN: admin_addr=%q binds every interface — restrict to 127.0.0.1 "+
			"or a private interface in production, or front the admin port with mTLS",
			cfg.AdminAddr)
	}

	// Fail closed on the dangerous no-auth-on-exposed-admin combination, and
	// reject a weak admin key. WAF_ALLOW_NO_AUTH=1 serves the entire admin
	// surface (config writes, bans, SSL upload, mesh, zero-trust) with NO
	// authentication — it is a local-dev escape hatch only and must never be
	// combined with a non-loopback admin bind, where the whole network could
	// reach it. A short WAF_API_KEY is brute-forceable, so enforce a floor.
	if os.Getenv("WAF_ALLOW_NO_AUTH") == "1" && os.Getenv("WAF_API_KEY") == "" {
		if !isLoopbackListenAddr(cfg.AdminAddr) {
			log.Fatalf("refusing to start: WAF_ALLOW_NO_AUTH=1 disables admin authentication, "+
				"but admin_addr=%q is not loopback. Set WAF_API_KEY (>=32 random bytes) or bind "+
				"admin_addr to 127.0.0.1.", cfg.AdminAddr)
		}
		log.Printf("WARN: WAF_ALLOW_NO_AUTH=1 — admin API authentication is DISABLED (loopback bind only)")
	}
	if k := os.Getenv("WAF_API_KEY"); k != "" && len(k) < 32 {
		log.Fatalf("refusing to start: WAF_API_KEY is too short (%d bytes); use at least 32 random "+
			"bytes (e.g. `openssl rand -hex 32`).", len(k))
	}

	if err := limits.Apply(cfg.MaxCPUCores, cfg.MaxMemoryMB); err != nil {
		log.Fatalf("failed to apply resource limits: %v", err)
	}
	log.Printf("resource limits applied: cpu=%d memory=%dMB", cfg.MaxCPUCores, cfg.MaxMemoryMB)

	rawRules := rules.DefaultRules()
	if cfg.CRSEnabled {
		rawRules = append(rawRules, rules.CRSRules()...)
		log.Printf("OWASP CRS rules merged: +%d rules", len(rules.CRSRules()))
	}
	rs, err := rules.NewRuleSet(rawRules)
	if err != nil {
		log.Fatalf("failed to compile rules: %v", err)
	}
	log.Printf("rules compiled: %d signatures loaded (paranoia_level=%d)",
		rs.Count(), cfg.ParanoiaLevel)

	eng, err := engine.NewEngine(cfg, rs, &simpleLogger{})
	if err != nil {
		log.Fatalf("failed to create engine: %v", err)
	}

	metrics := telemetry.NewMetrics()

	// History store — persistent SQLite with time-rotated databases.
	historyStore, err := history.Open(history.Options{
		Dir:        cfg.HistoryDir,
		Rotation:   time.Duration(cfg.HistoryRotateHours) * time.Hour,
		BufferSize: cfg.HistoryBufferSize,
		FlushEvery: time.Duration(cfg.HistoryFlushSeconds) * time.Second,
		WAFVersion: wafVersion,
	})
	if err != nil {
		log.Fatalf("failed to open history store: %v", err)
	}
	defer func() {
		if err := historyStore.Close(); err != nil {
			log.Printf("history store close error: %v", err)
		}
	}()
	log.Printf("history store opened: %s", historyStore.StatsSnapshot().CurrentPath)

	// Durable reputation ledger. When enabled it persists each repeat
	// offender's escalation tier and active ban so neither is forgotten across
	// a restart (closing WEWAF's restart-amnesia gap), and it auto-bans an IP
	// that accrues too many blocks in the configured window. Off by default —
	// an open failure is non-fatal (the in-memory backoff still applies).
	var repEngine *reputation.Engine
	if cfg.ReputationEnabled {
		repPath := filepath.Join(cfg.HistoryDir, "reputation.sqlite")
		re, rerr := reputation.Open(reputation.Options{Path: repPath, Config: reputationConfigFrom(cfg)})
		if rerr != nil {
			log.Printf("reputation: open failed (%v) — durable reputation OFF, in-memory backoff still applies", rerr)
		} else {
			repEngine = re
			repEngine.Start(context.Background())
			log.Printf("reputation ledger opened: %s", repPath)
			defer func() {
				if err := repEngine.Close(); err != nil {
					log.Printf("reputation ledger close error: %v", err)
				}
			}()
		}
	}

	// Attach persistence to the telemetry hot path.
	metrics.SetPersister(newHistoryPersister(historyStore))
	historyStore.OnRotate(func(_ time.Time) {
		metrics.OnRotation()
		// Reuse the 24h rotation tick to purge quiet, unbanned offenders from
		// the reputation ledger — no extra timer needed. No-op when disabled.
		repEngine.Purge()
		log.Printf("history rotated: new db=%s", historyStore.StatsSnapshot().CurrentPath)
	})

	// Shadow (canary) recorder: a rule listed in shadow_rule_ids evaluates but
	// never blocks; each would-block is tallied here so an operator can vet a
	// new/tightened rule against live traffic before promoting it (S2).
	eng.SetShadowRecorder(func(tx *core.Transaction, m core.Match) {
		method, path := "", ""
		if tx.Request != nil {
			method = tx.Request.Method
			if tx.Request.URL != nil {
				path = tx.Request.URL.Path
			}
		}
		metrics.RecordWouldBlock(tx.ClientIP, method, path, m.RuleID, m.RuleName, m.Message, m.Score)
	})
	if n := len(cfg.ShadowRuleIDs); n > 0 {
		log.Printf("shadow mode active: %d rule(s) run in canary (record-only, never block): %s",
			n, strings.Join(cfg.ShadowRuleIDs, ", "))
		// Warn on shadow IDs the engine can't cover: these detections are
		// enforced by separate proxy subsystems outside rule evaluation, so
		// shadowing them is silently a no-op. Tell the operator to use the
		// subsystem's own control instead (audit finding S2-2).
		for _, id := range cfg.ShadowRuleIDs {
			if knob, ok := shadowUncoverable[strings.ToUpper(strings.TrimSpace(id))]; ok {
				log.Printf("WARN: shadow_rule_ids lists %q, but that detection is enforced by a proxy "+
					"subsystem outside the rule engine — shadow mode will NOT suppress it. Use its own "+
					"control (%s) to disable/observe instead.", id, knob)
			}
		}
	}

	bf := bruteforce.NewDetector(time.Duration(cfg.BruteForceWindowSec) * time.Second)
	defer bf.Stop()

	// One *clientip.Extractor per WAF instance. The proxy creates its
	// own from cfg in NewWAFProxy below, so we don't construct a second
	// one here — instead we hand the proxy's instance to the session
	// tracker. That keeps trust_xff + trusted_proxies single-sourced
	// and makes hot-reload a single Update() call. The dependency
	// inversion (build proxy first, then tracker) is enforced by the
	// init order below.

	// Session tracker — foundation for anomaly scoring and browser challenge.
	// IPExtractor is wired after the proxy is built (see below).
	sessionTracker := session.NewTracker(session.Config{
		Secret:             cfg.SessionCookieSecret,
		MaxSessions:        cfg.SessionMaxSessions,
		IdleTTL:            time.Duration(cfg.SessionIdleTTLSec) * time.Second,
		Enabled:            cfg.SessionTrackingEnabled,
		RequestRateCeiling: cfg.SessionRequestRateCeiling,
		PathCountCeiling:   cfg.SessionPathCountCeiling,
		ChallengeTTL:       time.Duration(cfg.ChallengeTTLSec) * time.Second,
		ScoreDecayPerMin:   cfg.SessionScoreDecayPerMin,
	})
	defer sessionTracker.Stop()

	// GraphQL schema-aware validator. If the operator supplied a schema
	// file and it fails to parse, we log and keep structural-only mode —
	// better than refusing to start.
	var gqlSchemaSDL string
	if cfg.GraphQLSchemaFile != "" {
		if data, rerr := os.ReadFile(cfg.GraphQLSchemaFile); rerr != nil {
			log.Printf("graphql: could not read schema file %q: %v", cfg.GraphQLSchemaFile, rerr)
		} else {
			gqlSchemaSDL = string(data)
		}
	}
	gqlValidator, gqlErr := graphql.New(graphql.Config{
		Enabled:            cfg.GraphQLEnabled,
		MaxDepth:           cfg.GraphQLMaxDepth,
		MaxAliases:         cfg.GraphQLMaxAliases,
		MaxFields:          cfg.GraphQLMaxFields,
		SchemaSDL:          gqlSchemaSDL,
		RequireRoleHdr:     cfg.GraphQLRoleHeader,
		BlockOnError:       cfg.GraphQLBlockOnError,
		BlockSubscriptions: cfg.GraphQLBlockSubscriptions,
	})
	if gqlErr != nil {
		log.Printf("graphql: schema parse failed, running structural-only: %v", gqlErr)
	}

	wp, err := proxy.NewWAFProxy(cfg, eng, metrics, bf)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}
	// Share the proxy's client-IP extractor with the session tracker
	// so both layers agree on every source-IP decision and a single
	// hot-reload Update() propagates atomically.
	sessionTracker.SetClientIPExtractor(wp.IPExtractor())
	if cfg.TrustXFF && !wp.IPExtractor().HasTrustedProxies() {
		log.Printf("WARN: trust_xff is enabled with an empty trusted_proxies list — " +
			"any client can spoof X-Forwarded-For. Populate trusted_proxies with the " +
			"upstream CDN/LB CIDR ranges in production.")
	}
	wp.AttachSessionTracker(sessionTracker)
	wp.AttachGraphQLValidator(gqlValidator)

	// Origin proof-of-passage status. The proxy only injects the verify header
	// when a shared secret is present (see NewWAFProxy); surface the
	// misconfiguration here loudly so an operator who flipped the switch but
	// forgot the secret isn't lulled into thinking the origin is shielded.
	if cfg.OriginShieldEnabled {
		switch {
		case cfg.OriginShieldSecret == "":
			log.Printf("WARN: origin_shield_enabled but origin_shield_secret is empty — NOT injecting %q. "+
				"Set a strong shared secret and configure your origin to require it, or direct-to-origin "+
				"traffic still bypasses the WAF.", cfg.OriginShieldHeader)
		default:
			if len(cfg.OriginShieldSecret) < 16 {
				log.Printf("WARN: origin_shield_secret is short (%d chars) — use at least 16 random bytes "+
					"(e.g. `openssl rand -hex 24`).", len(cfg.OriginShieldSecret))
			}
			log.Printf("origin shield: enabled (header=%s, rotation=%v) — configure your origin to reject "+
				"requests missing this header to close the direct-to-origin bypass",
				cfg.OriginShieldHeader, cfg.OriginShieldSecretPrevious != "")
		}
	}

	// Tamper-evident audit log. Failure to open the chain is non-fatal —
	// we degrade to in-memory-only and surface a log line so operators
	// can see their disk setup is wrong without losing the WAF itself.
	var auditChain *audit.Chain
	if cfg.AuditEnabled {
		ch, aerr := audit.New(audit.Config{
			Secret:   cfg.AuditSecret,
			FilePath: cfg.AuditFilePath,
			RingSize: cfg.AuditRingSize,
		})
		if aerr != nil {
			log.Printf("audit: could not open chain (%v); falling back to in-memory ring", aerr)
			ch, _ = audit.New(audit.Config{Secret: cfg.AuditSecret, RingSize: cfg.AuditRingSize})
		}
		auditChain = ch
		defer func() { _ = auditChain.Close() }()
		wp.AttachAuditChain(auditChain)
		_, _ = auditChain.Append("startup", "system", "WEWAF daemon starting", "")
	}

	// JA3 fingerprinter. Cache is always created when the feature is on
	// (so future TLS termination wiring picks it up automatically); the
	// detector + trust + header path is also wired so edge deployments
	// behind a TLS-terminating proxy work out of the box. We hold a
	// reference to the detector so the intel-feed sink (below) can
	// MergeBad() into it as feeds publish new headless-build hashes.
	var jaDetector *ja3.Detector
	var jaCache *ja3.Cache // hoisted so the native TLS listener (below) can wire JA3 capture
	if cfg.JA3Enabled {
		jaCache = ja3.NewCache(cfg.JA3CacheCapacity, time.Duration(cfg.JA3CacheTTLSec)*time.Second)
		jaDetector = ja3.NewDetector()
		jaDetector.SetHardBlock(cfg.JA3HardBlock)
		jaTrust := ja3.NewTrustChecker(cfg.JA3TrustedSources)
		wp.AttachJA3(jaCache, jaDetector, jaTrust, cfg.JA3Header)
		log.Printf("ja3: enabled (header=%q trusted_sources=%d hard_block=%v)",
			cfg.JA3Header, len(cfg.JA3TrustedSources), cfg.JA3HardBlock)
	}

	// Proof-of-work issuer. If no secret was supplied, generate one and
	// keep it in-memory only — restarting the WAF invalidates outstanding
	// PoW cookies, which is the desired security posture during incidents.
	//
	// crypto/rand failure is FATAL here: the previous fallback to a
	// time-derived string was guessable in seconds (an attacker who
	// knows roughly when the daemon started can brute-force the secret
	// from `time.Now().String()` shape). Better to refuse to enable
	// PoW than ship a weak secret.
	var powIssuer *pow.Issuer
	if cfg.PoWEnabled {
		secret := []byte(cfg.PoWSecret)
		if len(secret) == 0 {
			b := make([]byte, 32)
			if _, rerr := cryptorand.Read(b); rerr != nil {
				log.Fatalf("pow: crypto/rand failed (%v); refusing to start with a weak secret", rerr)
			}
			secret = b
			cfg.PoWSecret = string(secret) // share with web layer for cookie signing
		}
		issuer, perr := pow.NewIssuer(
			secret,
			uint8(cfg.PoWMinDifficulty),
			uint8(cfg.PoWMaxDifficulty),
			time.Duration(cfg.PoWTokenTTLSec)*time.Second,
		)
		if perr != nil {
			log.Printf("pow: disabled — invalid configuration: %v", perr)
		} else {
			powIssuer = issuer
			wp.AttachPoW(powIssuer)
			log.Printf("pow: enabled (difficulty=%d-%d trigger_score=%d ttl=%ds)",
				cfg.PoWMinDifficulty, cfg.PoWMaxDifficulty,
				cfg.PoWTriggerScore, cfg.PoWTokenTTLSec)
		}
	}

	// Risk-tier ordering sanity. The graduated bands should ascend
	// throttle < challenge(PoW trigger) < block; riskTier is fail-secure so
	// a mis-order is a usability footgun (a stricter low band shadows a
	// looser high one), not a security hole — warn rather than refuse.
	if cfg.SessionThrottleThreshold > 0 {
		log.Printf("session: throttle band enabled (threshold=%d delay=%dms)",
			cfg.SessionThrottleThreshold, cfg.SessionThrottleDelayMs)
		if cfg.PoWEnabled && cfg.SessionThrottleThreshold >= cfg.PoWTriggerScore {
			log.Printf("WARN: session_throttle_threshold (%d) >= pow_trigger_score (%d) — "+
				"the throttle band is empty because the challenge fires first",
				cfg.SessionThrottleThreshold, cfg.PoWTriggerScore)
		}
		if cfg.SessionBlockThreshold > 0 && cfg.SessionThrottleThreshold >= cfg.SessionBlockThreshold {
			log.Printf("WARN: session_throttle_threshold (%d) >= session_block_threshold (%d) — "+
				"the throttle band is empty because the block fires first",
				cfg.SessionThrottleThreshold, cfg.SessionBlockThreshold)
		}
	}
	if cfg.SessionBlockThreshold > 0 && cfg.PoWEnabled &&
		cfg.SessionBlockThreshold <= cfg.PoWTriggerScore {
		log.Printf("WARN: session_block_threshold (%d) <= pow_trigger_score (%d) — "+
			"high-risk sessions will be blocked before they are ever challenged",
			cfg.SessionBlockThreshold, cfg.PoWTriggerScore)
	}

	// Background telemetry collectors.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	historyStore.Start(rootCtx)

	hostCollector := host.NewCollector(wafVersion)
	hostCollector.Start(rootCtx)
	defer hostCollector.Stop()

	connMgr := connection.NewManager(connection.Config{
		BackendURL:      cfg.BackendURL,
		ListenAddr:      cfg.ListenAddr,
		AdminAddr:       cfg.AdminAddr,
		PollIntervalSec: 10,
		RetryAttempts:   3,
		TimeoutMs:       2000,
	})
	connMgr.Start(rootCtx)
	defer connMgr.Stop()

	sslMgr, err := ssl.NewManager("certs")
	if err != nil {
		log.Printf("ssl manager disabled: %v", err)
	}

	rulesFn := func() []map[string]interface{} {
		compiled := rs.RulesSnapshot()
		out := make([]map[string]interface{}, 0, len(compiled))
		for _, cr := range compiled {
			pl := cr.Paranoia
			if pl <= 0 {
				pl = 1
			}
			out = append(out, map[string]interface{}{
				"id":          cr.ID,
				"name":        cr.Name,
				"phase":       cr.Phase.String(),
				"action":      cr.Action.String(),
				"score":       cr.Score,
				"description": cr.Description,
				"category":    cr.Category,
				"paranoia":    pl,
			})
		}
		return out
	}
	banList := core.NewBanList()
	banList.ConfigureBackoff(
		cfg.BanBackoffEnabled,
		cfg.BanBackoffMultiplier,
		time.Duration(cfg.BanBackoffWindowSec)*time.Second,
		time.Duration(cfg.MaxBanDurationSec)*time.Second,
	)
	stopBanCleanup := banList.StartCleanup(time.Minute)
	defer stopBanCleanup()

	// Enforce bans on the ingress path. Without this the ban list is only
	// ever read by the admin/auto-mitigation/mesh layers, so a banned IP keeps
	// reaching the backend. Wiring it here makes every ban source (manual,
	// threat-feed, mesh, auto-mitigate) actually block the offender.
	wp.AttachBanList(banList)

	// Never-ban allowlist. Loopback and the unspecified address are always
	// refused inside BanList; here we add the operator's explicit entries plus
	// the trusted-proxy CIDRs — banning your own CDN egress range (which every
	// real visitor's traffic appears to come from when trust_xff is on) would
	// be an instant self-inflicted outage, doubly so once the host-firewall
	// sink starts dropping those addresses at the kernel across every port.
	banAllowEntries := append([]string(nil), cfg.BanAllowlist...)
	banAllowEntries = append(banAllowEntries, cfg.TrustedProxies...)
	banAllowSet, banAllowErr := clientip.NewCIDRSet(banAllowEntries)
	if banAllowErr != nil {
		log.Printf("ban allowlist: invalid entry (%v) — proceeding with the loopback/unspecified guard only", banAllowErr)
		banAllowSet = nil
	}
	banList.SetAllowlist(banAllowSet)

	// Wire the durable reputation ledger into the ban path. This (a) makes the
	// existing exponential backoff durable — escalation is derived from the
	// persisted offense count, so a repeat offender keeps climbing the ladder
	// across restarts; (b) re-seeds bans that were still active at last
	// shutdown so an attacker mid-ban stays banned; and (c) installs the
	// auto-ban observer that turns the previously configured-but-unwired
	// "N blocks in a window" reputation feature into a live, self-improving
	// defence. The allowlist installed above still vetoes every ban source.
	if repEngine != nil {
		banList.SetOffenseLedger(repEngine)
		restored := 0
		for _, b := range repEngine.RestoreActive() {
			if banList.RestoreBan(b.Key, b.Reason, b.ExpiresAt, b.Offenses) {
				restored++
			}
		}
		if restored > 0 {
			log.Printf("reputation: restored %d active ban(s) across restart", restored)
		}
		// The single block funnel (every RecordBlock* path lands in
		// RecordBlockWithCategory) feeds the ledger. Crossing the windowed
		// threshold issues an escalating ban through core.BanList — the one
		// escalator — so manual, intel, and auto bans all share one ladder.
		metrics.SetBlockHook(func(ip, method, path, ruleID, category, message string, score int) {
			d := repEngine.RecordBlock(ip, reputationSubsystem(ruleID, category), message)
			if d.Ban {
				reason := d.Reason
				if reason == "" {
					reason = "reputation: block threshold exceeded"
				}
				banList.Ban(ip, reason, d.Duration)
			}
		})
		log.Printf("reputation auto-ban active: %d blocks within %ds escalate to a ban",
			cfg.ReputationThreshold, cfg.ReputationWindowSec)
		if cfg.RecidiveEnabled {
			log.Printf("reputation recidive active: an IP flagged by %d distinct subsystems is banned for %ds",
				cfg.RecidiveThreshold, cfg.RecidiveBanDurationSec)
		}
	}

	// Host-firewall ban sink. When enabled, a background reconcile loop syncs
	// the active ban list into the OS packet filter (nftables on Linux, Windows
	// Firewall on Windows) so a banned source is dropped at L3/L4 across EVERY
	// port, pre-handshake — protecting SSH, databases, and the origin port, not
	// just the website. The in-process HTTP ban check above stays on, so if a
	// kernel call fails the offender is still blocked at L7. Off by default
	// (needs CAP_NET_ADMIN / Administrator); firewall_dry_run logs the exact
	// commands without touching the host so operators can trial it safely.
	if cfg.FirewallSinkEnabled {
		// In legacy trust_xff mode (trust_xff on, no trusted_proxies) a client
		// can spoof X-Forwarded-For to an arbitrary IP and, by tripping an
		// auto-ban, have the sink kernel-DROP that address across every port.
		// The sink already refuses private/loopback/CGNAT targets, but warn
		// loudly so operators populate trusted_proxies before relying on it.
		if cfg.TrustXFF && !wp.IPExtractor().HasTrustedProxies() {
			log.Printf("WARN: firewall_sink_enabled with trust_xff and an empty trusted_proxies list — " +
				"a spoofed X-Forwarded-For can get a public IP auto-banned and dropped at the kernel. " +
				"Populate trusted_proxies before enabling the sink in production.")
		}
		fwBackend, fwErr := firewall.DefaultBackend(firewall.Config{
			Backend:  cfg.FirewallBackend,
			Table:    cfg.FirewallTable,
			DryRun:   cfg.FirewallDryRun,
			MaxRules: cfg.FirewallMaxRules,
		})
		switch {
		case fwErr != nil:
			log.Printf("firewall: backend init failed (%v) — host-firewall enforcement OFF, L7 ban check still applies", fwErr)
		case fwBackend == nil:
			log.Printf("firewall: no host-firewall backend for backend=%q on this platform — host-firewall enforcement OFF, L7 ban check still applies", cfg.FirewallBackend)
		default:
			fwSink := firewall.New(fwBackend, banListLister{banList}, firewall.Config{
				Reconcile:   time.Duration(cfg.FirewallReconcileSec) * time.Second,
				MaxRules:    cfg.FirewallMaxRules,
				Allowlist:   banAllowSet,
				DryRun:      cfg.FirewallDryRun,
				ClearOnStop: true,
			})
			fwSink.Start(rootCtx)
			defer fwSink.Stop()
		}
	}

	// Auto-updating threat-intel feeds. The supervisor pulls FREE
	// community lists (FireHOL, Spamhaus DROP, SSLBL JA3, blocklist.de,
	// ET compromised, mitchellkrogza bad-UAs, CISA KEV) on a schedule
	// and merges entries into the runtime stores: IPs into banList,
	// JA3 hashes into the detector. Failures are logged to stderr and
	// retried with exponential backoff; the daemon never blocks on a
	// fetch.
	var intelMgr *intel.Manager
	if cfg.IntelFeedsEnabled {
		cacheDir := cfg.IntelFeedsCacheDir
		if cacheDir == "" {
			cacheDir = cfg.HistoryDir + string(os.PathSeparator) + "intel"
		}
		// "Learning" window — for the first N hours after startup we
		// observe-only, regardless of source confidence. Lets ops see
		// the FP rate before letting feeds enforce.
		learningEndsAt := time.Time{}
		if cfg.IntelFeedsLearningHours > 0 {
			learningEndsAt = time.Now().Add(time.Duration(cfg.IntelFeedsLearningHours) * time.Hour)
		}
		sink := func(entries []intel.Entry) error {
			learning := !learningEndsAt.IsZero() && time.Now().Before(learningEndsAt)
			ipBatch := 0
			ja3Batch := make(map[string]string)
			uaBatch := 0
			cveBatch := 0
			for _, e := range entries {
				switch e.Kind {
				case intel.KindIPv4, intel.KindIPv6:
					// We only auto-ban from HIGH-confidence sources OR
					// when MEDIUM confidence accumulates from ≥2 sources.
					// Single-source LOW entries get logged but not banned.
					if learning || e.Confidence == intel.ConfLow {
						continue
					}
					reason := "intel:" + e.Source
					if e.Reason != "" {
						reason = reason + " " + e.Reason
					}
					// Long ban — these are typically permanent
					// listings; the cleanup loop reaps stale entries.
					// Count only bans that were actually stored (Ban now
					// normalises CIDR feed entries and drops allowlisted /
					// loopback / range values), so the log isn't a fiction.
					if banList.Ban(e.Value, reason, 7*24*time.Hour) {
						ipBatch++
					}
				case intel.KindJA3, intel.KindJA4:
					if jaDetector == nil {
						continue
					}
					reason := e.Source
					if e.Reason != "" {
						reason = reason + ": " + e.Reason
					}
					ja3Batch[e.Value] = reason
				case intel.KindUA:
					uaBatch++
					_ = e // hook point for a future bad-UA matcher
				case intel.KindCVE:
					cveBatch++
					_ = e // virtual-patch hook; KEV entries surface
					// in the dashboard via Manager.Stats() for now
				}
			}
			if len(ja3Batch) > 0 && jaDetector != nil {
				added := jaDetector.MergeBad(ja3Batch)
				if added > 0 {
					log.Printf("intel: merged %d new JA3 hashes from feed", added)
				}
			}
			if ipBatch > 0 {
				log.Printf("intel: banned %d IPs from feed (learning=%v)", ipBatch, learning)
			}
			if uaBatch > 0 || cveBatch > 0 {
				log.Printf("intel: observed UAs=%d CVEs=%d", uaBatch, cveBatch)
			}
			// Best-effort audit trail.
			if auditChain != nil {
				_, _ = auditChain.Append("intel_update", "system",
					"feed merge",
					"") // metaJSON kept lightweight; per-source counts live in Stats
			}
			return nil
		}

		mgr, mErr := intel.NewManager(intel.Config{
			CacheDir: cacheDir,
		}, sink)
		if mErr != nil {
			log.Printf("intel: disabled — %v", mErr)
		} else {
			allowed := make(map[string]struct{})
			for _, s := range cfg.IntelFeedsAllowSources {
				allowed[strings.TrimSpace(strings.ToLower(s))] = struct{}{}
			}
			added := 0
			for _, src := range intel.DefaultSources() {
				if len(allowed) > 0 {
					if _, ok := allowed[strings.ToLower(src.Name)]; !ok {
						continue
					}
				}
				if err := mgr.AddSource(src); err == nil {
					added++
				}
			}
			mgr.Start()
			intelMgr = mgr
			log.Printf("intel: enabled with %d feed sources (cache=%s, learning=%dh)",
				added, cacheDir, cfg.IntelFeedsLearningHours)
			defer mgr.Stop()
		}
	}
	// Adaptive (Tier-2) PoW bit-management. Wraps the issuer so the
	// proxy's PoW gate can ask for a difficulty derived from session
	// risk + per-IP fail history + global load + JA4 rarity. Disabled
	// callers fall back to the legacy SuggestDifficulty path.
	var powAdaptive *pow.AdaptiveTier
	if cfg.PoWEnabled && cfg.PoWAdaptiveEnabled && powIssuer != nil {
		powAdaptive = pow.NewAdaptiveTier(powIssuer)
		powAdaptive.Configure(uint32(cfg.PoWAdaptiveTier2Failures), uint8(cfg.PoWAdaptiveTier2PenaltyBits))
		// Wire it into the proxy that SERVES the gate so Recommend (per-IP
		// fail-rate + load + tier-2) sets the difficulty; the web verify handler
		// records solve outcomes into the same tier (RecordFailure/Success).
		wp.AttachPoWAdaptive(powAdaptive)
		log.Printf("pow: adaptive tier-2 enabled (failures=%d penalty=%d bits)",
			cfg.PoWAdaptiveTier2Failures, cfg.PoWAdaptiveTier2PenaltyBits)
	}

	// Multi-dimensional rate limiter (IP / JA4 / cookie / query-keys).
	// Each dimension has its own budget; a request is rejected if any
	// budget is exceeded. Designed to defeat IP-rotating bots that
	// keep a stable JA4 / cookie, and value-rotating enumeration
	// attacks that keep a stable URL shape.
	var multiLim *limits.MultiLimiter
	if cfg.MultiLimitEnabled {
		multiLim = limits.NewMultiLimiter(limits.MultiConfig{
			Window:          time.Duration(cfg.MultiLimitWindowSec) * time.Second,
			IPBudget:        cfg.MultiLimitIPRPM,
			JA4Budget:       cfg.MultiLimitJA4RPM,
			CookieBudget:    cfg.MultiLimitCookieRPM,
			CookieName:      cfg.MultiLimitCookieName,
			QueryKeysBudget: cfg.MultiLimitQueryRPM,
			MaxEntries:      cfg.MultiLimitMaxEntries,
		})
		log.Printf("multi-limiter: enabled (window=%ds budgets ip=%d ja4=%d cookie=%d query=%d)",
			cfg.MultiLimitWindowSec, cfg.MultiLimitIPRPM, cfg.MultiLimitJA4RPM,
			cfg.MultiLimitCookieRPM, cfg.MultiLimitQueryRPM)
	}

	// Backup the starting config so operators have a rollback target even
	// if they haven't touched /api/config yet. Errors are logged but not
	// fatal — a missing snapshot directory shouldn't take the daemon down.
	if path, err := cfg.SnapshotToFile("config_backup", 10); err == nil {
		log.Printf("config snapshot saved: %s", path)
	} else {
		log.Printf("config snapshot failed: %v", err)
	}

	// Config hot-reload. We watch the loaded file (only if the operator
	// supplied one) and on change we recompile rules + push soft settings
	// like Mode and BlockThreshold to the running daemon. Things that can't
	// safely hot-swap — listen address, admin auth, SQLite paths — still
	// require a full restart, and the watcher silently leaves them alone.
	var cfgWatcher *config.Watcher
	if configPath != "" {
		cfgWatcher = config.NewWatcher(configPath, 5*time.Second, func(fresh *config.Config) {
			newRules := rules.DefaultRules()
			if fresh.CRSEnabled {
				newRules = append(newRules, rules.CRSRules()...)
			}
			compiled, err := rules.NewRuleSet(newRules)
			if err != nil {
				log.Printf("config hot-reload: rule compile failed, keeping existing rules: %v", err)
				return
			}
			eng.Reload(compiled)
			cfg.SetMode(fresh.Mode) // mode is atomic, no lock needed
			// Mutate the shared live fields under cfg's lock — the engine
			// reads them via cfg.Snapshot() (RLock) and the proxy via its
			// published snapshot, so an unlocked write here was a data race.
			cfg.Lock()
			cfg.BlockThreshold = fresh.BlockThreshold
			cfg.ParanoiaLevel = fresh.ParanoiaLevel
			cfg.RateLimitRPS = fresh.RateLimitRPS
			cfg.RateLimitBurst = fresh.RateLimitBurst
			cfg.TrustXFF = fresh.TrustXFF
			cfg.TrustedProxies = append([]string(nil), fresh.TrustedProxies...)
			// Shadow rule set is hot-reloadable: promoting a canaried rule to
			// enforcement (or shadowing a new one) is a single config edit, no
			// restart. The engine reads this via cfg.Snapshot() each evaluation.
			cfg.ShadowRuleIDs = append([]string(nil), fresh.ShadowRuleIDs...)
			cfg.Unlock()
			// Hot-swap the reputation policy (window/threshold/decay/jitter)
			// atomically. The Enabled flag and the persistence/restore wiring
			// are fixed at startup, so a reload only re-tunes live behaviour.
			if repEngine != nil {
				repEngine.SetConfig(reputationConfigFrom(fresh))
			}
			// Republish the proxy's hot-path config snapshot.
			wp.RefreshConfig()
			// Apply the fresh trust policy atomically. A bad CIDR keeps
			// the previous policy in place and surfaces in the log.
			if ipx := wp.IPExtractor(); ipx != nil {
				if err := ipx.Update(fresh.TrustXFF, fresh.TrustedProxies); err != nil {
					log.Printf("config hot-reload: trusted_proxies rejected: %v", err)
				}
			}
			log.Printf("config hot-reload: %d rules compiled, mode=%s paranoia=%d",
				compiled.Count(), fresh.Mode, fresh.ParanoiaLevel)
		})
		cfgWatcher.Start()
		defer cfgWatcher.Stop()
		log.Printf("config hot-reload watcher enabled for %s", configPath)
	}

	admin := web.NewServer(web.Deps{
		Config:         cfg,
		Metrics:        metrics,
		RulesFn:        rulesFn,
		BanList:        banList,
		Host:           hostCollector,
		Connection:     connMgr,
		SSL:            sslMgr,
		History:        historyStore,
		Proxy:          wp,
		SessionTracker: sessionTracker,
		GraphQL:        gqlValidator,
		Audit:          auditChain,
		PoW:            powIssuer,
		PoWAdaptive:    powAdaptive,
		Intel:          intelMgr,
		MultiLimit:     multiLim,
		MeshEnabled:    cfg.MeshEnabled,
		MeshPeers:      cfg.MeshPeers,
		MeshAPIKey:     cfg.MeshAPIKey,
	})

	// Watchdog — rotates through lightweight checks on the critical paths
	// and records failures into the Server's errors buffer.
	wdog := watchdog.New(15 * time.Second)
	wdog.OnFail(func(h watchdog.Health) {
		admin.RecordError("watchdog:"+h.Subsystem, h.Message, "")
	})
	wdog.Register("history", func(ctx context.Context) watchdog.Health {
		if historyStore == nil {
			return watchdog.Health{Status: watchdog.StatusOK, Message: "disabled"}
		}
		stats := historyStore.StatsSnapshot()
		if stats.CurrentPath == "" {
			return watchdog.Health{Status: watchdog.StatusFail, Message: "no active database"}
		}
		// Queue > 90% full is degraded; keep the cutoff generous.
		if stats.BufferedQueue > (cfg.HistoryBufferSize*9)/10 {
			return watchdog.Health{Status: watchdog.StatusDegraded, Message: "writer queue near capacity"}
		}
		return watchdog.Health{Status: watchdog.StatusOK, Message: "ok"}
	})
	wdog.Register("connection", func(ctx context.Context) watchdog.Health {
		if connMgr == nil {
			return watchdog.Health{Status: watchdog.StatusOK, Message: "disabled"}
		}
		st := connMgr.StatusSnapshot()
		if !st.Connected {
			return watchdog.Health{Status: watchdog.StatusDegraded, Message: "backend unreachable"}
		}
		return watchdog.Health{Status: watchdog.StatusOK, Message: "reachable"}
	})
	wdog.Register("host", func(ctx context.Context) watchdog.Health {
		if hostCollector == nil {
			return watchdog.Health{Status: watchdog.StatusOK, Message: "disabled"}
		}
		res := hostCollector.ResourcesSnapshot()
		if res.MemoryUsagePercent >= 95 {
			return watchdog.Health{Status: watchdog.StatusDegraded, Message: "memory over 95%"}
		}
		return watchdog.Health{Status: watchdog.StatusOK, Message: "ok"}
	})
	admin.AttachWatchdog(wdog)
	wdog.Start(rootCtx)
	defer wdog.Stop()

	adminMux := http.NewServeMux()
	admin.RegisterRoutes(adminMux)
	// ReadHeaderTimeout closes a Slowloris gap that ReadTimeout alone leaves
	// open when the client dribbles headers. IdleTimeout prevents kept-alive
	// idle connections from piling up — the admin server in particular has
	// the long-lived SSE /events/stream route, so we use a generous one.
	adminServer := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           adminMux,
		ReadTimeout:       time.Duration(cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(cfg.WriteTimeoutSec) * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	proxyServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wp,
		ReadTimeout:       time.Duration(cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(cfg.WriteTimeoutSec) * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Native TLS termination, opt-in. The SSL manager owns the cert
	// pairs + TLS policy; we ask it for a *tls.Config and only flip
	// the proxy server to TLS when ssl_config.enabled is true AND
	// at least one cert is loaded.
	//
	// Failure-mode policy: when the operator has turned the feature
	// ON we refuse to start without TLS. The previous behaviour was
	// to log + fall back to plaintext, but a silent downgrade after
	// a cert-file corruption is exactly the kind of misconfiguration
	// that's invisible until the next traffic capture proves it.
	// Fail-fast forces the operator to fix the cert before traffic
	// flows. When the feature is off the proxy serves plaintext as
	// normal.
	proxyTLSEnabled := false
	if sslMgr != nil && sslMgr.ConfigSnapshot().Enabled {
		if !sslMgr.HasUsableCerts() {
			log.Fatalf("ssl: ssl_config.enabled=true but no usable certs are loaded — refusing to start " +
				"so the proxy doesn't silently downgrade to plaintext")
		}
		tlsCfg, err := sslMgr.BuildTLSConfig()
		if err != nil {
			log.Fatalf("ssl: BuildTLSConfig failed (%v) — refusing to start a TLS-enabled WAF without TLS", err)
		}
		if tlsCfg == nil {
			// Defensive: HasUsableCerts is true but BuildTLSConfig
			// returned nil. That's a code-level inconsistency, not
			// an operator error, but still refuse to silently
			// downgrade.
			log.Fatalf("ssl: BuildTLSConfig returned nil despite HasUsableCerts=true — internal inconsistency")
		}
		if jaCache != nil {
			wrapped, hooked, jerr := proxy.JA3TLSConfig(tlsCfg, jaCache)
			if jerr != nil {
				log.Printf("ssl: JA3TLSConfig wrap failed (%v); using plain TLS without JA3 capture", jerr)
			} else if hooked {
				tlsCfg = wrapped
			}
		}
		proxyServer.TLSConfig = tlsCfg
		proxyTLSEnabled = true
		log.Printf("ssl: native TLS enabled — min_version=%s, certs=%d",
			sslMgr.ConfigSnapshot().MinTLSVersion, len(sslMgr.List()))
	}

	var egressServer *http.Server
	if cfg.EgressEnabled {
		ep := proxy.NewEgressProxy(cfg, eng, metrics, banList)
		egressServer = &http.Server{
			Addr:              cfg.EgressAddr,
			Handler:           ep,
			ReadTimeout:       time.Duration(cfg.ReadTimeoutSec) * time.Second,
			WriteTimeout:      time.Duration(cfg.WriteTimeoutSec) * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		core.SafeGo("egress-server", func() {
			log.Printf("egress proxy listening on http://%s", cfg.EgressAddr)
			if err := egressServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("egress server error: %v", err)
			}
		})
	}

	stopSampler := startTrafficSampler(metrics)

	meshStopCh := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	core.SafeGo("admin-server", func() {
		// WEWAF no longer ships a bundled dashboard — it is operated from
		// ypanel (the Yuril control panel) at its own subdomain. The admin
		// port serves the JSON API, /metrics, and the SSE stream that the
		// ypanel reporter consumes; opening the old dashboard URL on this
		// port redirects the operator to ypanel.
		log.Printf("admin API listening on http://%s — operate this node from ypanel: %s",
			cfg.AdminAddr, cfg.YpanelURL)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server error: %v", err)
		}
	})

	core.SafeGo("proxy-server", func() {
		// ListenAndServeTLS("", "") tells net/http to use the
		// pre-built proxyServer.TLSConfig (Certificates +
		// GetCertificate) instead of reading cert/key files. Empty
		// strings are the documented "use existing config" form.
		var serveErr error
		if proxyTLSEnabled {
			log.Printf("WAF proxy listening on https://%s -> %s", cfg.ListenAddr, cfg.BackendURL)
			serveErr = proxyServer.ListenAndServeTLS("", "")
		} else {
			log.Printf("WAF proxy listening on http://%s -> %s", cfg.ListenAddr, cfg.BackendURL)
			serveErr = proxyServer.ListenAndServe()
		}
		if err := serveErr; err != nil && err != http.ErrServerClosed {
			log.Printf("proxy server error: %v", err)
			// Non-blocking — if the main loop is already shutting down on a
			// real signal, an unconditional send would leak this goroutine.
			select {
			case sigCh <- os.Interrupt:
			default:
			}
		}
	})

	if cfg.MeshEnabled {
		core.SafeGo("mesh-gossip", func() {
			interval := time.Duration(cfg.MeshGossipIntervalSec) * time.Second
			if interval <= 0 {
				interval = 60 * time.Second
			}
			// Dedicated client with a hard timeout so a peer that stalls its
			// TLS handshake doesn't hang this goroutine per tick; also gives
			// us a bounded connection pool separate from DefaultClient.
			meshTimeout := time.Duration(cfg.MeshSyncTimeoutSec) * time.Second
			if meshTimeout <= 0 {
				meshTimeout = 10 * time.Second
			}
			meshClient := &http.Client{
				Timeout: meshTimeout,
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout:   3 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					MaxIdleConns:          16,
					MaxIdleConnsPerHost:   2,
					MaxConnsPerHost:       4,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   5 * time.Second,
					ResponseHeaderTimeout: meshTimeout,
					ExpectContinueTimeout: 1 * time.Second,
				},
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					localBans := banList.List()
					payload := map[string]interface{}{"bans": localBans}
					body, err := json.Marshal(payload)
					if err != nil {
						log.Printf("mesh gossip: failed to marshal bans: %v", err)
						continue
					}
					for _, peerURL := range cfg.MeshPeers {
						if peerURL == "" {
							continue
						}
						syncURL := strings.TrimSuffix(peerURL, "/") + "/api/mesh/sync"
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MeshSyncTimeoutSec)*time.Second)
						req, err := http.NewRequestWithContext(ctx, http.MethodPost, syncURL, bytes.NewReader(body))
						if err != nil {
							cancel()
							log.Printf("mesh gossip: failed to create request for %s: %v", peerURL, err)
							continue
						}
						req.Header.Set("Content-Type", "application/json")
						if cfg.MeshAPIKey != "" {
							req.Header.Set("X-Mesh-Key", cfg.MeshAPIKey)
						}

						resp, err := meshClient.Do(req)
						cancel()
						if err != nil {
							log.Printf("mesh gossip: peer %s sync error: %v", peerURL, err)
							continue
						}

						// Bound the decoded body so a malicious peer cannot OOM
						// the daemon. Reading one byte past the cap lets us
						// detect the overflow case explicitly.
						limited := io.LimitReader(resp.Body, meshMaxResponseBytes+1)
						raw, readErr := io.ReadAll(limited)
						resp.Body.Close()
						if readErr != nil {
							log.Printf("mesh gossip: peer %s body read error: %v", peerURL, readErr)
							continue
						}
						if int64(len(raw)) > meshMaxResponseBytes {
							log.Printf("mesh gossip: peer %s response exceeded %d bytes, dropping", peerURL, meshMaxResponseBytes)
							continue
						}
						var result struct {
							Status string          `json:"status"`
							Bans   []core.BanEntry `json:"bans"`
						}
						if err := json.Unmarshal(raw, &result); err != nil {
							log.Printf("mesh gossip: peer %s decode error: %v", peerURL, err)
							continue
						}

						if resp.StatusCode == http.StatusOK && result.Status == "synced" {
							// Cap inbound ban durations at the operator's
							// configured maximum (or 30 days) so a peer can't
							// pin an IP to year-9999 expiry. Truncate the
							// reason for the same reason — UI memory pressure.
							maxDur := time.Duration(cfg.MaxBanDurationSec) * time.Second
							if maxDur <= 0 {
								maxDur = 30 * 24 * time.Hour
							}
							for _, b := range result.Bans {
								if b.IP == "" || net.ParseIP(b.IP) == nil {
									continue
								}
								duration := time.Until(b.ExpiresAt)
								if duration <= 0 {
									continue
								}
								if duration > maxDur {
									duration = maxDur
								}
								reason := b.Reason
								if len(reason) > 256 {
									reason = reason[:256]
								}
								banList.Ban(b.IP, reason, duration)
							}
							log.Printf("mesh gossip: peer %s synced, received %d bans", peerURL, len(result.Bans))
						} else {
							log.Printf("mesh gossip: peer %s returned status %d (status=%q)",
								peerURL, resp.StatusCode, result.Status)
						}
					}
				case <-meshStopCh:
					return
				}
			}
		})
	}

	<-sigCh
	log.Println("shutdown signal received, gracefully stopping...")

	close(meshStopCh)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("admin server shutdown error: %v", err)
	}
	if err := proxyServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("proxy server shutdown error: %v", err)
	}
	if egressServer != nil {
		if err := egressServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("egress server shutdown error: %v", err)
		}
	}
	stopSampler()
	log.Println("WEWaf stopped")
}

// startTrafficSampler periodically snapshots request counters for the dashboard graph.
// Ticks every 10s so the bandwidth rate refreshes quickly enough for a live
// view, while keeping persisted traffic_points bounded.
func startTrafficSampler(m *telemetry.Metrics) func() {
	ticker := time.NewTicker(10 * time.Second)
	stop := make(chan struct{})
	var lastReq, lastBlocked uint64
	go func() {
		for {
			select {
			case <-ticker.C:
				snap := m.Snapshot()
				currReq, _ := snap["total_requests"].(uint64)
				currBlocked, _ := snap["blocked_requests"].(uint64)
				var reqDelta, blockedDelta int
				if currReq >= lastReq {
					reqDelta = int(currReq - lastReq)
				}
				if currBlocked >= lastBlocked {
					blockedDelta = int(currBlocked - lastBlocked)
				}
				m.AddTrafficPoint(reqDelta, blockedDelta)
				lastReq = currReq
				lastBlocked = currBlocked
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(stop) }
}

// isWildcardListenAddr reports whether addr binds to every available
// interface. Recognises the ":port" form (Go's net/http convention),
// the explicit "0.0.0.0:port" / "[::]:port" forms, and the bare
// IPv6-zero. Anything else (loopback, private addresses, DNS-only
// hostnames) is treated as a more conservative choice and not warned
// about. Cross-platform: Windows + Linux + BSD all use the same set
// of zero-address representations here.
func isWildcardListenAddr(addr string) bool {
	if addr == "" {
		return true // net/http defaults to ":http" when blank — wildcard
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Single-port form like ":8443" doesn't have a host — treat as
		// wildcard. Anything else that fails the split is unknown
		// shape; refuse to warn rather than cry wolf.
		if strings.HasPrefix(addr, ":") {
			return true
		}
		return false
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

// isLoopbackListenAddr reports whether addr binds ONLY to the loopback
// interface (127.0.0.0/8, ::1, or "localhost"). Used to gate the
// WAF_ALLOW_NO_AUTH dev escape hatch — disabling admin auth is only
// acceptable when nothing off-box can reach the admin port.
func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// ":8443" / no-host form binds the wildcard, not loopback.
		return false
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

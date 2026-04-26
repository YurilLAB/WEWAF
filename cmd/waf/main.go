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
	"strings"
	"syscall"
	"time"

	"wewaf/internal/audit"
	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/graphql"
	"wewaf/internal/history"
	"wewaf/internal/host"
	"wewaf/internal/intel"
	"wewaf/internal/ja3"
	"wewaf/internal/limits"
	"wewaf/internal/pow"
	"wewaf/internal/proxy"
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

	// Attach persistence to the telemetry hot path.
	metrics.SetPersister(newHistoryPersister(historyStore))
	historyStore.OnRotate(func(_ time.Time) {
		metrics.OnRotation()
		log.Printf("history rotated: new db=%s", historyStore.StatsSnapshot().CurrentPath)
	})

	bf := bruteforce.NewDetector(time.Duration(cfg.BruteForceWindowSec) * time.Second)
	defer bf.Stop()

	// Session tracker — foundation for anomaly scoring and browser challenge.
	sessionTracker := session.NewTracker(session.Config{
		Secret:             cfg.SessionCookieSecret,
		MaxSessions:        cfg.SessionMaxSessions,
		IdleTTL:            time.Duration(cfg.SessionIdleTTLSec) * time.Second,
		Enabled:            cfg.SessionTrackingEnabled,
		RequestRateCeiling: cfg.SessionRequestRateCeiling,
		PathCountCeiling:   cfg.SessionPathCountCeiling,
		TrustXFF:           cfg.TrustXFF,
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
	wp.AttachSessionTracker(sessionTracker)
	wp.AttachGraphQLValidator(gqlValidator)

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
	if cfg.JA3Enabled {
		jaCache := ja3.NewCache(cfg.JA3CacheCapacity, time.Duration(cfg.JA3CacheTTLSec)*time.Second)
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
					banList.Ban(e.Value, reason, 7*24*time.Hour)
					ipBatch++
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
			cfg.SetMode(fresh.Mode)
			cfg.BlockThreshold = fresh.BlockThreshold
			cfg.ParanoiaLevel = fresh.ParanoiaLevel
			cfg.RateLimitRPS = fresh.RateLimitRPS
			cfg.RateLimitBurst = fresh.RateLimitBurst
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
		log.Printf("admin dashboard listening on http://%s", cfg.AdminAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server error: %v", err)
		}
	})

	core.SafeGo("proxy-server", func() {
		log.Printf("WAF proxy listening on http://%s -> %s", cfg.ListenAddr, cfg.BackendURL)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

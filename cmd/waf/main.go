package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/connection"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/history"
	"wewaf/internal/host"
	"wewaf/internal/limits"
	"wewaf/internal/proxy"
	"wewaf/internal/rules"
	"wewaf/internal/ssl"
	"wewaf/internal/telemetry"
	"wewaf/internal/watchdog"
	"wewaf/internal/web"
)

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

	wp, err := proxy.NewWAFProxy(cfg, eng, metrics, bf)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
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
	stopBanCleanup := banList.StartCleanup(time.Minute)
	defer stopBanCleanup()

	// Backup the starting config so operators have a rollback target even
	// if they haven't touched /api/config yet. Errors are logged but not
	// fatal — a missing snapshot directory shouldn't take the daemon down.
	if path, err := cfg.SnapshotToFile("config_backup", 10); err == nil {
		log.Printf("config snapshot saved: %s", path)
	} else {
		log.Printf("config snapshot failed: %v", err)
	}

	admin := web.NewServer(web.Deps{
		Config:      cfg,
		Metrics:     metrics,
		RulesFn:     rulesFn,
		BanList:     banList,
		Host:        hostCollector,
		Connection:  connMgr,
		SSL:         sslMgr,
		History:     historyStore,
		Proxy:       wp,
		MeshEnabled: cfg.MeshEnabled,
		MeshPeers:   cfg.MeshPeers,
		MeshAPIKey:  cfg.MeshAPIKey,
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
	adminServer := &http.Server{
		Addr:         cfg.AdminAddr,
		Handler:      adminMux,
		ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
	}

	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      wp,
		ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
	}

	var egressServer *http.Server
	if cfg.EgressEnabled {
		ep := proxy.NewEgressProxy(cfg, eng, metrics, banList)
		egressServer = &http.Server{
			Addr:         cfg.EgressAddr,
			Handler:      ep,
			ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
			WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
		}
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("egress server panic: %v", rec)
				}
			}()
			log.Printf("egress proxy listening on http://%s", cfg.EgressAddr)
			if err := egressServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("egress server error: %v", err)
			}
		}()
	}

	stopSampler := startTrafficSampler(metrics)

	meshStopCh := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("admin server panic: %v", rec)
			}
		}()
		log.Printf("admin dashboard listening on http://%s", cfg.AdminAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server error: %v", err)
		}
	}()

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("proxy server panic: %v", rec)
			}
		}()
		log.Printf("WAF proxy listening on http://%s -> %s", cfg.ListenAddr, cfg.BackendURL)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("proxy server error: %v", err)
			sigCh <- os.Interrupt
		}
	}()

	if cfg.MeshEnabled {
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("mesh gossip panic: %v", rec)
				}
			}()
			ticker := time.NewTicker(time.Duration(cfg.MeshGossipIntervalSec) * time.Second)
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

						resp, err := http.DefaultClient.Do(req)
						cancel()
						if err != nil {
							log.Printf("mesh gossip: peer %s sync error: %v", peerURL, err)
							continue
						}

						var result struct {
							Status string          `json:"status"`
							Bans   []core.BanEntry `json:"bans"`
						}
						if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
							resp.Body.Close()
							log.Printf("mesh gossip: peer %s decode error: %v", peerURL, err)
							continue
						}
						resp.Body.Close()

						if resp.StatusCode == http.StatusOK {
							for _, b := range result.Bans {
								if b.IP == "" || net.ParseIP(b.IP) == nil {
									continue
								}
								duration := time.Until(b.ExpiresAt)
								if duration <= 0 {
									continue
								}
								banList.Ban(b.IP, b.Reason, duration)
							}
							log.Printf("mesh gossip: peer %s synced, received %d bans", peerURL, len(result.Bans))
						} else {
							log.Printf("mesh gossip: peer %s returned status %d", peerURL, resp.StatusCode)
						}
					}
				case <-meshStopCh:
					return
				}
			}
		}()
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

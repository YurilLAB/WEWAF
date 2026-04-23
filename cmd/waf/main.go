package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	rs, err := rules.NewRuleSet(rawRules)
	if err != nil {
		log.Fatalf("failed to compile rules: %v", err)
	}
	log.Printf("rules compiled: %d signatures loaded", rs.Count())

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
			out = append(out, map[string]interface{}{
				"id":          cr.ID,
				"name":        cr.Name,
				"phase":       cr.Phase.String(),
				"action":      cr.Action.String(),
				"score":       cr.Score,
				"description": cr.Description,
			})
		}
		return out
	}
	banList := core.NewBanList()
	stopBanCleanup := banList.StartCleanup(time.Minute)
	defer stopBanCleanup()

	admin := web.NewServer(web.Deps{
		Config:     cfg,
		Metrics:    metrics,
		RulesFn:    rulesFn,
		BanList:    banList,
		Host:       hostCollector,
		Connection: connMgr,
		SSL:        sslMgr,
		History:    historyStore,
	})
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

	stopSampler := startTrafficSampler(metrics)

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

	<-sigCh
	log.Println("shutdown signal received, gracefully stopping...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("admin server shutdown error: %v", err)
	}
	if err := proxyServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("proxy server shutdown error: %v", err)
	}
	stopSampler()
	log.Println("WEWaf stopped")
}

// startTrafficSampler periodically snapshots request counters for the dashboard graph.
func startTrafficSampler(m *telemetry.Metrics) func() {
	ticker := time.NewTicker(30 * time.Second)
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

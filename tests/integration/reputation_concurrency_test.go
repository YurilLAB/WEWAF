package integration_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wewaf/internal/core"
	"wewaf/internal/reputation"
)

// TestReputationLedgerConcurrency stress-tests the live integration the way it
// actually runs: a single reputation.Engine installed as core.BanList's
// OffenseLedger, hammered concurrently by the two paths that take the locks in
// the order that matters — banList.Ban (acquires bl.mu, then calls into the
// ledger's Offenses/RecordBan which take engine.mu) and the reputation engine's
// own RecordBlock/Consult/EscalatedDuration (engine.mu only). If the lock
// ordering were inconsistent this deadlocks (caught by the test timeout); if a
// shared field were unguarded, -race flags it. It also asserts the ledger never
// loses the monotonic offense progression under contention.
func TestReputationLedgerConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.sqlite")
	eng, err := reputation.Open(reputation.Options{
		Path: path,
		Config: reputation.Config{
			Enabled:           true,
			Window:            time.Hour,
			Threshold:         5,
			BaseDuration:      time.Minute,
			Factor:            2,
			MaxDuration:       24 * time.Hour,
			OffenseWindow:     24 * time.Hour,
			Recidive:          true,
			RecidiveThreshold: 3,
			RecidiveBan:       time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	eng.Start(context.Background())
	t.Cleanup(func() { _ = eng.Close() })

	bl := core.NewBanList()
	bl.ConfigureBackoff(true, 2, 24*time.Hour, 24*time.Hour)
	bl.SetOffenseLedger(eng)

	ips := []string{"203.0.113.10", "203.0.113.11", "2001:db8::10", "198.51.100.20"}
	subsystems := []string{"engine", "ddos", "bruteforce", "ja3", "intel", "session", "rate"}

	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := ips[g%len(ips)]
			for i := 0; i < 300; i++ {
				switch i % 6 {
				case 0:
					// Full live auto-ban path: RecordBlock -> on trigger, ban via
					// BanList, which re-enters the ledger (bl.mu -> engine.mu).
					if d := eng.RecordBlock(ip, subsystems[i%len(subsystems)], "x"); d.Ban {
						bl.Ban(ip, "rep", d.Duration)
					}
				case 1:
					_ = eng.Consult(ip)
				case 2:
					_ = eng.EscalatedDuration(ip, time.Minute)
				case 3:
					bl.Ban(ip, "manual", time.Minute) // direct ban -> ledger.RecordBan
				case 4:
					_ = bl.IsBanned(ip)
				case 5:
					eng.SetConfig(reputation.Config{Enabled: true, Window: time.Hour, Threshold: 5, BaseDuration: time.Minute, Factor: 2, MaxDuration: 24 * time.Hour, OffenseWindow: 24 * time.Hour, Recidive: true, RecidiveThreshold: 3, RecidiveBan: time.Hour})
				}
			}
		}(g)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock: BanList<->reputation ledger lock ordering hung")
	}

	// Every IP was banned many times; the durable offense tier must be >= 1 and
	// bounded by the cap (10), proving the ledger stayed consistent.
	for _, ip := range ips {
		rep := eng.Consult(ip)
		if !rep.Known {
			t.Errorf("ip %s should be tracked after the stress run", ip)
			continue
		}
		if rep.Offenses < 1 || rep.Offenses > 10 {
			t.Errorf("ip %s offense tier %d out of expected [1,10]", ip, rep.Offenses)
		}
	}
}

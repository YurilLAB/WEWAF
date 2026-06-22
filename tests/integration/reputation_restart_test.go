package integration_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"wewaf/internal/clientip"
	"wewaf/internal/core"
	"wewaf/internal/reputation"
)

// TestReputationSurvivesRestart is the end-to-end proof that the durable
// reputation ledger closes WEWAF's restart-amnesia gap: an offender's escalation
// tier AND their active ban both survive a simulated daemon restart, so a
// returning attacker keeps climbing the ban ladder instead of starting fresh.
func TestReputationSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.sqlite")
	repCfg := reputation.Config{
		Enabled:       true,
		Factor:        2.0,
		BaseDuration:  time.Hour,
		MaxDuration:   1000 * time.Hour,
		OffenseWindow: 24 * time.Hour,
	}
	const victimIP = "203.0.113.77"
	key := clientip.NormalizeIPKey(victimIP)

	// ---- first run: two bans escalate the offender to tier 2 ----
	eng1, err := reputation.Open(reputation.Options{Path: path, Config: repCfg})
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	eng1.Start(context.Background())

	bl1 := core.NewBanList()
	bl1.ConfigureBackoff(true, 2, 24*time.Hour, 1000*time.Hour)
	bl1.SetOffenseLedger(eng1)

	bl1.Ban(victimIP, "x", time.Hour) // tier 1
	bl1.Ban(victimIP, "x", time.Hour) // tier 2
	if tier := banTier(bl1, key); tier != 2 {
		t.Fatalf("pre-restart offense tier got %d want 2", tier)
	}
	if err := eng1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	// ---- simulated restart: reopen the ledger from disk ----
	eng2, err := reputation.Open(reputation.Options{Path: path, Config: repCfg})
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	eng2.Start(context.Background())
	t.Cleanup(func() { _ = eng2.Close() })

	bl2 := core.NewBanList()
	bl2.ConfigureBackoff(true, 2, 24*time.Hour, 1000*time.Hour)
	bl2.SetOffenseLedger(eng2)

	// The active ban from before the restart must be re-seeded.
	restored := eng2.RestoreActive()
	reapplied := 0
	for _, b := range restored {
		if bl2.RestoreBan(b.Key, b.Reason, b.ExpiresAt, b.Offenses) {
			reapplied++
		}
	}
	if reapplied != 1 {
		t.Fatalf("expected 1 active ban restored across restart, got %d", reapplied)
	}
	if !bl2.IsBanned(victimIP) {
		t.Fatalf("offender should still be banned immediately after restart")
	}

	// The escalation memory must persist: the NEXT ban is tier 3, not tier 1.
	bl2.Ban(victimIP, "x", time.Hour)
	if tier := banTier(bl2, key); tier != 3 {
		t.Fatalf("post-restart offense tier got %d want 3 (escalation amnesia!)", tier)
	}
}

func banTier(bl *core.BanList, key string) int {
	for _, e := range bl.List() {
		if e.IP == key {
			return e.Offenses
		}
	}
	return 0
}

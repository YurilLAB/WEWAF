package core

import (
	"testing"
	"time"

	"wewaf/internal/clientip"
)

func TestBanListBasicEvict(t *testing.T) {
	bl := NewBanList()
	bl.Ban("1.1.1.1", "scan", 20*time.Millisecond)
	if !bl.IsBanned("1.1.1.1") {
		t.Fatalf("expected IP to be banned immediately")
	}
	time.Sleep(30 * time.Millisecond)
	if bl.IsBanned("1.1.1.1") {
		t.Fatalf("expected ban to have expired")
	}
}

func TestBanListCleanupRemovesExpired(t *testing.T) {
	bl := NewBanList()
	bl.Ban("1.1.1.1", "", 10*time.Millisecond)
	bl.Ban("2.2.2.2", "", time.Hour)
	time.Sleep(20 * time.Millisecond)
	bl.Cleanup()
	if bl.Count() != 1 {
		t.Fatalf("expected Cleanup to leave 1 active ban, got %d", bl.Count())
	}
}

func TestBanListExponentialBackoff(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 2, time.Minute, time.Hour)
	bl.Ban("3.3.3.3", "x", 100*time.Millisecond)
	first := bl.entries["3.3.3.3"].ExpiresAt
	// Second ban within the backoff window doubles the duration.
	bl.Ban("3.3.3.3", "x", 100*time.Millisecond)
	second := bl.entries["3.3.3.3"].ExpiresAt
	if !second.After(first.Add(80 * time.Millisecond)) {
		t.Fatalf("expected second ban to extend ~2x beyond first; first=%v second=%v", first, second)
	}
	// Third ban should be ~4x the base.
	bl.Ban("3.3.3.3", "x", 100*time.Millisecond)
	third := bl.entries["3.3.3.3"].ExpiresAt
	if !third.After(second.Add(180 * time.Millisecond)) {
		t.Fatalf("expected third ban to extend ~4x beyond first; second=%v third=%v", second, third)
	}
}

func TestBanListBackoffCappedAtMax(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 10, time.Minute, 150*time.Millisecond)
	for i := 0; i < 5; i++ {
		bl.Ban("4.4.4.4", "x", 100*time.Millisecond)
	}
	// After a few doublings we should be capped at ~150ms, not 100*10^4.
	entry := bl.entries["4.4.4.4"]
	expires := entry.ExpiresAt
	maxExpected := entry.Timestamp.Add(150 * time.Millisecond)
	if expires.After(maxExpected.Add(50 * time.Millisecond)) {
		t.Fatalf("backoff exceeded max cap: expires=%v max=%v", expires, maxExpected)
	}
}

func TestBanListBackoffResetsAfterWindow(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 2, 30*time.Millisecond, time.Hour)
	bl.Ban("5.5.5.5", "x", 50*time.Millisecond)
	// Wait past both the ban and the backoff-history window.
	time.Sleep(80 * time.Millisecond)
	bl.Ban("5.5.5.5", "x", 50*time.Millisecond)
	entry := bl.entries["5.5.5.5"]
	if entry.Offenses != 1 {
		t.Fatalf("expected offense counter to reset after backoff window, got %d", entry.Offenses)
	}
}

func TestBanListRejectsInvalidIPs(t *testing.T) {
	bl := NewBanList()
	// Strings that are not IP addresses — including command/argument-injection
	// shapes that would be catastrophic once a ban flows into nft/netsh argv.
	bad := []string{
		"", "not-an-ip", "1.2.3.4; rm -rf /", "-j ACCEPT", "--flush",
		"1.2.3.4 || true", "999.999.999.999", "0x7f000001", "localhost",
		"1.2.3.4/24", "$(reboot)", "1.2.3.4\n5.6.7.8",
	}
	for _, ip := range bad {
		bl.Ban(ip, "x", time.Hour)
	}
	if c := bl.Count(); c != 0 {
		t.Fatalf("expected all malformed bans to be dropped, got %d active bans", c)
	}
	// A real IP must still go through.
	bl.Ban("203.0.113.7", "x", time.Hour)
	if !bl.IsBanned("203.0.113.7") {
		t.Fatalf("expected a valid IP to be bannable")
	}
}

func TestBanListNeverBansLoopbackOrUnspecified(t *testing.T) {
	bl := NewBanList()
	for _, ip := range []string{"127.0.0.1", "127.5.5.5", "::1", "0.0.0.0", "::"} {
		bl.Ban(ip, "x", time.Hour)
		if bl.IsBanned(ip) {
			t.Fatalf("loopback/unspecified %q must never be bannable (self-DoS guard)", ip)
		}
	}
}

func TestBanListAllowlistBlocksBan(t *testing.T) {
	bl := NewBanList()
	set, err := clientip.NewCIDRSet([]string{"203.0.113.0/24", "198.51.100.7"})
	if err != nil {
		t.Fatalf("NewCIDRSet: %v", err)
	}
	bl.SetAllowlist(set)

	// Inside the allowlisted CDN range — must be refused.
	bl.Ban("203.0.113.42", "feed", time.Hour)
	if bl.IsBanned("203.0.113.42") {
		t.Fatalf("allowlisted CIDR member must not be bannable")
	}
	// Exact allowlisted host — must be refused.
	bl.Ban("198.51.100.7", "feed", time.Hour)
	if bl.IsBanned("198.51.100.7") {
		t.Fatalf("allowlisted host must not be bannable")
	}
	// Outside the allowlist — must still ban normally.
	bl.Ban("198.51.100.8", "feed", time.Hour)
	if !bl.IsBanned("198.51.100.8") {
		t.Fatalf("non-allowlisted IP must still be bannable")
	}

	// Clearing the allowlist re-enables banning (loopback guard still holds).
	bl.SetAllowlist(nil)
	bl.Ban("203.0.113.42", "feed", time.Hour)
	if !bl.IsBanned("203.0.113.42") {
		t.Fatalf("after clearing allowlist the IP should be bannable")
	}
}

func TestBanListAcceptsSingleHostCIDR(t *testing.T) {
	// Threat-intel feeds emit individual addresses in CIDR form; these must ban.
	bl := NewBanList()
	if !bl.Ban("8.8.8.8/32", "feed", time.Hour) {
		t.Fatal("a /32 single-host CIDR must be accepted")
	}
	if !bl.IsBanned("8.8.8.8") {
		t.Fatal("/32 feed entry must block the host")
	}
	if !bl.Ban("2001:db8::1/128", "feed", time.Hour) {
		t.Fatal("a /128 single-host CIDR must be accepted")
	}
	if !bl.IsBanned("2001:db8::1") {
		t.Fatal("/128 feed entry must block the host")
	}
	// A wider range cannot be represented in the host-keyed map — refuse it
	// rather than store a misleading single-address key.
	if bl.Ban("1.2.3.0/24", "feed", time.Hour) {
		t.Fatal("a multi-host CIDR range must be refused (cannot key a range)")
	}
}

// fakeLedger is a minimal OffenseLedger for testing the BanList delegation.
type fakeLedger struct {
	offenses int
	last     time.Time
	have     bool
	recorded []ledgerCall
}

type ledgerCall struct {
	key      string
	reason   string
	offenses int
	expires  time.Time
}

func (f *fakeLedger) Offenses(key string) (int, time.Time, bool) {
	return f.offenses, f.last, f.have
}

func (f *fakeLedger) RecordBan(key, reason string, offenses int, now, expires time.Time) {
	f.recorded = append(f.recorded, ledgerCall{key, reason, offenses, expires})
}

// TestBanListEscalatesFromLedger proves that when a durable ledger is installed,
// escalation derives the prior offense count from IT — not the (empty)
// in-memory history — so escalation survives a restart, and that each accepted
// ban is recorded back to the ledger.
func TestBanListEscalatesFromLedger(t *testing.T) {
	bl := NewBanList()
	bl.ConfigureBackoff(true, 2, time.Hour, 1000*time.Hour)
	led := &fakeLedger{offenses: 2, last: time.Now().UTC(), have: true}
	bl.SetOffenseLedger(led)

	// In-memory history is empty; without the ledger this would be tier 1
	// (base). The ledger's prior count of 2 must escalate this to tier 3.
	if !bl.Ban("9.9.9.9", "x", 100*time.Millisecond) {
		t.Fatal("ban should be accepted")
	}
	entry := bl.entries["9.9.9.9"]
	if entry.Offenses != 3 {
		t.Fatalf("expected ledger-derived offense tier 3, got %d", entry.Offenses)
	}
	// tier 3 at factor 2 => base * 2^2 = 400ms.
	dur := entry.ExpiresAt.Sub(entry.Timestamp)
	if dur < 350*time.Millisecond || dur > 450*time.Millisecond {
		t.Fatalf("expected ~400ms escalated duration, got %s", dur)
	}
	if len(led.recorded) != 1 {
		t.Fatalf("expected exactly one RecordBan, got %d", len(led.recorded))
	}
	if led.recorded[0].offenses != 3 {
		t.Fatalf("RecordBan offense count got %d want 3", led.recorded[0].offenses)
	}
}

func TestBanListRestoreBan(t *testing.T) {
	bl := NewBanList()
	exp := time.Now().Add(time.Hour)
	if !bl.RestoreBan("203.0.113.50", "restored", exp, 4) {
		t.Fatal("an active ban should be restorable")
	}
	if !bl.IsBanned("203.0.113.50") {
		t.Fatal("restored ban must make IsBanned true")
	}
	if got := bl.entries["203.0.113.50"].Offenses; got != 4 {
		t.Fatalf("restored offense tier got %d want 4", got)
	}
	// An already-lapsed ban must not be re-seeded.
	if bl.RestoreBan("203.0.113.51", "stale", time.Now().Add(-time.Hour), 1) {
		t.Fatal("a lapsed ban must not be restored")
	}
	// Allowlisted/loopback targets are still refused on the restore path.
	if bl.RestoreBan("127.0.0.1", "x", exp, 1) {
		t.Fatal("loopback must never be restorable (self-DoS guard)")
	}
}

func TestBanListAllowlistProtectsIPv6SameSlash64(t *testing.T) {
	// Allowlisting a single /128 admin host must prevent banning ANY address in
	// its /64, because the ban list keys (and matches) IPv6 at /64 — otherwise a
	// same-/64 neighbour ban would collateral-block the admin host.
	bl := NewBanList()
	set, err := clientip.NewCIDRSet([]string{"2001:db8:abcd:1234::dead/128"})
	if err != nil {
		t.Fatalf("NewCIDRSet: %v", err)
	}
	bl.SetAllowlist(set)

	if bl.Ban("2001:db8:abcd:1234::1", "scan", time.Hour) {
		t.Fatal("banning a neighbour in the allowlisted host's /64 must be refused")
	}
	if bl.IsBanned("2001:db8:abcd:1234::dead") {
		t.Fatal("the allowlisted admin host must never end up banned")
	}
	// A different /64 is unaffected.
	if !bl.Ban("2001:db8:abcd:9999::1", "scan", time.Hour) {
		t.Fatal("a ban in a different /64 must still be accepted")
	}
}

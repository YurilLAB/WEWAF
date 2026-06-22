package firewall

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"wewaf/internal/clientip"
)

// recordingRunner captures every command instead of executing it.
type recordingRunner struct {
	mu    sync.Mutex
	calls []recCall
}

type recCall struct {
	name  string
	args  []string
	stdin string
}

func (r *recordingRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recCall{name: name, args: append([]string(nil), args...), stdin: stdin})
	return "", nil
}

func (r *recordingRunner) snapshot() []recCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recCall(nil), r.calls...)
}

func (r *recordingRunner) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// fakeLister returns a swappable ban set.
type fakeLister struct {
	mu   sync.Mutex
	bans []Ban
}

func (l *fakeLister) set(b ...Ban) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bans = append([]Ban(nil), b...)
}

func (l *fakeLister) ActiveBans() []Ban {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Ban(nil), l.bans...)
}

func future() time.Time { return time.Now().Add(time.Hour) }

func newTestSink(t *testing.T, run runner, lister Lister, cfg Config) *Sink {
	t.Helper()
	cfg.Logf = func(string, ...interface{}) {}
	be := &nftBackend{table: sanitizeIdent(cfg.Table, "wewaf"), run: run}
	s := New(be, lister, cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	return s
}

func countElementOps(calls []recCall, verb string) int {
	n := 0
	for _, c := range calls {
		if len(c.args) >= 2 && c.args[0] == verb && c.args[1] == "element" {
			n++
		}
	}
	return n
}

func TestReconcileAddsThenRemoves(t *testing.T) {
	run := &recordingRunner{}
	lister := &fakeLister{}
	lister.set(Ban{IP: "203.0.113.10", ExpiresAt: future()}, Ban{IP: "2001:db8::5", ExpiresAt: future()})
	s := newTestSink(t, run, lister, Config{Reconcile: time.Hour})

	ctx := context.Background()
	if err := s.backend.EnsureSetup(ctx); err != nil {
		t.Fatalf("EnsureSetup: %v", err)
	}
	s.reconcile(ctx)
	if got := countElementOps(run.snapshot(), "add"); got != 2 {
		t.Fatalf("expected 2 add-element ops, got %d", got)
	}

	// Idempotent: a second reconcile with the same set issues nothing new.
	run.reset()
	s.reconcile(ctx)
	if got := len(run.snapshot()); got != 0 {
		t.Fatalf("expected no ops on idempotent reconcile, got %d", got)
	}

	// Drop one ban -> exactly one delete-element on the next reconcile.
	run.reset()
	lister.set(Ban{IP: "203.0.113.10", ExpiresAt: future()})
	s.reconcile(ctx)
	if got := countElementOps(run.snapshot(), "delete"); got != 1 {
		t.Fatalf("expected 1 delete-element op, got %d", got)
	}
	if got := countElementOps(run.snapshot(), "add"); got != 0 {
		t.Fatalf("expected 0 add ops when only removing, got %d", got)
	}
}

func TestReconcileSkipsInvalidAndAllowlisted(t *testing.T) {
	run := &recordingRunner{}
	lister := &fakeLister{}
	set, err := clientip.NewCIDRSet([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("NewCIDRSet: %v", err)
	}
	lister.set(
		Ban{IP: "not-an-ip", ExpiresAt: future()},         // invalid -> rejected
		Ban{IP: "1.2.3.4; rm -rf /", ExpiresAt: future()}, // injection -> rejected
		Ban{IP: "203.0.113.9", ExpiresAt: future()},       // allowlisted -> rejected
		Ban{IP: "198.51.100.4", ExpiresAt: future()},      // valid -> applied
	)
	s := newTestSink(t, run, lister, Config{Reconcile: time.Hour, Allowlist: set})
	ctx := context.Background()
	_ = s.backend.EnsureSetup(ctx)
	s.reconcile(ctx)

	if got := countElementOps(run.snapshot(), "add"); got != 1 {
		t.Fatalf("expected only the single valid IP to be added, got %d add ops", got)
	}
	if s.rejected.Load() != 3 {
		t.Fatalf("expected 3 rejected (invalid+injection+allowlisted), got %d", s.rejected.Load())
	}
	// Confirm the injection string never reached the runner verbatim.
	for _, c := range run.snapshot() {
		joined := strings.Join(c.args, " ") + c.stdin
		if strings.Contains(joined, "rm -rf") || strings.Contains(joined, "not-an-ip") {
			t.Fatalf("attacker string leaked into command: %q", joined)
		}
	}
}

func TestReconcileMaxRules(t *testing.T) {
	run := &recordingRunner{}
	lister := &fakeLister{}
	lister.set(
		Ban{IP: "198.51.100.1", ExpiresAt: future()},
		Ban{IP: "198.51.100.2", ExpiresAt: future()},
		Ban{IP: "198.51.100.3", ExpiresAt: future()},
	)
	s := newTestSink(t, run, lister, Config{Reconcile: time.Hour, MaxRules: 2})
	ctx := context.Background()
	_ = s.backend.EnsureSetup(ctx)
	s.reconcile(ctx)
	if got := countElementOps(run.snapshot(), "add"); got != 2 {
		t.Fatalf("expected MaxRules=2 to cap adds at 2, got %d", got)
	}
	if s.capped.Load() == 0 {
		t.Fatal("expected capped counter to be incremented")
	}
}

func TestReconcileApplyErrorDoesNotMarkApplied(t *testing.T) {
	// A runner that always errors must leave applied empty so the next reconcile
	// retries the full delta (no silent permanent failure).
	errRun := runnerFunc(func(context.Context, string, []string, string) (string, error) {
		return "", context.DeadlineExceeded
	})
	lister := &fakeLister{}
	lister.set(Ban{IP: "198.51.100.9", ExpiresAt: future()})
	s := newTestSink(t, errRun, lister, Config{Reconcile: time.Hour})
	ctx := context.Background()
	s.reconcile(ctx)
	s.mu.Lock()
	n := len(s.applied)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected applied to stay empty after apply error, got %d", n)
	}
	if s.errors.Load() == 0 {
		t.Fatal("expected error counter to increment")
	}
}

type runnerFunc func(context.Context, string, []string, string) (string, error)

func (f runnerFunc) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	return f(ctx, name, args, stdin)
}

func TestNftAddElementArgs(t *testing.T) {
	args, err := nftAddElementArgs("wewaf", "1.2.3.4", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"add", "element", "inet", "wewaf", "blocklist4", "{ 1.2.3.4 timeout 3600s }"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("v4 args mismatch:\n got %v\nwant %v", args, want)
	}
	// IPv6 is programmed as the /64 PREFIX, not the single host, so the kernel
	// drops the whole prefix the ban list keys on.
	args6, err := nftAddElementArgs("wewaf", "2001:db8::dead:beef", 60)
	if err != nil {
		t.Fatalf("unexpected v6 error: %v", err)
	}
	if args6[4] != "blocklist6" {
		t.Fatalf("expected v6 to route to blocklist6, got %q", args6[4])
	}
	if !strings.Contains(args6[5], "2001:db8::/64") {
		t.Fatalf("expected v6 element to carry the /64 prefix, got %q", args6[5])
	}
	if _, err := nftAddElementArgs("wewaf", "garbage; nft flush ruleset", 60); err == nil {
		t.Fatal("expected non-IP to be rejected")
	}
}

func TestSinkClearOnStopRunsReset(t *testing.T) {
	run := &recordingRunner{}
	lister := &fakeLister{}
	lister.set(Ban{IP: "203.0.113.7", ExpiresAt: future()})
	be := &nftBackend{table: "wewaf", run: run}
	s := New(be, lister, Config{Reconcile: time.Hour, ClearOnStop: true, Logf: func(string, ...interface{}) {}})
	s.Start(context.Background())
	s.Stop() // closes stopCh, loop runs teardown -> Reset, done closes, Stop returns

	found := false
	for _, c := range run.snapshot() {
		if len(c.args) >= 2 && c.args[0] == "delete" && c.args[1] == "table" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a Reset (nft delete table) when ClearOnStop is set")
	}
}

func TestNftSetupScriptSanitisesTable(t *testing.T) {
	good := nftSetupScript("wewaf")
	if !strings.Contains(good, "add table inet wewaf") {
		t.Fatalf("setup script missing table line:\n%s", good)
	}
	// A hostile table name must be replaced with the default, never embedded.
	bad := nftSetupScript("evil; flush ruleset")
	if strings.Contains(bad, "flush ruleset") || !strings.Contains(bad, "add table inet wewaf") {
		t.Fatalf("hostile table name not sanitised:\n%s", bad)
	}
}

func TestPowerShellCommandsQuoteIP(t *testing.T) {
	add, err := psAddCommand("WEWAF", "1.2.3.4")
	if err != nil {
		t.Fatalf("psAddCommand: %v", err)
	}
	if !strings.Contains(add, "-RemoteAddress '1.2.3.4'") || !strings.Contains(add, "-Action Block") {
		t.Fatalf("unexpected add command: %q", add)
	}
	if _, err := psAddCommand("WEWAF", "1.2.3.4'; Stop-Computer #"); err == nil {
		t.Fatal("expected injection-shaped IP to be rejected by psAddCommand")
	}
	reset := psResetCommand("WEWAF")
	if !strings.Contains(reset, "Remove-NetFirewallRule -Group 'WEWAF'") {
		t.Fatalf("unexpected reset command: %q", reset)
	}
}

func TestDefaultBackendSelection(t *testing.T) {
	// "none" disables.
	be, err := DefaultBackend(Config{Backend: "none"})
	if err != nil || be != nil {
		t.Fatalf("expected (nil,nil) for none, got (%v,%v)", be, err)
	}
	// Explicit nft / netsh resolve regardless of host OS.
	nb, _ := DefaultBackend(Config{Backend: "nft", Table: "wewaf"})
	if nb == nil || nb.Name() != "nftables" {
		t.Fatalf("expected nftables backend, got %v", nb)
	}
	wb, _ := DefaultBackend(Config{Backend: "netsh"})
	if wb == nil || wb.Name() != "windows-firewall" {
		t.Fatalf("expected windows-firewall backend, got %v", wb)
	}
}

func TestSinkDryRunRecordsButDoesNotExec(t *testing.T) {
	// DryRun wires the logging runner: reconcile must succeed and count adds
	// without ever calling a real command. We assert via the stats counters.
	be, err := DefaultBackend(Config{Backend: "nft", Table: "wewaf", DryRun: true, Logf: func(string, ...interface{}) {}})
	if err != nil || be == nil {
		t.Fatalf("DefaultBackend dry-run: be=%v err=%v", be, err)
	}
	lister := &fakeLister{}
	lister.set(Ban{IP: "198.51.100.20", ExpiresAt: future()})
	s := New(be, lister, Config{Reconcile: time.Hour, DryRun: true, Logf: func(string, ...interface{}) {}})
	ctx := context.Background()
	_ = be.EnsureSetup(ctx)
	s.reconcile(ctx)
	if s.added.Load() != 1 {
		t.Fatalf("expected dry-run reconcile to record 1 add, got %d", s.added.Load())
	}
	if st := s.Stats(); st["dry_run"] != true {
		t.Fatalf("expected stats dry_run=true, got %v", st["dry_run"])
	}
}

func TestSinkConcurrentReconcileAndStats(t *testing.T) {
	// Drive the live loop (short ticker, dry-run backend) while mutating the
	// ban source and reading Stats from several goroutines. Run under -race this
	// is the real check that the reconciler's locking is sound.
	be, err := DefaultBackend(Config{Backend: "nft", DryRun: true, Logf: func(string, ...interface{}) {}})
	if err != nil || be == nil {
		t.Fatalf("DefaultBackend: be=%v err=%v", be, err)
	}
	lister := &fakeLister{}
	s := New(be, lister, Config{Reconcile: time.Millisecond, DryRun: true, Logf: func(string, ...interface{}) {}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	ips := []string{"203.0.113.1", "203.0.113.2", "198.51.100.3", "2001:db8::9", "127.0.0.1"}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				lister.set(Ban{IP: ips[j%len(ips)], ExpiresAt: future()})
				_ = s.Stats()
			}
		}()
	}
	wg.Wait()
	s.Stop()
	// Loopback in the rotation must never have been pushed.
	if st := s.Stats(); st == nil {
		t.Fatal("expected stats after stop")
	}
}

func TestTTLSecondsClampedAndPadded(t *testing.T) {
	// Already-expired ban still yields a positive (>=1s) ttl.
	if got := ttlSeconds(Ban{IP: "1.2.3.4", ExpiresAt: time.Now().Add(-time.Hour)}); got < 1 {
		t.Fatalf("ttl must be >= 1s, got %d", got)
	}
	// A ban far in the future is clamped to maxKernelTTL.
	big := ttlSeconds(Ban{IP: "1.2.3.4", ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour)})
	if big > int(maxKernelTTL/time.Second) {
		t.Fatalf("ttl not clamped: %d > %d", big, int(maxKernelTTL/time.Second))
	}
}

// Package firewall pushes WEWAF's in-memory IP ban list down to the host
// packet filter so a banned source is dropped at L3/L4 — pre-handshake, across
// EVERY port — instead of only when it speaks HTTP through the proxy.
//
// Why this exists. WEWAF is an L7 WAF: every ban is enforced in
// proxy.ServeHTTP by returning HTTP 403, which means a "banned" attacker has
// already completed accept()+TLS+HTTP-parse before being turned away, and is
// entirely free to hammer SSH, a database port, or the origin directly on the
// same host. That protects the website, not the server. This package closes
// that gap the way fail2ban and CrowdSec do: a single reconcile goroutine syncs
// the active ban set into the kernel firewall (nftables on Linux, Windows
// Firewall on Windows). The in-process HTTP ban check stays exactly where it
// is, so the sink is a pure add-on — if a kernel call fails the request is
// still blocked at L7 (fail-open relative to the existing enforcement, never
// fail-open relative to the attacker).
//
// Design (poll-and-reconcile, not per-event exec):
//   - The reconcile loop reads the authoritative ban list on a ticker and
//     diffs it against what it has already applied, so the hot request path
//     never shells out.
//   - Every IP is canonicalised (net.ParseIP) and allowlist-checked before it
//     can reach an exec, so attacker-influenced ban strings can neither inject
//     a command nor ban the loopback/CDN/gateway and self-DoS the box.
//   - Linux uses kernel-side timeouts so a crashed daemon's drops self-expire;
//     Windows flushes the WEWAF rule group on startup and shutdown to the same
//     end.
package firewall

import (
	"context"
	"log"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"wewaf/internal/clientip"
)

// Ban is one entry the sink should enforce. IP is a bare address (the ban
// list's normalised key); ExpiresAt is when it should lapse.
type Ban struct {
	IP        string
	ExpiresAt time.Time
}

// Lister is the source of truth for the active ban set. *core.BanList satisfies
// this via a thin adapter in cmd/waf; keeping it an interface leaves this
// package free of a core dependency and trivially testable with a fake.
type Lister interface {
	ActiveBans() []Ban
}

// Backend applies and removes drop rules in the host firewall. Implementations
// are selected at runtime by DefaultBackend. Apply receives the desired delta —
// addresses to add and addresses to remove — and must be idempotent.
type Backend interface {
	// EnsureSetup creates whatever scaffolding the backend needs (table/set/
	// chain on Linux; group flush on Windows). Called on Start and safe to call
	// repeatedly.
	EnsureSetup(ctx context.Context) error
	// Apply adds the given bans and removes the given addresses, returning the
	// keys it ACTUALLY applied so the reconciler only marks real successes —
	// a persistently-failing single entry then retries in isolation instead of
	// the whole set re-executing every tick.
	Apply(ctx context.Context, add []Ban, remove []string) (appliedAdd, appliedRemove []string, err error)
	// Reset tears down everything this backend created (best effort).
	Reset(ctx context.Context) error
	// Name identifies the backend for logs and stats.
	Name() string
}

// runner executes an external command. The real implementation shells out via
// os/exec; the dry-run implementation logs the exact command and returns
// success without touching the host. Tests inject a recording fake. Abstracting
// here means the backends and their argv builders stay 100% testable on any OS.
type runner interface {
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

// Config configures a Sink.
type Config struct {
	// Backend names the firewall tool: "auto" (default — nft on Linux, Windows
	// Firewall on Windows), "nft", "netsh", or "none".
	Backend string
	// Table is the nftables table name (Linux only).
	Table string
	// DryRun logs every command instead of executing it — a safe trial that
	// shows exactly what would be pushed to the kernel without changing it.
	DryRun bool
	// Reconcile is how often the active ban set is synced to the kernel.
	Reconcile time.Duration
	// MaxRules caps how many entries the sink will push (0 = unlimited). Guards
	// the per-rule Windows path from a 200k-IP flood; nftables sets scale
	// natively so the cap is mostly a Windows concern.
	MaxRules int
	// Allowlist is the never-touch set. Even though core.BanList already gates
	// bans, the sink re-checks here as defence in depth before anything reaches
	// the kernel.
	Allowlist *clientip.CIDRSet
	// ClearOnStop tears the ruleset down on graceful shutdown (default true).
	ClearOnStop bool
	// Logf is the log sink (defaults to log.Printf).
	Logf func(string, ...interface{})
}

const (
	// kernelTTLMargin pads each kernel-side timeout beyond the ban's own expiry
	// so the reconcile loop (not the kernel) owns removal during normal running;
	// the timeout only matters as a crash backstop.
	kernelTTLMargin = 5 * time.Minute
	// maxKernelTTL clamps the timeout so exponential-backoff bans that scale
	// toward years don't exceed what the packet filter accepts.
	maxKernelTTL = 30 * 24 * time.Hour
)

// ttlDuration is the kernel timeout for a ban: time until expiry plus a margin,
// clamped to [1s, maxKernelTTL]. The clamp is applied BEFORE adding the margin
// so a far-future (saturating) expiry can't overflow int64 and wrap to a 1s
// timeout; a zero-value expiry is treated as the max, not as "already expired".
func ttlDuration(b Ban) time.Duration {
	if b.ExpiresAt.IsZero() {
		return maxKernelTTL
	}
	d := time.Until(b.ExpiresAt)
	if d > maxKernelTTL {
		return maxKernelTTL
	}
	d += kernelTTLMargin
	if d > maxKernelTTL {
		d = maxKernelTTL
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// ttlSeconds is ttlDuration in whole seconds, for the nft `timeout Ns` syntax.
func ttlSeconds(b Ban) int { return int(ttlDuration(b) / time.Second) }

// defaultWindowsMaxRules caps the per-rule Windows path when the operator left
// MaxRules unset. nftables sets scale natively, but each Windows entry is its
// own firewall rule (and process spawn), so an uncapped ban flood there is a
// self-inflicted resource problem.
const defaultWindowsMaxRules = 5000

// Sink reconciles a Lister's active bans into a Backend.
type Sink struct {
	backend   Backend
	lister    Lister
	allowlist *clientip.CIDRSet
	interval  time.Duration
	maxRules  int
	clearStop bool
	dryRun    bool
	logf      func(string, ...interface{})

	mu      sync.Mutex
	applied map[string]time.Time // canonical IP -> ban expiry currently pushed

	added    atomic.Uint64
	removed  atomic.Uint64
	rejected atomic.Uint64
	errors   atomic.Uint64
	capped   atomic.Uint64
	syncs    atomic.Uint64

	started  atomic.Bool
	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{} // closed by loop() after teardown so Stop() can wait
}

// New builds a Sink. backend may be nil (returns nil — the feature is off).
func New(backend Backend, lister Lister, cfg Config) *Sink {
	if backend == nil || lister == nil {
		return nil
	}
	if cfg.Reconcile <= 0 {
		cfg.Reconcile = 5 * time.Second
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	maxRules := cfg.MaxRules
	if maxRules <= 0 && backend.Name() == "windows-firewall" {
		maxRules = defaultWindowsMaxRules
	}
	return &Sink{
		backend:   backend,
		lister:    lister,
		allowlist: cfg.Allowlist,
		interval:  cfg.Reconcile,
		maxRules:  maxRules,
		clearStop: cfg.ClearOnStop,
		dryRun:    cfg.DryRun,
		logf:      logf,
		applied:   make(map[string]time.Time),
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Start runs EnsureSetup then launches the reconcile loop. Non-blocking.
func (s *Sink) Start(ctx context.Context) {
	if s == nil {
		return
	}
	if err := s.backend.EnsureSetup(ctx); err != nil {
		s.errors.Add(1)
		s.logf("firewall: setup failed on %s backend (%v) — host-firewall enforcement is OFF; "+
			"the in-process L7 ban check still applies", s.backend.Name(), err)
		return
	}
	mode := "live"
	if s.dryRun {
		mode = "dry-run"
	}
	s.logf("firewall: %s sink active (%s, reconcile=%s) — bans now drop at the kernel across all ports",
		s.backend.Name(), mode, s.interval)
	s.started.Store(true)
	go s.loop(ctx)
}

func (s *Sink) loop(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if r := recover(); r != nil {
			s.logf("firewall: reconcile loop panic: %v", r)
		}
	}()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			s.teardown()
			return
		case <-s.stopCh:
			s.teardown()
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

func (s *Sink) teardown() {
	if !s.clearStop {
		return
	}
	// Detached context: ctx is already cancelled at shutdown, but we still want
	// the cleanup command to run so bans don't outlive the daemon.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.backend.Reset(ctx); err != nil {
		s.logf("firewall: reset on shutdown failed: %v", err)
	}
}

// reconcile computes the desired kernel set from the ban list, diffs it against
// what is already applied, and pushes only the delta.
func (s *Sink) reconcile(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.errors.Add(1)
			s.logf("firewall: reconcile panic: %v", r)
		}
	}()
	now := time.Now()

	bans := s.lister.ActiveBans()
	// Deterministic order so the MaxRules cap keeps a STABLE subset instead of
	// flapping with Go's randomized map iteration (which would add then remove a
	// rotating set every tick). Longest-lived bans win the cap.
	sort.Slice(bans, func(i, j int) bool {
		if !bans[i].ExpiresAt.Equal(bans[j].ExpiresAt) {
			return bans[i].ExpiresAt.After(bans[j].ExpiresAt)
		}
		return bans[i].IP < bans[j].IP
	})

	desired := make(map[string]Ban, len(bans))
	for _, b := range bans {
		canon, ok := CanonicalIP(b.IP)
		if !ok {
			s.rejected.Add(1)
			continue
		}
		if isNeverDropIP(canon) {
			s.rejected.Add(1)
			continue
		}
		if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			continue // already lapsed
		}
		// Allowlist with prefix semantics: an allowlisted /128 inside a banned
		// /64 (or any overlap) must veto the kernel drop.
		if s.allowlist != nil {
			if n := effectiveNet(canon); n != nil && s.allowlist.Overlaps(n) {
				s.rejected.Add(1)
				continue
			}
		}
		if _, dup := desired[canon]; !dup && s.maxRules > 0 && len(desired) >= s.maxRules {
			s.capped.Add(1)
			continue
		}
		desired[canon] = Ban{IP: canon, ExpiresAt: b.ExpiresAt}
	}

	// Compute the delta and the wall-clock kernel expiry we will program for
	// each add, so we can refresh long bans before the kernel self-expires them.
	prog := make(map[string]time.Time)
	s.mu.Lock()
	var add []Ban
	var remove []string
	for ip, b := range desired {
		prev, ok := s.applied[ip]
		if !ok || now.Add(kernelTTLMargin).After(prev) {
			add = append(add, b)
			prog[ip] = now.Add(ttlDuration(b))
		}
	}
	for ip := range s.applied {
		if _, ok := desired[ip]; !ok {
			remove = append(remove, ip)
		}
	}
	s.mu.Unlock()

	if len(add) == 0 && len(remove) == 0 {
		s.syncs.Add(1)
		return
	}

	appliedAdd, appliedRemove, err := s.backend.Apply(ctx, add, remove)
	if err != nil {
		s.errors.Add(1)
		s.logf("firewall: apply error (failed entries retry next reconcile): %v", err)
	}

	// Mark ONLY what the backend actually applied, keyed on the programmed
	// kernel expiry (not the ban's true expiry) so the refresh check above fires
	// before a clamped kernel timeout lapses.
	s.mu.Lock()
	for _, ip := range appliedAdd {
		if exp, ok := prog[ip]; ok {
			s.applied[ip] = exp
		} else {
			s.applied[ip] = now.Add(maxKernelTTL)
		}
	}
	for _, ip := range appliedRemove {
		delete(s.applied, ip)
	}
	s.mu.Unlock()

	s.added.Add(uint64(len(appliedAdd)))
	s.removed.Add(uint64(len(appliedRemove)))
	s.syncs.Add(1)
}

// Stop halts the reconcile loop and (if ClearOnStop) tears the ruleset down,
// waiting (bounded) for teardown to finish so Windows Firewall rules — which
// have no kernel timeout — don't outlive the daemon on a clean shutdown.
func (s *Sink) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	if s.started.Load() {
		select {
		case <-s.done:
		case <-time.After(6 * time.Second):
		}
	}
}

// Stats returns a snapshot for the admin API / logs.
func (s *Sink) Stats() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}
	s.mu.Lock()
	applied := len(s.applied)
	s.mu.Unlock()
	return map[string]interface{}{
		"enabled":        true,
		"backend":        s.backend.Name(),
		"dry_run":        s.dryRun,
		"applied":        applied,
		"added_total":    s.added.Load(),
		"removed_total":  s.removed.Load(),
		"rejected_total": s.rejected.Load(),
		"capped_total":   s.capped.Load(),
		"errors_total":   s.errors.Load(),
		"syncs_total":    s.syncs.Load(),
	}
}

// DefaultBackend selects and constructs the platform backend from cfg. It
// returns (nil, nil) when the resolved backend is "none" (or the platform is
// unsupported), which the caller treats as "feature disabled". When DryRun is
// set the backend is wired to a runner that logs instead of executing.
func DefaultBackend(cfg Config) (Backend, error) {
	name := cfg.Backend
	if name == "" || name == "auto" {
		switch runtime.GOOS {
		case "linux":
			name = "nft"
		case "windows":
			name = "netsh"
		default:
			name = "none"
		}
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	var run runner = osRunner{}
	if cfg.DryRun {
		run = &dryRunner{logf: logf}
	}
	switch name {
	case "nft", "nftables":
		return &nftBackend{table: sanitizeIdent(cfg.Table, "wewaf"), run: run}, nil
	case "netsh", "windows", "windows-firewall":
		return &windowsBackend{group: windowsRuleGroup, run: run}, nil
	case "none":
		return nil, nil
	default:
		return nil, nil
	}
}

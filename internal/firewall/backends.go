package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// This file holds the platform backends and — more importantly — the PURE
// command/argv builders they call. The builders are deliberately kept free of
// any exec / OS dependency so they compile and are unit-tested AND fuzzed on
// every platform (including the Windows dev box this was written on). The only
// platform-specific behaviour is which external tool runs, and that is selected
// at runtime via runtime.GOOS in DefaultBackend — not via build tags — because
// nothing here uses an OS-specific API that would fail to compile elsewhere
// (unlike internal/proxy/connerr_windows.go, which references syscall.Errno).
//
// SECURITY INVARIANT (locked down by FuzzCanonicalIP / FuzzFirewallArgv):
// every IP that reaches a builder is first run through CanonicalIP, which
// rejects anything net.ParseIP can't parse and returns the canonical text form.
// That form can only contain [0-9a-fA-F:.], so it can carry no shell/argv/nft
// metacharacter — no `;`, `$`, backtick, quote, space, or newline. Commands are
// additionally executed via exec.Command with a separate argv (no shell), and
// the Windows PowerShell path single-quotes the IP, so a banned string can
// never inject a command even though ban strings originate from attacker-
// influenced sources (threat feeds, mesh peers, the admin API).

// CanonicalIP validates an IP string and returns its canonical text form.
// ok is false when the input is not a parseable IP address. The returned
// string is guaranteed to contain only characters in [0-9a-fA-F:.].
func CanonicalIP(s string) (canonical string, ok bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// kernelTarget validates an IP and returns the address form to program into the
// host firewall plus its nftables set. IPv4 maps to the /32 host; IPv6 maps to
// the /64 PREFIX — matching the ban list's /64 keying (NormalizeIPKey), so the
// kernel drops the entire prefix an attacker rotates through, not just the one
// base address. ok is false for any non-IP input. The returned target contains
// only [0-9a-fA-F:./], so it carries no shell/argv/nft metacharacter.
func kernelTarget(ipStr string) (target, set string, ok bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", "", false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), nftSet4, true
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64", nftSet6, true
}

// effectiveNet is the network a canonical key actually covers — an IPv4 /32 or
// an IPv6 /64 — used to test the sink's allowlist with prefix semantics so an
// allowlisted /128 inside a /64 correctly blocks a /64 drop. Returns nil for a
// non-IP (which isNeverDropIP/CanonicalIP have already rejected).
func effectiveNet(canonical string) *net.IPNet {
	ip := net.ParseIP(canonical)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
}

// isNeverDropIP reports addresses the sink must NEVER push to the kernel,
// independent of any operator allowlist. core.BanList already refuses loopback,
// but a kernel-wide DROP is the single most catastrophic self-DoS available, so
// the sink re-checks at the last boundary before exec and additionally refuses
// PRIVATE / CGNAT / multicast / broadcast addresses: in legacy trust_xff mode an
// attacker can spoof X-Forwarded-For to an internal IP, trip an auto-ban, and
// otherwise have the sink sever the default gateway or the WAF→origin path.
func isNeverDropIP(canonical string) bool {
	ip := net.ParseIP(canonical)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() { // RFC1918 + IPv6 ULA fc00::/7
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// CGNAT 100.64.0.0/10 and the limited broadcast address.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4.Equal(net.IPv4bcast) {
			return true
		}
	}
	return false
}

// sanitizeIdent constrains an nftables identifier (table/set/chain name) to a
// safe character class so an operator-supplied table name can never alter the
// structure of the `nft -f` setup script. Falls back to def when the input is
// empty or contains anything outside [A-Za-z0-9_].
func sanitizeIdent(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return def
		}
	}
	return s
}

// --- nftables (Linux) ---------------------------------------------------

const (
	nftSet4 = "blocklist4"
	nftSet6 = "blocklist6"
)

// nftSetupScript returns an idempotent `nft -f` script that creates the table,
// the timeout-flagged v4/v6 sets, and an input-hook chain that drops any source
// address present in either set. It flushes the chain and sets first so a
// restart rebuilds a clean ruleset (reconcile re-populates within one interval)
// and a prior crash never leaves duplicate drop rules. Priority -150 runs ahead
// of most service rules; policy accept means only matched sources are dropped.
func nftSetupScript(table string) string {
	t := sanitizeIdent(table, "wewaf")
	lines := []string{
		"add table inet " + t,
		"add chain inet " + t + " input { type filter hook input priority -150 ; policy accept ; }",
		"add set inet " + t + " " + nftSet4 + " { type ipv4_addr ; flags timeout ; }",
		// interval flag lets the v6 set hold /64 PREFIXES (one element drops the
		// whole prefix the ban list keys on), not just single /128 hosts.
		"add set inet " + t + " " + nftSet6 + " { type ipv6_addr ; flags interval, timeout ; }",
		"flush chain inet " + t + " input",
		"flush set inet " + t + " " + nftSet4,
		"flush set inet " + t + " " + nftSet6,
		"add rule inet " + t + " input ip saddr @" + nftSet4 + " drop",
		"add rule inet " + t + " input ip6 saddr @" + nftSet6 + " drop",
		"",
	}
	return strings.Join(lines, "\n")
}

// nftAddElementArgs builds the argv for adding one IP to the appropriate set
// with a kernel-side timeout (so a crashed daemon's drops self-expire). IPv6 is
// programmed as the /64 prefix. ttlSec must be >= 1.
func nftAddElementArgs(table, ipStr string, ttlSec int) ([]string, error) {
	target, set, ok := kernelTarget(ipStr)
	if !ok {
		return nil, fmt.Errorf("firewall: refusing to add non-IP %q", ipStr)
	}
	if ttlSec < 1 {
		ttlSec = 1
	}
	t := sanitizeIdent(table, "wewaf")
	elem := fmt.Sprintf("{ %s timeout %ds }", target, ttlSec)
	return []string{"add", "element", "inet", t, set, elem}, nil
}

// nftDelElementArgs builds the argv for removing one IP (IPv6: its /64) from its
// set.
func nftDelElementArgs(table, ipStr string) ([]string, error) {
	target, set, ok := kernelTarget(ipStr)
	if !ok {
		return nil, fmt.Errorf("firewall: refusing to delete non-IP %q", ipStr)
	}
	t := sanitizeIdent(table, "wewaf")
	return []string{"delete", "element", "inet", t, set, "{ " + target + " }"}, nil
}

// nftResetArgs tears the whole table down (best effort on shutdown).
func nftResetArgs(table string) []string {
	return []string{"delete", "table", "inet", sanitizeIdent(table, "wewaf")}
}

type nftBackend struct {
	table string
	run   runner
}

func (b *nftBackend) Name() string { return "nftables" }

func (b *nftBackend) EnsureSetup(ctx context.Context) error {
	_, err := b.run.Run(ctx, "nft", []string{"-f", "-"}, nftSetupScript(b.table))
	return err
}

func (b *nftBackend) Apply(ctx context.Context, add []Ban, remove []string) (appliedAdd, appliedRemove []string, err error) {
	var firstErr error
	for _, ban := range add {
		args, aerr := nftAddElementArgs(b.table, ban.IP, ttlSeconds(ban))
		if aerr != nil {
			continue // CanonicalIP already gated this upstream; defensive skip
		}
		if _, e := b.run.Run(ctx, "nft", args, ""); e != nil {
			if firstErr == nil {
				firstErr = e
			}
			continue // do NOT report a failed add as applied — it retries next tick
		}
		appliedAdd = append(appliedAdd, ban.IP)
	}
	for _, ip := range remove {
		args, derr := nftDelElementArgs(b.table, ip)
		if derr != nil {
			continue
		}
		// A delete of an already-expired element returns an error; that's
		// benign (the kernel timeout beat us to it), so the element is gone
		// either way — always report removes as applied so we stop tracking it.
		_, _ = b.run.Run(ctx, "nft", args, "")
		appliedRemove = append(appliedRemove, ip)
	}
	return appliedAdd, appliedRemove, firstErr
}

func (b *nftBackend) Reset(ctx context.Context) error {
	_, err := b.run.Run(ctx, "nft", nftResetArgs(b.table), "")
	return err
}

// --- Windows Firewall (PowerShell) --------------------------------------

const windowsRuleGroup = "WEWAF"

// wewafRuleName is the deterministic per-IP rule name. Because the IP is
// canonical it contains no character that needs escaping in a rule name.
func wewafRuleName(canonicalIP string) string { return "WEWAF-block-" + canonicalIP }

// psAddCommand builds the PowerShell statement that adds an inbound block rule
// for one IP (IPv6: its /64). The target is single-quoted; since kernelTarget
// only ever yields [0-9a-fA-F:./], the literal holds no PowerShell metacharacter
// (no quote, ;, $, backtick, space) and cannot be broken out of.
func psAddCommand(group, ipStr string) (string, error) {
	target, _, ok := kernelTarget(ipStr)
	if !ok {
		return "", fmt.Errorf("firewall: refusing to add non-IP %q", ipStr)
	}
	return fmt.Sprintf(
		"New-NetFirewallRule -DisplayName '%s' -Group '%s' -Direction Inbound -Action Block -RemoteAddress '%s' -Profile Any -ErrorAction Stop | Out-Null",
		wewafRuleName(target), group, target), nil
}

// psRemoveCommand builds the statement that removes one IP's rule. It must
// derive the same name psAddCommand did, so it routes through kernelTarget too.
func psRemoveCommand(ipStr string) (string, error) {
	target, _, ok := kernelTarget(ipStr)
	if !ok {
		return "", fmt.Errorf("firewall: refusing to delete non-IP %q", ipStr)
	}
	return fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue",
		wewafRuleName(target)), nil
}

// psResetCommand removes every rule in the WEWAF group in one call — the clean
// bulk-cleanup that lets a restart flush orphaned rules left by a prior crash.
func psResetCommand(group string) string {
	return fmt.Sprintf("Remove-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue", group)
}

type windowsBackend struct {
	group string
	run   runner
}

func (b *windowsBackend) Name() string { return "windows-firewall" }

func (b *windowsBackend) ps(ctx context.Context, cmd string) error {
	_, err := b.run.Run(ctx, "powershell.exe",
		[]string{"-NoProfile", "-NonInteractive", "-Command", cmd}, "")
	return err
}

func (b *windowsBackend) EnsureSetup(ctx context.Context) error {
	// Flush any rules left by a previous (possibly crashed) run so we start
	// from a known-clean group. Windows Firewall rules have no kernel timeout,
	// so this startup flush is load-bearing for expiry correctness.
	return b.ps(ctx, psResetCommand(b.group))
}

func (b *windowsBackend) Apply(ctx context.Context, add []Ban, remove []string) (appliedAdd, appliedRemove []string, err error) {
	var firstErr error
	for _, ban := range add {
		cmd, cerr := psAddCommand(b.group, ban.IP)
		if cerr != nil {
			continue
		}
		if e := b.ps(ctx, cmd); e != nil {
			if firstErr == nil {
				firstErr = e
			}
			continue
		}
		appliedAdd = append(appliedAdd, ban.IP)
	}
	for _, ip := range remove {
		cmd, cerr := psRemoveCommand(ip)
		if cerr != nil {
			continue
		}
		_ = b.ps(ctx, cmd)
		appliedRemove = append(appliedRemove, ip)
	}
	return appliedAdd, appliedRemove, firstErr
}

func (b *windowsBackend) Reset(ctx context.Context) error {
	return b.ps(ctx, psResetCommand(b.group))
}

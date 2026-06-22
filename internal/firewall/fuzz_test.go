package firewall

import (
	"net"
	"strings"
	"testing"
)

// onlyIPChars reports whether s is restricted to the character class a
// canonical net.IP text form can produce: hex digits, '.', and ':'. This is the
// invariant that makes interpolating an IP into an nft script or a PowerShell
// single-quoted literal injection-proof.
func onlyIPChars(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		case r == '.' || r == ':':
		default:
			return false
		}
	}
	return true
}

// onlyTargetChars is onlyIPChars plus '/' — the kernel target may be a CIDR
// prefix (IPv6 /64). None of these characters is a shell/nft/PowerShell
// metacharacter, so interpolation stays injection-proof.
func onlyTargetChars(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '/' {
			continue
		}
		if !onlyIPChars(string(r)) {
			return false
		}
	}
	return true
}

// dangerous metacharacters that must never appear in a built command/arg as a
// result of the IP input.
const dangerousChars = ";\n\r\t`$|&<>(){}*?!\\\"' "

func containsAny(s, set string) bool { return strings.ContainsAny(s, set) }

var fuzzSeeds = []string{
	"1.2.3.4", "255.255.255.255", "0.0.0.0", "::1", "::", "2001:db8::1",
	"::ffff:1.2.3.4", "fe80::1%eth0", "  10.0.0.1  ",
	"", "not-an-ip", "localhost", "1.2.3.4/24", "999.999.999.999",
	"1.2.3.4; rm -rf /", "-j ACCEPT", "--flush", "$(reboot)", "`id`",
	"1.2.3.4'; Stop-Computer #", "1.2.3.4 || true", "1.2.3.4\nDROP",
	"{ 1.2.3.4 }", "1.2.3.4 timeout 9999999s", "evil; flush ruleset",
}

func FuzzCanonicalIP(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		canon, ok := CanonicalIP(s)
		if !ok {
			if canon != "" {
				t.Fatalf("CanonicalIP returned ok=false but non-empty %q", canon)
			}
			return
		}
		if net.ParseIP(canon) == nil {
			t.Fatalf("CanonicalIP accepted %q -> %q which does not re-parse", s, canon)
		}
		if !onlyIPChars(canon) {
			t.Fatalf("CanonicalIP(%q) -> %q contains a non-IP character", s, canon)
		}
	})
}

func FuzzNftArgsNoInjection(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s, 3600)
	}
	f.Fuzz(func(t *testing.T, ipStr string, ttl int) {
		add, err := nftAddElementArgs("wewaf", ipStr, ttl)
		if err != nil {
			// Rejected inputs must never also return args.
			if add != nil {
				t.Fatalf("nftAddElementArgs returned args with error for %q", ipStr)
			}
			return
		}
		target, _, ok := kernelTarget(ipStr)
		if !ok {
			t.Fatalf("nftAddElementArgs accepted %q that kernelTarget rejects", ipStr)
		}
		if len(add) != 6 {
			t.Fatalf("expected 6 args, got %d: %v", len(add), add)
		}
		// Every structural arg is a fixed token; only arg[5] embeds the target.
		if !strings.Contains(add[5], target) {
			t.Fatalf("element token %q missing kernel target %q", add[5], target)
		}
		// The target must be the ONLY variable content — no metacharacter may
		// have survived into any argv token.
		for i, a := range add {
			if i == 5 {
				continue
			}
			if containsAny(a, ";\n\r`$|&") {
				t.Fatalf("structural arg %q carries a metacharacter", a)
			}
		}
		// And the embedded target itself is the safe charset (incl. '/').
		if !onlyTargetChars(target) {
			t.Fatalf("embedded target %q not in safe charset", target)
		}

		del, derr := nftDelElementArgs("wewaf", ipStr)
		if derr != nil {
			t.Fatalf("add accepted %q but delete rejected it", ipStr)
		}
		if !strings.Contains(del[5], target) {
			t.Fatalf("delete token %q missing kernel target", del[5])
		}
	})
}

func FuzzPowerShellNoInjection(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ipStr string) {
		cmd, err := psAddCommand("WEWAF", ipStr)
		if err != nil {
			if cmd != "" {
				t.Fatalf("psAddCommand returned a command with error for %q", ipStr)
			}
			return
		}
		target, _, ok := kernelTarget(ipStr)
		if !ok {
			t.Fatalf("psAddCommand accepted %q that kernelTarget rejects", ipStr)
		}
		if !onlyTargetChars(target) {
			t.Fatalf("kernel target %q not in safe charset", target)
		}
		// Exactly three single-quoted literals (DisplayName, Group,
		// RemoteAddress) => exactly six apostrophes. A breakout would add more.
		if n := strings.Count(cmd, "'"); n != 6 {
			t.Fatalf("expected 6 single quotes (no breakout), got %d in %q", n, cmd)
		}
		// No newline / statement separator may appear anywhere in the command.
		if strings.ContainsAny(cmd, "\n\r") {
			t.Fatalf("command contains a newline: %q", cmd)
		}
		rem, rerr := psRemoveCommand(ipStr)
		if rerr != nil {
			t.Fatalf("add accepted %q but remove rejected it", ipStr)
		}
		if strings.Count(rem, "'") != 2 {
			t.Fatalf("remove command should single-quote exactly the name: %q", rem)
		}
	})
}

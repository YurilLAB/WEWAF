package firewall

import (
	"context"
	"os/exec"
	"strings"
)

// osRunner executes commands for real. exec.CommandContext is platform-neutral
// Go — it compiles on every OS — so the only thing that makes a command
// Linux-only or Windows-only is the tool name chosen by DefaultBackend. Args
// are passed as a separate argv (never a shell string), so there is no shell to
// inject into; combined with CanonicalIP the command surface is closed.
type osRunner struct{}

func (osRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// dryRunner logs the exact command that would run and reports success without
// touching the host. This backs FirewallDryRun — the safe way to switch the
// sink on, watch the precise nft/PowerShell commands it would issue, and only
// then flip to live enforcement.
type dryRunner struct {
	logf func(string, ...interface{})
}

func (d *dryRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	if stdin != "" {
		// Multi-line setup scripts: render them inline but compact.
		d.logf("firewall[dry-run]: %s <<<\n%s", name, stdin)
		return "", nil
	}
	d.logf("firewall[dry-run]: %s %s", name, strings.Join(args, " "))
	return "", nil
}

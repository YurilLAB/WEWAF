package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SnapshotToFile writes a timestamped JSON snapshot of the config to the
// given directory. It's called on startup (so the live config is captured)
// and after every successful SetMode / UpdateConfig through the admin API
// so a rollback is one file away.
//
// Snapshots older than keep are pruned so the directory doesn't grow
// without bound.
func (c *Config) SnapshotToFile(dir string, keep int) (string, error) {
	if c == nil {
		return "", fmt.Errorf("config: SnapshotToFile on nil config")
	}
	if dir == "" {
		dir = "config_backup"
	}
	// 0o700 — config snapshots can hold redacted-but-still-sensitive
	// metadata (mesh peer URLs, file paths, port numbers, ban counts).
	// On a shared host the previous 0o755 made them world-readable.
	// On Windows the mode bits are advisory and ACLs are inherited
	// from the parent, so this hardens POSIX without changing
	// observable Windows behaviour.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("config: create snapshot dir: %w", err)
	}
	snap := c.Snapshot()
	buf, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("config: marshal snapshot: %w", err)
	}
	name := fmt.Sprintf("config-%s.json", time.Now().UTC().Format("2006-01-02T15-04-05Z"))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return "", fmt.Errorf("config: write snapshot: %w", err)
	}
	// Best-effort pruning. Failures here shouldn't take the daemon down.
	_ = pruneOld(dir, keep)
	return path, nil
}

// pruneOld removes the oldest config-*.json files until at most `keep`
// remain. Not part of the SnapshotToFile return value — callers that care
// can re-list themselves.
func pruneOld(dir string, keep int) error {
	if keep <= 0 {
		keep = 10
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type snap struct {
		name string
		mod  time.Time
	}
	var snaps []snap
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if len(n) < 8 || n[:7] != "config-" || filepath.Ext(n) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		snaps = append(snaps, snap{name: n, mod: info.ModTime()})
	}
	if len(snaps) <= keep {
		return nil
	}
	// Oldest first.
	for i := 0; i < len(snaps)-1; i++ {
		for j := i + 1; j < len(snaps); j++ {
			if snaps[j].mod.Before(snaps[i].mod) {
				snaps[i], snaps[j] = snaps[j], snaps[i]
			}
		}
	}
	for _, s := range snaps[:len(snaps)-keep] {
		_ = os.Remove(filepath.Join(dir, s.name))
	}
	return nil
}

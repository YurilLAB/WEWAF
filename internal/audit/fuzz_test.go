package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzChainResume feeds arbitrary bytes as an on-disk audit log and opens it.
// New() scans + resumes the existing file, so a corrupt or hostile audit file
// must never panic the daemon — a crash here is a won't-start DoS (an attacker
// who can write a byte into the audit file could stop the WAF from booting).
// Run: go test -run=^$ -fuzz=^FuzzChainResume$ -fuzztime=60s ./internal/audit/
func FuzzChainResume(f *testing.F) {
	f.Add([]byte("{\"seq\":1,\"timestamp\":\"2026-01-01T00:00:00Z\",\"kind\":\"x\",\"mac\":\"ab\"}\n"))
	f.Add([]byte("not json at all\n"))
	f.Add([]byte("{\n{\n{\n"))
	f.Add([]byte("{\"seq\":18446744073709551615}\n")) // uint64 max seq
	f.Add([]byte(""))
	// Create ONE temp dir for the whole run and reuse a single file path each
	// iteration (rewritten via WriteFile, which truncates). The previous
	// per-iteration t.TempDir()+create+cleanup made every exec a handful of
	// filesystem syscalls — ~1k execs/s vs the 100k+/s of CPU-bound targets —
	// which under load made the post-fuzztime shutdown miss its deadline
	// ("context deadline exceeded") without ever finding a real crash. One reused
	// dir keeps each exec a single write + open, so the target actually explores.
	dir, err := os.MkdirTemp("", "fuzzchainresume")
	if err != nil {
		f.Fatalf("MkdirTemp: %v", err)
	}
	f.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "audit.log")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		c, err := New(Config{Secret: "k", FilePath: path, RingSize: 16})
		if err == nil && c != nil {
			_, _, _ = c.Verify()
			_ = c.Close()
		}
	})
}

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
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
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

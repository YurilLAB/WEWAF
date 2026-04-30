package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingWriter pretends to be a healthy disk for n successful writes
// then returns an error forever. Used to verify that an Append failure
// does not corrupt the in-memory chain state.
type failingWriter struct {
	bytes int
	cap   int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.bytes+len(p) > f.cap {
		return 0, errors.New("disk full")
	}
	f.bytes += len(p)
	return len(p), nil
}

// TestChainStateRollbackOnWriteFailure proves the Append fix: when a
// disk write fails, c.seq and c.prevMAC are NOT advanced, so a retry
// produces a valid chain. Without the fix, a transient I/O error
// would leave subsequent entries chained against a MAC that doesn't
// exist on disk — verify() would then fail forever.
func TestChainStateRollbackOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	c, err := New(Config{Secret: "test", FilePath: path})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer c.Close()

	// Drop in a writer that fails on every write to simulate a full
	// disk. The bw wraps it so the Flush carries the failure forward.
	c.mu.Lock()
	c.bw = bufio.NewWriter(&failingWriter{cap: 0})
	c.mu.Unlock()

	if _, err := c.Append("test", "actor", "first", ""); err == nil {
		t.Fatal("expected first Append to fail with disk full")
	}
	// Now restore a healthy writer; a retry should produce seq=1, not seq=2.
	healthy, _ := os.OpenFile(filepath.Join(dir, "fresh.log"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	defer healthy.Close()
	c.mu.Lock()
	c.bw = bufio.NewWriter(healthy)
	c.mu.Unlock()

	e, err := c.Append("test", "actor", "first", "")
	if err != nil {
		t.Fatalf("retry Append: %v", err)
	}
	if e.Seq != 1 {
		t.Fatalf("seq should roll back to 1 after failed write; got %d", e.Seq)
	}
	if e.PrevMAC != "" {
		t.Fatalf("prevMAC should be empty for the first real entry; got %q", e.PrevMAC)
	}
}

func TestChainAppendAndVerifyRoundtrip(t *testing.T) {
	c, err := New(Config{Secret: "test-secret-do-not-use-in-prod"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer c.Close()

	for i := 0; i < 5; i++ {
		if _, err := c.Append("block", "1.2.3.4", "rule-hit", ""); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	ok, bad, total := c.Verify()
	if !ok {
		t.Fatalf("fresh chain failed verification: badSeq=%d total=%d", bad, total)
	}
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	appends, _ := c.Stats()
	if appends != 5 {
		t.Fatalf("stats appends = %d, want 5", appends)
	}
}

// TestChainDetectsEdit is the whole point of the package. We write a few
// entries, corrupt one in-place in memory, then verify and expect a fail
// pointing at the right seq.
func TestChainDetectsEdit(t *testing.T) {
	c, _ := New(Config{Secret: "k"})
	defer c.Close()
	for i := 0; i < 4; i++ {
		_, _ = c.Append("block", "a", "m", "")
	}
	// Tamper the 2nd ring entry.
	c.mu.Lock()
	start := (c.ringHead - c.ringSize + c.ringMax) % c.ringMax
	c.ring[(start+1)%c.ringMax].Message = "tampered"
	c.mu.Unlock()

	ok, bad, _ := c.Verify()
	if ok {
		t.Fatalf("verify missed an edited entry")
	}
	if bad != 2 {
		t.Fatalf("expected badSeq=2, got %d", bad)
	}
}

// TestChainDetectsDeletion covers the "attacker dropped a line" case.
// Seq check catches it before the MAC even runs.
func TestChainDetectsDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	c, _ := New(Config{Secret: "s", FilePath: path})
	for i := 0; i < 5; i++ {
		_, _ = c.Append("block", "ip", "m", "")
	}
	_ = c.Close()

	// Delete entry 3 manually by rewriting the file without that line.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
	// Drop line index 2 (seq=3).
	tampered := strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "\n") + "\n"
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	// Reopen and verify.
	c2, err := New(Config{Secret: "s", FilePath: path})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer c2.Close()
	ok, bad, total := c2.Verify()
	if ok {
		t.Fatalf("verify missed the deletion")
	}
	if bad == 0 {
		t.Fatalf("badSeq should be nonzero")
	}
	if total >= 5 {
		t.Fatalf("should not claim total >= 5 after deletion; got %d", total)
	}
}

// TestChainDetectsReorder — swap two adjacent lines in the file.
func TestChainDetectsReorder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	c, _ := New(Config{Secret: "z", FilePath: path})
	for i := 0; i < 4; i++ {
		_, _ = c.Append("block", "x", "m", "")
	}
	_ = c.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[1], lines[2] = lines[2], lines[1]
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)

	c2, _ := New(Config{Secret: "z", FilePath: path})
	defer c2.Close()
	ok, _, _ := c2.Verify()
	if ok {
		t.Fatalf("reordered log still verified clean")
	}
}

// TestChainSurvivesTruncatedTailLine — a power loss during the last
// write shouldn't invalidate the whole file.
func TestChainSurvivesTruncatedTailLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	c, _ := New(Config{Secret: "z", FilePath: path})
	for i := 0; i < 3; i++ {
		_, _ = c.Append("block", "x", "m", "")
	}
	_ = c.Close()

	// Chop off half the last line.
	raw, _ := os.ReadFile(path)
	cut := len(raw) - 20
	if cut < 0 {
		cut = 0
	}
	_ = os.WriteFile(path, raw[:cut], 0600)

	c2, _ := New(Config{Secret: "z", FilePath: path})
	defer c2.Close()
	// Append one more entry.
	e, err := c2.Append("block", "y", "m", "")
	if err != nil {
		t.Fatalf("append after truncation: %v", err)
	}
	if e.Seq < 3 {
		t.Fatalf("seq should continue after truncation; got %d", e.Seq)
	}
	ok, _, _ := c2.Verify()
	if !ok {
		t.Fatalf("verify failed after graceful tail truncation")
	}
}

// TestChainFilePersistence — entries written in one session are visible
// to Verify() run in a fresh Chain on the same file.
func TestChainFilePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	c, _ := New(Config{Secret: "persist", FilePath: path})
	_, _ = c.Append("block", "a", "first", "")
	_, _ = c.Append("config_change", "op", "mode=detect", "")
	_ = c.Close()

	// Read the raw file to make sure both entries were flushed.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 persisted entries, got %d", count)
	}

	// Fresh chain, same file + secret — should verify.
	c2, _ := New(Config{Secret: "persist", FilePath: path})
	defer c2.Close()
	ok, _, total := c2.Verify()
	if !ok {
		t.Fatalf("reopen verify failed")
	}
	if total != 2 {
		t.Fatalf("total=%d, want 2", total)
	}
	// And the next seq should be 3, not restart at 1.
	e, _ := c2.Append("block", "b", "after reopen", "")
	if e.Seq != 3 {
		t.Fatalf("seq after reopen = %d, want 3", e.Seq)
	}
}

// TestChainRejectsWrongSecret — the same file read with a different key
// should fail verification on every entry.
func TestChainRejectsWrongSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	c, _ := New(Config{Secret: "correct", FilePath: path})
	for i := 0; i < 3; i++ {
		_, _ = c.Append("block", "a", "m", "")
	}
	_ = c.Close()

	c2, _ := New(Config{Secret: "wrong", FilePath: path})
	defer c2.Close()
	ok, _, _ := c2.Verify()
	if ok {
		t.Fatalf("verification with wrong secret should fail")
	}
}

func TestChainTailOrder(t *testing.T) {
	c, _ := New(Config{Secret: "t"})
	defer c.Close()
	for i := 0; i < 10; i++ {
		_, _ = c.Append("block", "a", string(rune('A'+i)), "")
	}
	tail := c.Tail(3)
	if len(tail) != 3 {
		t.Fatalf("tail len = %d, want 3", len(tail))
	}
	if tail[0].Seq != 8 || tail[2].Seq != 10 {
		t.Fatalf("tail not in increasing seq order: %v", []uint64{tail[0].Seq, tail[1].Seq, tail[2].Seq})
	}
}

// TestValidateAuditFilePath_BlocksDevicesAndReservedNames documents
// the bypass class the path validator closes: an audit log that
// silently absorbs entries into a device file leaves no trace of
// security events. The Windows-reserved-name check runs on every
// platform — we share configs across OSes and would rather refuse
// the path on the Linux box than silently break it on Windows.
func TestValidateAuditFilePath_BlocksDevicesAndReservedNames(t *testing.T) {
	bad := []string{
		"",                              // empty
		"audit\x00.log",                 // NUL injection
		`\\server\share\audit.log`,      // UNC
		"//server/share/audit.log",      // POSIX-style network share
		`\\?\C:\audit.log`,              // Windows long-path device namespace
		"/dev/null", "/dev/zero",
		"/dev/random", "/dev/urandom",
		"/dev/full", "/dev/tty",
		// Windows reserved names — with extension, with a directory
		// prefix, and case-folded. CreateFile() honours the device
		// regardless of either.
		"con", "CON", "Nul.log", "audit/PRN", "audit/COM1.txt",
		`logs\LPT3.audit`, "AUX",
	}
	for _, p := range bad {
		if err := validateAuditFilePath(p); err == nil {
			t.Fatalf("validateAuditFilePath(%q) accepted; expected refusal", p)
		}
	}

	good := []string{
		"audit.log",
		"logs/audit.log",
		"/var/log/wewaf/audit.log",
		`C:\waf\audit.log`,
		"./audit.log",
		// "console.log" and "lptd.log" — superficially similar to
		// reserved names but neither is itself reserved.
		"console.log",
		"lptd.log",
	}
	for _, p := range good {
		if err := validateAuditFilePath(p); err != nil {
			t.Fatalf("validateAuditFilePath(%q) refused; expected acceptance: %v", p, err)
		}
	}
}

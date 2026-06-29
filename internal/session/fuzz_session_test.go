package session

import (
	"testing"
	"time"
)

// verifyCookie parses attacker-supplied cookie values on every request. A
// panic there is a per-request DoS, and a logic slip is an auth bypass. Fuzz
// with arbitrary cookie strings and assert: never panic, and a forged/garbage
// value never validates (only the tracker's own signing can produce an
// accepted value).
//
// Run:  go test ./internal/session -run x -fuzz FuzzVerifyCookie -fuzztime 30s
func FuzzVerifyCookie(f *testing.F) {
	tr := NewTracker(Config{Enabled: true, IdleTTL: time.Minute, MaxSessions: 100})

	// A genuinely-signed cookie as a seed (so the fuzzer explores near-valid).
	good := tr.signCookie("seed-session")
	f.Add(good)
	f.Add("")
	f.Add("a.b")
	f.Add("seed-session.deadbeef")
	f.Add("....")
	f.Add(good + "x") // tampered tail

	f.Fuzz(func(t *testing.T, value string) {
		id, ok := tr.verifyCookie(value)
		if ok {
			// If it validated, re-signing the returned id must reproduce the
			// exact input — i.e. only correctly-signed values are accepted.
			if tr.signCookie(id) != value {
				t.Fatalf("accepted a value that does not match its own signature: id=%q value=%q", id, value)
			}
		}
	})
}

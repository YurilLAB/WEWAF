package graphql

import (
	"strings"
	"testing"
	"time"
)

// TestValidateDeeplyNestedDoesNotExhaustStack is the regression for
// WS-GQLPARSE-001: with the default unbounded token budget, a body of deeply
// nested list literals / selection sets (reachable just under the 1 MiB extract
// cap) drove gqlparser's recursive-descent parser ~1M frames deep and crashed
// the whole process with a non-recoverable "goroutine stack exceeds
// 1000000000-byte limit" — before any post-parse depth guard could run. The
// bounded token limit must make the parser reject such input as an ordinary
// parse error in bounded time/stack instead.
func TestValidateDeeplyNestedDoesNotExhaustStack(t *testing.T) {
	v, _ := New(Config{Enabled: true, BlockOnError: true})

	// ~200k nested list-open tokens, an order of magnitude over maxParseTokens
	// but well under the 1 MiB extract cap.
	q := "{a(x:" + strings.Repeat("[", 200000)
	body := []byte(`{"query":` + toJSONString(q) + `}`)

	done := make(chan Result, 1)
	go func() { done <- v.Validate(body, "") }()
	select {
	case <-done:
		// Returned without crashing or hanging — the token cap fired.
	case <-time.After(5 * time.Second):
		t.Fatal("Validate did not return for a deeply nested query — parse was not bounded")
	}
	if v.statsParseFails.Load() == 0 {
		t.Fatalf("expected the over-nested query to be rejected as a parse failure")
	}

	// A legitimate query must still parse and validate cleanly under the cap.
	r := v.Validate([]byte(`{"query":`+toJSONString(`{ viewer { name email } }`)+`}`), "")
	if r.Blocked {
		t.Fatalf("legit query falsely blocked under the token cap: %q", r.Reason)
	}
}

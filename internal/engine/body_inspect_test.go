package engine

import (
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

// newBodyTestEngine builds an engine with the default rule set in active
// mode so blocking decisions surface as interruptions.
func newBodyTestEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = "active"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	rs, err := rules.NewRuleSet(rules.DefaultRules())
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	eng, err := NewEngine(cfg, rs, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func newBodyTx() *core.Transaction {
	req := httptest.NewRequest("POST", "/submit", nil)
	return core.NewTransaction(nil, req, nil)
}

// TestProcessRequestBodyInspectsDecodedBody guards the regression where a
// gzip/brotli-decompressed body (stored under "decoded_body") was produced
// for inspection but never inspected — letting compressed payloads bypass
// every body rule. The raw "body" is benign; the decoded form carries the
// attack and must trigger a block.
func TestProcessRequestBodyInspectsDecodedBody(t *testing.T) {
	eng := newBodyTestEngine(t)
	tx := newBodyTx()

	tx.SetMetadata("body", []byte("perfectly fine compressed-looking bytes"))
	tx.SetMetadata("decoded_body", []byte(`<script>alert(1)</script>`))

	intr := eng.ProcessRequestBody(tx)
	if intr == nil {
		t.Fatalf("expected decoded body XSS to be blocked, got no interruption")
	}
	if intr.Status != 403 {
		t.Fatalf("expected 403, got %d", intr.Status)
	}
}

// TestProcessRequestBodyInspectsGRPCTargets guards the companion gap: string
// runs extracted from protobuf frames (stored under "grpc_targets") must be
// fed to the rule engine.
func TestProcessRequestBodyInspectsGRPCTargets(t *testing.T) {
	eng := newBodyTestEngine(t)
	tx := newBodyTx()

	tx.SetMetadata("body", []byte("\x00\x00\x00\x00\x10binary-frame-noise"))
	tx.SetMetadata("grpc_targets", []string{
		"hello world",
		"1 UNION SELECT password FROM users",
	})

	intr := eng.ProcessRequestBody(tx)
	if intr == nil {
		t.Fatalf("expected SQLi in gRPC string field to be blocked, got no interruption")
	}
}

// TestProcessRequestBodyBenignDecodedBodyPasses confirms the new inspection
// path does not introduce false positives on legitimate decompressed JSON.
func TestProcessRequestBodyBenignDecodedBodyPasses(t *testing.T) {
	eng := newBodyTestEngine(t)
	tx := newBodyTx()

	tx.SetMetadata("body", []byte("compressed"))
	tx.SetMetadata("decoded_body", []byte(`{"name":"Ada Lovelace","city":"London"}`))

	if intr := eng.ProcessRequestBody(tx); intr != nil {
		t.Fatalf("benign decoded JSON must not block, got %q", intr.Message)
	}
	if c := tx.MatchCount(); c != 0 {
		ms := tx.MatchesSnapshot()
		ids := make([]string, 0, len(ms))
		for _, m := range ms {
			ids = append(ids, m.RuleID)
		}
		t.Fatalf("benign decoded JSON produced %d matches: %s", c, strings.Join(ids, ","))
	}
}

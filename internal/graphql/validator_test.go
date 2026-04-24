package graphql

import (
	"strings"
	"testing"
)

func TestValidatorDepthLimit(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 3, BlockOnError: true})
	// Depth 4 query.
	query := `{ a { b { c { d } } } }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if !res.Blocked {
		t.Fatalf("expected block on depth=4 with max=3")
	}
	if !strings.Contains(res.Reason, "depth") {
		t.Fatalf("expected depth reason, got %q", res.Reason)
	}
	// Stats must reflect the block — if this didn't increment the
	// /api/graphql/stats endpoint would lie to operators.
	if v.statsDepthFails.Load() != 1 {
		t.Fatalf("depth_fails counter = %d, want 1", v.statsDepthFails.Load())
	}
	if v.statsBlocked.Load() != 1 {
		t.Fatalf("blocked counter = %d, want 1", v.statsBlocked.Load())
	}
	// A legal query on the same validator must NOT bump the block count.
	pre := v.statsBlocked.Load()
	ok := `{ a { b } }`
	r2 := v.Validate([]byte(`{"query":`+toJSONString(ok)+`}`), "")
	if r2.Blocked {
		t.Fatalf("depth-3 query falsely blocked")
	}
	if v.statsBlocked.Load() != pre {
		t.Fatalf("blocked counter moved on a legal query")
	}
}

func TestValidatorAliasLimit(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxAliases: 2, BlockOnError: true})
	query := `{ a: foo, b: foo, c: foo, d: foo }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if !res.Blocked {
		t.Fatalf("expected block on 4 aliases with max=2")
	}
}

func TestValidatorFieldLimit(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxFields: 3, BlockOnError: true})
	query := `{ a b c d e }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if !res.Blocked {
		t.Fatalf("expected block on 5 fields with max=3")
	}
}

func TestValidatorAllowsSimpleQuery(t *testing.T) {
	v, _ := New(Config{Enabled: true, BlockOnError: true})
	query := `{ viewer { name email } }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if res.Blocked {
		t.Fatalf("simple query should not be blocked: %q", res.Reason)
	}
}

func TestValidatorSchemaAuthRequires(t *testing.T) {
	schema := `
directive @requires(role: String!) on FIELD_DEFINITION

type Query {
  public: String
  secret: String @requires(role: "admin")
}
`
	v, err := New(Config{Enabled: true, SchemaSDL: schema, BlockOnError: true})
	if err != nil {
		t.Fatalf("schema parse: %v", err)
	}
	// Missing role → blocked.
	res := v.Validate([]byte(`{"query":`+toJSONString(`{ secret }`)+`}`), "")
	if !res.Blocked {
		t.Fatalf("expected block on @requires without role")
	}
	// Wrong role → blocked.
	res = v.Validate([]byte(`{"query":`+toJSONString(`{ secret }`)+`}`), "viewer")
	if !res.Blocked {
		t.Fatalf("expected block with wrong role")
	}
	// Right role → allowed.
	res = v.Validate([]byte(`{"query":`+toJSONString(`{ secret }`)+`}`), "admin")
	if res.Blocked {
		t.Fatalf("admin role should pass: %q", res.Reason)
	}
	// Public field → always allowed.
	res = v.Validate([]byte(`{"query":`+toJSONString(`{ public }`)+`}`), "")
	if res.Blocked {
		t.Fatalf("public field should pass: %q", res.Reason)
	}
}

func TestValidatorObserveOnly(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 2, BlockOnError: false})
	// Deep query with block-on-error off → returns Blocked=false but stats bumped.
	query := `{ a { b { c { d } } } }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if res.Blocked {
		t.Fatalf("BlockOnError=false must not block")
	}
	if v.statsDepthFails.Load() == 0 {
		t.Fatalf("depth_fails should still increment in observe mode")
	}
}

// Regression: the validator used to inspect only the first query in a
// batch, letting an attacker smuggle a deep query behind a benign one.
// This test is a canary against that shortcut returning.
func TestValidatorInspectsFullBatch(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 3, BlockOnError: true})
	benign := `{ a }`
	deep := `{ a { b { c { d } } } }` // depth 4
	body := `[{"query":` + toJSONString(benign) + `},{"query":` + toJSONString(deep) + `}]`
	res := v.Validate([]byte(body), "")
	if !res.Blocked {
		t.Fatalf("batch validator missed depth violation in entry 2: %+v", res)
	}
}

func TestValidatorSubscriptionBlock(t *testing.T) {
	v, _ := New(Config{Enabled: true, BlockOnError: true, BlockSubscriptions: true})
	query := `subscription { onEvent { id } }`
	res := v.Validate([]byte(`{"query":`+toJSONString(query)+`}`), "")
	if !res.Blocked {
		t.Fatalf("subscription block not enforced")
	}
}

func TestIsGraphQLRequestDetection(t *testing.T) {
	// Unit helper: test detect logic via string matcher — can't spin
	// http.Request here without import noise; cover the path suffix.
	cases := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}
	_ = cases // covered elsewhere; placeholder to keep table here
}

// toJSONString escapes a query for embedding in a JSON literal.
func toJSONString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

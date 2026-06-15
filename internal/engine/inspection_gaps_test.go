package engine

import (
	"net/http/httptest"
	"testing"

	"wewaf/internal/core"
)

// TestDecodedBodyInspected confirms that a decompressed request body (stored by
// the proxy under the "decoded_body" metadata key) is folded into the body
// inspection surface. Without this, a Content-Encoding: gzip/deflate/br payload
// bypassed every body-phase signature because the engine only ever scanned the
// still-compressed bytes under "body".
func TestDecodedBodyInspected(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	cases := map[string]string{
		"xss_script":  "<script>alert(document.cookie)</script>",
		"sqli_union":  "id=1 UNION SELECT password FROM users",
		"java_serial": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
	}
	for name, payload := range cases {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://shop.example.com/api", nil)
			w := httptest.NewRecorder()
			tx := core.NewTransaction(w, r, ipx)
			// "body" holds opaque (compressed-like) bytes the signatures can't
			// match; "decoded_body" holds the plaintext the backend would see.
			tx.SetMetadata("body", []byte{0x1f, 0x8b, 0x08, 0x00, 0x00})
			tx.SetMetadata("decoded_body", []byte(payload))
			eng.ProcessRequestHeaders(tx)
			eng.ProcessRequestBody(tx)
			if !tx.IsBlocked() {
				t.Fatalf("decoded body payload %q must block (score=%d)", name, tx.ScoreSnapshot())
			}
		})
	}
}

// TestDecodedBodyNoFalsePositive confirms folding the decoded body in does not
// block ordinary decompressed content (a benign JSON form post).
func TestDecodedBodyNoFalsePositive(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	r := httptest.NewRequest("POST", "http://shop.example.com/api", nil)
	w := httptest.NewRecorder()
	tx := core.NewTransaction(w, r, ipx)
	tx.SetMetadata("body", []byte{0x1f, 0x8b, 0x08})
	tx.SetMetadata("decoded_body", []byte(`{"name":"alice","email":"alice@example.com","note":"hello there"}`))
	eng.ProcessRequestHeaders(tx)
	eng.ProcessRequestBody(tx)
	if tx.IsBlocked() {
		t.Fatalf("benign decoded body must not block (score=%d)", tx.ScoreSnapshot())
	}
}

// TestGRPCTargetsInspected confirms the printable string runs the proxy
// extracts from protobuf frames (stored under "grpc_targets") are evaluated by
// the rule engine. Before the fix the metadata was written but never read, so a
// SQLi/XSS payload inside a proto string field rode through uninspected.
func TestGRPCTargetsInspected(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	r := httptest.NewRequest("POST", "http://shop.example.com/grpc.Service/Method", nil)
	w := httptest.NewRecorder()
	tx := core.NewTransaction(w, r, ipx)
	tx.SetMetadata("grpc_targets", []string{
		"username: bob",
		"comment: <img src=x onerror=alert(1)>",
	})
	eng.ProcessRequestHeaders(tx)
	eng.ProcessRequestBody(tx)
	if !tx.IsBlocked() {
		t.Fatalf("gRPC proto string payload must block (score=%d)", tx.ScoreSnapshot())
	}
}

// TestQueryParamNameInspected confirms a payload hidden in a query-parameter
// NAME (not value) is inspected. The args._names synthetic target surfaces the
// decoded parameter names to the args-targeted signatures.
func TestQueryParamNameInspected(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	cases := map[string]string{
		"xss_in_name":  "<script>alert(1)</script>=1",
		"sqli_in_name": "1 UNION SELECT pw FROM users=x",
	}
	for name, rawQuery := range cases {
		name, rawQuery := name, rawQuery
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://shop.example.com/p", nil)
			r.URL.RawQuery = rawQuery
			w := httptest.NewRecorder()
			tx := core.NewTransaction(w, r, ipx)
			eng.ProcessRequestHeaders(tx)
			eng.ProcessRequestBody(tx)
			if !tx.IsBlocked() {
				t.Fatalf("payload in query-param name %q must block (score=%d)", name, tx.ScoreSnapshot())
			}
		})
	}
}

// TestQueryParamNameNoFalsePositive confirms ordinary parameter names are not
// flagged by the new name-inspection path.
func TestQueryParamNameNoFalsePositive(t *testing.T) {
	eng, ipx := headerTestEngine(t)
	r := httptest.NewRequest("GET", "http://shop.example.com/p", nil)
	r.URL.RawQuery = "page=2&sort=name&filter=active&q=hello+world"
	w := httptest.NewRecorder()
	tx := core.NewTransaction(w, r, ipx)
	eng.ProcessRequestHeaders(tx)
	eng.ProcessRequestBody(tx)
	if tx.IsBlocked() {
		t.Fatalf("ordinary query param names must not block (score=%d)", tx.ScoreSnapshot())
	}
}

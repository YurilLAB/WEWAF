package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// evaluateHardening is the first-line protocol-abuse gate (request smuggling,
// CR/LF header injection, double-encoded traversal, dangerous methods, Host
// sanity) and runs on every request before any other inspection. Its inputs —
// method, path, Host, and every header name/value — are wholly attacker-
// controlled. A panic is a request-level DoS; a logic gap is a bypass of the
// smuggling/injection defences. We build the request struct directly (rather
// than via http.NewRequest) so the thing under test is OUR logic, not net/http's
// inbound validation.
//
// Run:  go test ./internal/proxy -run x -fuzz FuzzEvaluateHardening -fuzztime 30s
func FuzzEvaluateHardening(f *testing.F) {
	f.Add("GET", "/", "example.com", "X-Test", "ok", false, "")
	f.Add("POST", "/a/../b", "h", "X-Inject", "a\r\nb", false, "")
	f.Add("TRACE", "/", "h", "", "", false, "")
	f.Add("GET", "/%252e%252e/x", "h", "", "", false, "chunked")
	f.Add("PUT", "/", "evil.com/path", "", "", true, "chunked")
	f.Add("GET", "/", "h", "Transfer-Encoding", "chunked, chunked", false, "gzip")

	f.Fuzz(func(t *testing.T, method, rawPath, host, hname, hval string, setCL bool, teVal string) {
		h := http.Header{}
		if hname != "" {
			h[hname] = []string{hval}
		}
		if setCL {
			h.Set("Content-Length", "10")
		}
		if teVal != "" {
			h.Set("Transfer-Encoding", teVal)
		}
		u := &url.URL{Path: rawPath, RawPath: rawPath}
		r := &http.Request{
			Method: method,
			URL:    u,
			Header: h,
			Host:   host,
		}

		// Contract 1: never panics.
		v := evaluateHardening(r)

		// Contract 2 (metamorphic regression guard): a CR/LF anywhere in a header
		// name or value MUST be rejected — that is the response-splitting defence.
		if hname != "" && (strings.ContainsAny(hname, "\r\n") || strings.ContainsAny(hval, "\r\n")) {
			if !v.Reject {
				t.Fatalf("CR/LF in header (name=%q val=%q) was NOT rejected", hname, hval)
			}
		}

		// Contract 3: Content-Length together with Transfer-Encoding is the
		// textbook smuggling desync and MUST be rejected.
		if setCL && teVal != "" {
			if !v.Reject {
				t.Fatalf("CL+TE (te=%q) was NOT rejected", teVal)
			}
		}

		// Contract 4: a rejection always carries a status and a rule id, so the
		// caller can emit a coherent response + metric.
		if v.Reject && (v.Status == 0 || v.RuleID == "") {
			t.Fatalf("rejection missing status/ruleID: %+v", v)
		}
	})
}

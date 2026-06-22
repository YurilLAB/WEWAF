package integration_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

// gzipBytes returns the gzip-compressed form of p.
func gzipBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(p); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestBlocksPlaintextBodyXSS is the control: an uncompressed XSS payload in
// the request body must be blocked by the body rule engine. If this fails,
// the compressed-body test below proves nothing.
func TestBlocksPlaintextBodyXSS(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	payload := []byte(`<script>alert(1)</script>`)
	resp, err := http.Post(frontend.URL+"/comment", "text/plain", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("plaintext XSS body should be blocked (403), got %d: %s", resp.StatusCode, b)
	}
}

// TestBlocksGzipBodyXSS demonstrates that a payload which is blocked in
// plaintext must also be blocked when the client gzip-encodes it. With
// DecompressInspect enabled (the default), the proxy decompresses the body
// for inspection — so the rule engine MUST see the decompressed content.
//
// Before the fix this returned 200: the engine only inspected the raw
// (compressed) bytes, which match no signature, so any gzip/brotli-wrapped
// attack bypassed every body rule.
func TestBlocksGzipBodyXSS(t *testing.T) {
	frontend, backend, _, _, stop := newTestProxy(t)
	defer stop()
	_ = backend

	payload := []byte(`<script>alert(1)</script>`)
	compressed := gzipBytes(t, payload)

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/comment", bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("gzip-encoded XSS body should be blocked (403), got %d: %s\n"+
			"the decompressed body is not being inspected — compression bypasses all body rules",
			resp.StatusCode, body)
	}
}

// TestFormUrlEncodedBodyXSS probes whether a URL-encoded form body smuggles
// a payload past the body rules. Query-string args are URL-decoded and
// canonicalized before matching; if the request body is not, then
// `q=%3Cscript%3E...` reaches the backend as `<script>...` while the WAF
// only ever sees the percent-encoded form.
func TestFormUrlEncodedBodyXSS(t *testing.T) {
	frontend, _, _, _, stop := newTestProxy(t)
	defer stop()

	// URL-encoded <script>alert(1)</script>
	body := "comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/comment", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("url-encoded form-body XSS should be blocked (403), got %d: %s", resp.StatusCode, out)
	}
}

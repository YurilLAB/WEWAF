package proxy

import (
	"bytes"
	"compress/zlib"
	"testing"
)

// TestDeflateBodyIsDecompressedForInspection is the regression guard for the
// deflate bypass: a deflate-encoded request body must be decompressed so the
// rule engine sees the real payload, not opaque compressed bytes. Before the
// fix, "deflate" fell through to "inspect raw", letting an attacker hide an
// injection one zlib layer deep.
func TestDeflateBodyIsDecompressedForInspection(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	payload := []byte("<script>alert(1)</script>")
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	headers := map[string][]string{"Content-Encoding": {"deflate"}}
	decoded, reason := maybeDecompressBody(headers, buf.Bytes(), 100, 1<<20)
	if reason != "" {
		t.Fatalf("deflate body should decode cleanly, got reject reason %q", reason)
	}
	if !bytes.Contains(decoded, payload) {
		t.Fatalf("deflate body did not decode to the payload; got %q", decoded)
	}
}

// TestStackedContentEncodingRejected is the regression guard for the layered
// content-encoding bypass: stacked encodings on a request body are a
// WAF-evasion trick and must be refused (a non-empty reject reason), not
// inspected one layer too shallow. Covers both the comma-joined and the
// repeated-header-line forms.
func TestStackedContentEncodingRejected(t *testing.T) {
	if _, reason := maybeDecompressBody(
		map[string][]string{"Content-Encoding": {"gzip, gzip"}},
		[]byte("anything"), 100, 1<<20); reason == "" {
		t.Fatal("comma-joined stacked content-encoding must be rejected, not inspected raw")
	}
	if _, reason := maybeDecompressBody(
		map[string][]string{"Content-Encoding": {"br", "gzip"}},
		[]byte("anything"), 100, 1<<20); reason == "" {
		t.Fatal("multi-line stacked content-encoding must be rejected, not inspected raw")
	}
}

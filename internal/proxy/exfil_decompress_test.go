package proxy

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// TestExfilDecompressesBeforeScan is the regression for the egress exfil
// compressed-response bypass: the inspector scanned the RAW response bytes, so
// gzip-encoding the response hid AWS keys / PANs from the plaintext scanner
// (findings=0) even though the decompressed body clearly leaks them. The fix
// decompresses a copy before scanning, matching the sibling reverse-proxy path.
func TestExfilDecompressesBeforeScan(t *testing.T) {
	// Canonical AWS doc placeholder built at runtime (secret-scanner friendly)
	// plus a Luhn-valid test PAN.
	key := "AKIA" + strings.Repeat("A", 13) + "BCD"
	plaintext := []byte(`{"aws":"` + key + `","card":"4111111111111111"}`)

	// Sanity: the plaintext genuinely trips the scanner.
	if findings := inspectEgressResponseBody(plaintext); len(findings) < 2 {
		t.Fatalf("plaintext should yield >=2 findings (aws+card), got %d", len(findings))
	}

	// gzip the body the way a backend that set its own Accept-Encoding would.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := gz.Bytes()

	// The bug: scanning the raw gzip bytes finds nothing.
	if findings := inspectEgressResponseBody(compressed); len(findings) != 0 {
		t.Fatalf("raw gzip bytes should not match the plaintext scanner, got %d findings", len(findings))
	}

	// The fix: decompress-for-inspection (Content-Encoding: gzip) then scan —
	// the secrets are recovered. This is exactly what the ServeHTTP egress path
	// now does before forwarding the original (still-compressed) bytes.
	headers := map[string][]string{"Content-Encoding": {"gzip"}}
	decoded, reason := maybeDecompressBody(headers, compressed, 100, 10*1024*1024)
	if reason != "" {
		t.Fatalf("unexpected decompress reject: %s", reason)
	}
	if findings := inspectEgressResponseBody(decoded); len(findings) < 2 {
		t.Fatalf("decompressed gzip should yield >=2 findings, got %d (bypass still open)", len(findings))
	}
}

package engine

import "testing"

// TestCL0SmugglingBody closes the CRS-921110 offset-0 gap: a request-shaped body
// (the CL.0 / 0.CL desync primitive) starting at byte 0 must be flagged, while a
// benign body that merely begins "GET /..." (no HTTP/ request line) must not.
func TestCL0SmugglingBody(t *testing.T) {
	eng := newFuzzEngine(t)

	// CL.0 primitive: the entire body is a smuggled request line at offset 0.
	if !blockedInRawBody(eng, "GET /admin/users HTTP/1.1\r\nFoo: bar\r\n\r\n") {
		t.Error("CL.0 request-shaped body (offset 0) was NOT blocked")
	}
	// Classic second-line embedded request still blocks (control).
	if !blockedInRawBody(eng, "x=1\r\nGET /admin HTTP/1.1\r\n\r\n") {
		t.Error("second-line embedded request was NOT blocked")
	}
	// Benign bodies must NOT block.
	for _, b := range []string{
		"GET /api/v1/users is the endpoint we document here",
		`{"method":"GET","path":"/admin"}`,
		"please POST /feedback with your comments",
	} {
		if blockedInRawBody(eng, b) {
			t.Errorf("false positive: benign body %q was blocked", b)
		}
	}
}

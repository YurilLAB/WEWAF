package proxy

import (
	"net/http"
	"testing"
)

func mkResp(ct string) *http.Response {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{Header: h, StatusCode: 200}
}

// TestIsStreamingContentType is the regression for RESP-SSE-001: the body
// buffer/inspect path must be skipped for long-lived streaming responses (so
// io.ReadAll doesn't block until the stream closes), but NOT for ordinary
// responses — including plain chunked HTML/JSON — which must stay inspected.
func TestIsStreamingContentType(t *testing.T) {
	streaming := []string{
		"text/event-stream",
		"text/event-stream; charset=utf-8",
		"multipart/x-mixed-replace; boundary=frame",
		"application/grpc",
		"application/grpc+proto",
		"APPLICATION/GRPC", // case-insensitive
	}
	for _, ct := range streaming {
		if !isStreamingContentType(mkResp(ct)) {
			t.Errorf("content-type %q should be treated as streaming", ct)
		}
	}
	notStreaming := []string{
		"", "text/html", "text/html; charset=utf-8", "application/json",
		"text/plain", "application/octet-stream",
	}
	for _, ct := range notStreaming {
		if isStreamingContentType(mkResp(ct)) {
			t.Errorf("content-type %q must NOT be streaming (would skip body inspection)", ct)
		}
	}
}

// TestStripUninspectableResponseTrailers is the regression for RESP-TRAILER-001:
// response trailers (which the WAF cannot inspect, as their values arrive after
// the body) must be stripped from normal forwarded responses, but preserved for
// gRPC where grpc-status legitimately rides in a trailer.
func TestStripUninspectableResponseTrailers(t *testing.T) {
	// Normal response: announced trailer + the trailer map are both removed.
	res := mkResp("text/html")
	res.Header.Set("Trailer", "X-Leak")
	res.Trailer = http.Header{"X-Leak": []string{"AKIA" + "0123456789ABCDEF"}}
	stripUninspectableResponseTrailers(res)
	if res.Trailer != nil {
		t.Errorf("trailers should be stripped on a normal response, got %v", res.Trailer)
	}
	if res.Header.Get("Trailer") != "" {
		t.Errorf("Trailer announce header should be removed, got %q", res.Header.Get("Trailer"))
	}

	// gRPC: trailers must survive (grpc-status/grpc-message live there).
	g := mkResp("application/grpc")
	g.Header.Set("Trailer", "grpc-status")
	g.Trailer = http.Header{"grpc-status": []string{"0"}}
	stripUninspectableResponseTrailers(g)
	if g.Trailer == nil {
		t.Error("gRPC response trailers must be preserved")
	}
	if g.Header.Get("Trailer") == "" {
		t.Error("gRPC Trailer announce header must be preserved")
	}
}

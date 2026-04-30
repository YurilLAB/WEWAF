package dpi

import (
	"encoding/binary"
	"net/http/httptest"
	"strings"
	"testing"
)

// helper: build a gRPC-style frame.
func grpcFrame(payload string, compressed bool) []byte {
	buf := make([]byte, 5+len(payload))
	if compressed {
		buf[0] = 0x01
	}
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

func TestGRPCDetection(t *testing.T) {
	cases := map[string]bool{
		"application/grpc":             true,
		"application/grpc+proto":       true,
		"application/grpc+json":        true,
		"application/grpc-web":         true,
		"application/json":             false,
		"":                             false,
		"application/grpcsomething":    true, // prefix match — intentional
	}
	for ct, want := range cases {
		r := httptest.NewRequest("POST", "/", strings.NewReader(""))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		got := IsGRPCRequest(r)
		if got != want {
			t.Errorf("IsGRPCRequest(%q) = %v, want %v", ct, got, want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Content-Type", "application/grpc")
	if IsGRPCRequest(r) {
		t.Errorf("GET should never be gRPC")
	}
}

func TestGRPCParsesMultipleFrames(t *testing.T) {
	body := append(grpcFrame("user@example.com was born on 2001-01-01", false),
		grpcFrame("another string here", false)...)
	res := InspectGRPCBody(body, GRPCLimits{})
	if res.Blocked {
		t.Fatalf("unexpected block: %s", res.Reason)
	}
	if res.Stats.Frames != 2 {
		t.Fatalf("frames = %d, want 2", res.Stats.Frames)
	}
	if len(res.ScanTargets) == 0 {
		t.Fatalf("expected scan targets to be extracted")
	}
	joined := strings.Join(res.ScanTargets, "|")
	if !strings.Contains(joined, "user@example.com") {
		t.Fatalf("printable run missing: %q", joined)
	}
}

func TestGRPCBlocksOversizeFrame(t *testing.T) {
	// Forge a length-prefix claiming 10 MiB but with only 10 bytes of body —
	// the inspector must use the declared length, not the actual remainder,
	// to avoid integer-underflow bypasses.
	big := make([]byte, 5+10)
	big[0] = 0
	binary.BigEndian.PutUint32(big[1:5], 10*1024*1024)
	res := InspectGRPCBody(big, GRPCLimits{MaxFrameBytes: 1024})
	if !res.Blocked {
		t.Fatalf("expected block on oversize frame")
	}
	if !strings.Contains(res.Reason, "exceeds max") {
		t.Fatalf("reason: %s", res.Reason)
	}
}

func TestGRPCToleratesTruncation(t *testing.T) {
	frame := grpcFrame("hello world", false)
	// Chop the last byte — simulates a streaming body that hasn't fully
	// arrived. We must not block; we must note Truncated=true.
	truncated := frame[:len(frame)-1]
	res := InspectGRPCBody(truncated, GRPCLimits{})
	if res.Blocked {
		t.Fatalf("truncation must not block: %s", res.Reason)
	}
	if !res.Stats.Truncated {
		t.Fatalf("expected Truncated=true")
	}
}

func TestGRPCCompressedFrameSkipsStringExtraction(t *testing.T) {
	body := grpcFrame("this won't decompress", true)
	res := InspectGRPCBody(body, GRPCLimits{})
	if res.Stats.Compressed != 1 {
		t.Fatalf("Compressed counter = %d, want 1", res.Stats.Compressed)
	}
	if len(res.ScanTargets) != 0 {
		t.Fatalf("should skip string extraction on compressed frames")
	}
}

// TestGRPCRejectsLengthBeyondInt32 closes the 32-bit cast bypass:
// a malicious frame declared as 0xFFFFFFFF bytes used to slip past
// the "int(length) > MaxFrameBytes" check on 32-bit hosts (where
// int(0xFFFFFFFF) == -1) and crash the parser via a panic in the
// subsequent slice expression. The check now stays in uint64 / has
// an explicit int32 ceiling so the bypass is impossible regardless
// of host word size.
func TestGRPCRejectsLengthBeyondInt32(t *testing.T) {
	// Hand-craft a frame whose declared length is uint32-max. We
	// only need 5 bytes (the header); the parser must refuse based
	// on the length field before touching the (absent) payload.
	body := make([]byte, 5)
	body[0] = 0
	body[1], body[2], body[3], body[4] = 0xff, 0xff, 0xff, 0xff
	res := InspectGRPCBody(body, GRPCLimits{MaxFrameBytes: 1 << 20})
	if !res.Blocked {
		t.Fatalf("uint32-max length must be rejected (Reason=%q)", res.Reason)
	}
	if res.Stats.Oversize != 1 {
		t.Fatalf("Oversize counter = %d, want 1", res.Stats.Oversize)
	}
}

// TestGRPCBlockCompressedFailsClosed documents the bypass class the
// BlockCompressed knob closes: an attacker can hide a payload behind
// any compression codec the inspector doesn't decode, and without
// fail-closed semantics the rule engine never sees the body.
func TestGRPCBlockCompressedFailsClosed(t *testing.T) {
	body := grpcFrame("opaque-codec-payload", true)
	res := InspectGRPCBody(body, GRPCLimits{BlockCompressed: true})
	if !res.Blocked {
		t.Fatalf("BlockCompressed should reject compressed frames")
	}
	if res.Reason == "" {
		t.Fatalf("BlockCompressed verdict missing reason for operator visibility")
	}
}

func TestGRPCBlocksFrameCountBomb(t *testing.T) {
	// 100 tiny frames with a cap of 50.
	var body []byte
	for i := 0; i < 100; i++ {
		body = append(body, grpcFrame("ab", false)...)
	}
	res := InspectGRPCBody(body, GRPCLimits{MaxFrames: 50, MaxFrameBytes: 1024})
	if !res.Blocked {
		t.Fatalf("expected frame-count block")
	}
}

func TestGRPCExtractsSQLInjectionString(t *testing.T) {
	// Simulate a protobuf string field containing a SQLi payload.
	payload := "\x12\x1c' OR 1=1 --"
	res := InspectGRPCBody(grpcFrame(payload, false), GRPCLimits{})
	if len(res.ScanTargets) == 0 {
		t.Fatalf("expected to extract injection substring")
	}
	joined := strings.Join(res.ScanTargets, "|")
	if !strings.Contains(joined, "OR 1=1") {
		t.Fatalf("sqli string not extracted: %q", joined)
	}
}

func TestExtractPrintableRunsLengthFloor(t *testing.T) {
	// 3-character run must not come through; 4+ does.
	b := []byte{0x01, 0x02, 'a', 'b', 'c', 0x03, 'h', 'e', 'l', 'l', 'o'}
	runs := extractPrintableRuns(b)
	for _, r := range runs {
		if len(r) < 4 {
			t.Fatalf("run below floor: %q", r)
		}
	}
	if len(runs) == 0 || runs[0] != "hello" {
		t.Fatalf("expected 'hello' run, got %v", runs)
	}
}

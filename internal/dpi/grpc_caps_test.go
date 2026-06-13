package dpi

import (
	"strings"
	"testing"
)

// TestGRPCCompressedFramesRespectFrameCap is the regression guard for the
// cap-ordering bug: the MaxFrames / MaxTotalBytes caps used to sit AFTER the
// compressed-frame `continue`, so a body made entirely of compressed frames
// never tripped them. The caps must apply uniformly, compressed or not.
func TestGRPCCompressedFramesRespectFrameCap(t *testing.T) {
	var body []byte
	for i := 0; i < 50; i++ {
		body = append(body, grpcFrame("", true)...) // compressed, zero-length frames
	}
	res := InspectGRPCBody(body, GRPCLimits{MaxFrames: 10, MaxFrameBytes: 1 << 20, MaxTotalBytes: 1 << 20})
	if !res.Blocked {
		t.Fatalf("expected block when compressed frame count exceeds MaxFrames=10 (saw %d frames)", res.Stats.Frames)
	}
	if !strings.Contains(res.Reason, "frame count") {
		t.Fatalf("expected a frame-count block reason, got %q", res.Reason)
	}
}

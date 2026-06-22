package dpi

import (
	"bytes"
	"testing"
)

// Binary parsers fed straight from untrusted request bodies / sockets are the
// classic place for length-field panics (slice out of range, huge make()).
// These fuzzers assert the gRPC frame inspector and the RFC 6455 frame reader
// never panic and honour their byte caps on arbitrary input.
//
// Run e.g.:  go test ./internal/dpi -run x -fuzz FuzzInspectGRPCBody -fuzztime 30s

func FuzzInspectGRPCBody(f *testing.F) {
	// Seeds: empty, a valid 1-byte frame, a frame claiming a huge length, and
	// the length-prefix framing edge cases.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x41})             // 1-byte payload "A"
	f.Add([]byte{0x00, 0xff, 0xff, 0xff, 0xff})                   // claims 4GiB, no body
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x41, 0x42, 0x43}) // compressed flag
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                         // truncated header

	lim := GRPCLimits{MaxFrames: 1024, MaxFrameBytes: 1 << 20, MaxTotalBytes: 16 << 20}
	f.Fuzz(func(t *testing.T, body []byte) {
		res := InspectGRPCBody(body, lim)
		// Each extracted scan target must be within the body's size budget —
		// the inspector must never fabricate or over-read.
		for _, s := range res.ScanTargets {
			if len(s) > len(body)+16 {
				t.Fatalf("scan target longer than body: %d > %d", len(s), len(body))
			}
		}
	})
}

func FuzzReadWSFrame(f *testing.F) {
	f.Add([]byte{0x81, 0x00})                               // empty text frame
	f.Add([]byte{0x81, 0x85, 0x01, 0x02, 0x03, 0x04, 0x41}) // masked, len 5, truncated
	f.Add([]byte{0x82, 0x7e, 0xff, 0xff})                   // 16-bit ext len, no body
	f.Add([]byte{0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // 64-bit huge len
	f.Add([]byte{0x88, 0x00})                               // close frame

	f.Fuzz(func(t *testing.T, raw []byte) {
		// The reader must never panic and must never allocate/return a payload
		// larger than the cap regardless of the advertised length field.
		const cap = 1 << 16
		fr, err := ReadWSFrame(bytes.NewReader(raw), cap)
		if err == nil && len(fr.Payload) > cap {
			t.Fatalf("payload %d exceeds cap %d", len(fr.Payload), cap)
		}
	})
}

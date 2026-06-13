package dpi

import (
	"bytes"
	"testing"
)

// FuzzReadWSFrame hammers the RFC 6455 frame reader with arbitrary bytes. A
// crafted frame header (64-bit length with the MSB set, masking edge cases,
// oversized payload claim) is a classic binary-parser crash / over-read
// surface. The reader must never panic; errors are expected and fine. Run:
//   go test -run=^$ -fuzz=^FuzzReadWSFrame$ -fuzztime=75s ./internal/dpi/
func FuzzReadWSFrame(f *testing.F) {
	f.Add([]byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'})                       // text "hello"
	f.Add([]byte{0x81, 0x85, 0x00, 0x00, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}) // masked
	f.Add([]byte{0x81, 0xfe, 0xff, 0xff})                                    // 16-bit length, truncated
	f.Add([]byte{0x81, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0})                     // 64-bit length, MSB set (illegal)
	f.Add([]byte{0x88, 0x7e, 0x00, 0x7e})                                    // close frame, oversized control
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// 16 KiB cap mirrors a realistic per-frame inspection bound.
		_, _ = ReadWSFrame(bytes.NewReader(data), 16<<10)
	})
}

// FuzzInspectGRPCBody hammers the length-prefixed Protobuf frame parser with
// arbitrary bytes. This is a classic binary-parser crash surface: a bad length
// field can drive an out-of-bounds slice or an unbounded loop. A panic here is
// a remote DoS of the WAF. Run:
//   go test -run=^$ -fuzz=^FuzzInspectGRPCBody$ -fuzztime=90s ./internal/dpi/
func FuzzInspectGRPCBody(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'}) // one 3-byte frame
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00})                // compressed, empty
	f.Add([]byte{0x00, 0xff, 0xff, 0xff, 0xff})                // length ~4GiB, truncated
	f.Add([]byte{0x00, 0x7f, 0xff, 0xff, 0xff})                // length = max int32
	f.Add([]byte{0x00, 0x80, 0x00, 0x00, 0x00})                // length crosses int32 sign bit
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		res := InspectGRPCBody(body, GRPCLimits{MaxFrames: 1024, MaxFrameBytes: 1 << 20, MaxTotalBytes: 16 << 20})
		// Accounted payload bytes can never exceed the body we were handed —
		// that would mean the parser read past its buffer.
		if res.Stats.Bytes < 0 || res.Stats.Bytes > len(body) {
			t.Fatalf("grpc Stats.Bytes=%d out of range for body len %d", res.Stats.Bytes, len(body))
		}
		if res.Stats.Frames < 0 {
			t.Fatalf("grpc Stats.Frames negative: %d", res.Stats.Frames)
		}
	})
}

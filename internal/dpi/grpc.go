// Package dpi implements deep packet inspection for binary / framed
// protocols (gRPC length-prefixed Protobuf frames, WebSocket RFC 6455
// data frames) that a classic HTTP body-pattern WAF can't see through.
//
// The design constraint: we never try to be a complete protocol parser.
// Full protobuf decoding requires the schema (.proto descriptors) and
// WebSocket message reassembly requires tracking continuation frames
// across connection lifetime. Both can go wrong and block legit
// traffic. Instead, each inspector does the minimum work needed to
//
//   - bound per-frame and per-connection resource use,
//   - peel off the outer framing so the existing HTTP-body rule set can
//     match against the raw payload bytes,
//   - surface a clear block-or-allow verdict with a reason code.
//
// Everything is fail-open on parse failure: a frame we can't decode is
// logged and forwarded, not dropped — the backend is a stricter parser
// than we are and will reject malformed traffic on its own merits.
package dpi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// GRPCContentTypes lists the MIME types gRPC clients set. The `+proto`
// / `+json` suffixes appear in the spec for codec negotiation; we match
// by prefix to catch all variants without enumerating every codec.
var grpcContentTypes = []string{
	"application/grpc",
	"application/grpc+proto",
	"application/grpc+json",
	"application/grpc-web",
	"application/grpc-web+proto",
	"application/grpc-web-text",
}

// IsGRPCRequest returns true when the request is gRPC. The spec mandates
// POST with a `Content-Type` starting with application/grpc; gRPC-Web
// uses the same convention.
func IsGRPCRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	for _, want := range grpcContentTypes {
		if strings.HasPrefix(ct, want) {
			return true
		}
	}
	return false
}

// GRPCFrame is one length-prefixed payload from a gRPC stream.
//
// Wire format per the gRPC spec:
//
//	+--------+----------------+---------------------+
//	| 1 byte |    4 bytes     |    N bytes payload  |
//	+--------+----------------+---------------------+
//	  flags   length (BE u32)   (protobuf or codec)
//
// The low bit of flags indicates compression. We don't decompress —
// compressed payloads pass through with Compressed=true so the caller
// can choose to skip rule matching or mark it uninspectable.
type GRPCFrame struct {
	Compressed bool
	Payload    []byte
}

// GRPCStats is returned by the inspector so admin UIs can render
// per-request diagnostics without a second pass over the body.
type GRPCStats struct {
	Frames      int
	Bytes       int
	Compressed  int
	Oversize    int
	Truncated   bool
	LargestFrame int
}

// GRPCLimits bounds how much work one request can make the inspector do.
// Zero values fall back to safe defaults.
type GRPCLimits struct {
	MaxFrames     int // hard cap on frames per body (default 1024)
	MaxFrameBytes int // per-frame payload cap (default 1 MiB)
	MaxTotalBytes int // sum of all payloads (default 16 MiB)
}

func (l *GRPCLimits) applyDefaults() {
	if l.MaxFrames <= 0 {
		l.MaxFrames = 1024
	}
	if l.MaxFrameBytes <= 0 {
		l.MaxFrameBytes = 1 << 20
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = 16 << 20
	}
}

// GRPCResult is the inspector output. Blocked is authoritative — when
// true, the caller should return 400/413 without forwarding.
type GRPCResult struct {
	Blocked      bool
	Reason       string
	Stats        GRPCStats
	ScanTargets  []string // decoded string-like fields for the rule engine
}

// ErrTruncatedFrame is returned when the body ends mid-frame. A benign
// short read from a streaming client hits this; so does a malicious
// client trying to confuse the parser. Either way, forward-with-log.
var ErrTruncatedFrame = errors.New("grpc: truncated frame")

// InspectGRPCBody parses the length-prefixed frames inside body and
// returns a verdict plus string-like fields extracted from each frame.
// body is expected to be the full POST body (already bounded by the
// caller's MaxBodyBytes).
//
// The string extraction is intentionally naive: we run each payload's
// bytes through a UTF-8 "valid string run of >= 4 chars" scanner. That
// catches injection attempts that ride inside proto string fields
// without needing the schema. False positives on random protobuf tag
// bytes are possible; they're passed to the rule engine as low-priority
// targets and the engine's existing canonicalisation + paranoia gating
// decides what to do with them.
func InspectGRPCBody(body []byte, limits GRPCLimits) GRPCResult {
	limits.applyDefaults()
	res := GRPCResult{}
	if len(body) == 0 {
		return res
	}

	var cursor int
	for cursor < len(body) {
		if len(body)-cursor < 5 {
			res.Stats.Truncated = true
			break
		}
		flags := body[cursor]
		length := binary.BigEndian.Uint32(body[cursor+1 : cursor+5])
		cursor += 5
		if int(length) > limits.MaxFrameBytes {
			res.Blocked = true
			res.Reason = fmt.Sprintf("grpc frame %d bytes exceeds max %d", length, limits.MaxFrameBytes)
			res.Stats.Oversize++
			return res
		}
		if cursor+int(length) > len(body) {
			res.Stats.Truncated = true
			break
		}
		payload := body[cursor : cursor+int(length)]
		cursor += int(length)

		res.Stats.Frames++
		res.Stats.Bytes += int(length)
		if int(length) > res.Stats.LargestFrame {
			res.Stats.LargestFrame = int(length)
		}
		if flags&0x01 != 0 {
			res.Stats.Compressed++
			// Skip string extraction on compressed payloads — it'd just
			// return noise. The rule engine won't see into them; that's
			// the tradeoff of gRPC compression being per-frame.
			continue
		}
		if res.Stats.Frames > limits.MaxFrames {
			res.Blocked = true
			res.Reason = fmt.Sprintf("grpc frame count %d exceeds max %d", res.Stats.Frames, limits.MaxFrames)
			return res
		}
		if res.Stats.Bytes > limits.MaxTotalBytes {
			res.Blocked = true
			res.Reason = fmt.Sprintf("grpc total bytes %d exceeds max %d", res.Stats.Bytes, limits.MaxTotalBytes)
			return res
		}
		res.ScanTargets = append(res.ScanTargets, extractPrintableRuns(payload)...)
	}
	return res
}

// extractPrintableRuns finds maximal runs of valid UTF-8 printable
// characters of length >= 4. We apply the length floor because proto
// varint encoding produces short printable-by-accident byte sequences
// (e.g. field tag 0x0a which is '\n'); 4+ char runs are much more
// likely to actually be string fields.
func extractPrintableRuns(b []byte) []string {
	var out []string
	const minRun = 4
	i := 0
	for i < len(b) {
		r, size := utf8.DecodeRune(b[i:])
		if size == 0 {
			break
		}
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if !isPrintable(r) {
			i += size
			continue
		}
		start := i
		for i < len(b) {
			r, size = utf8.DecodeRune(b[i:])
			if size == 0 || (r == utf8.RuneError && size == 1) || !isPrintable(r) {
				break
			}
			i += size
		}
		run := string(b[start:i])
		if utf8.RuneCountInString(run) >= minRun {
			out = append(out, run)
		}
	}
	return out
}

func isPrintable(r rune) bool {
	// Exclude control chars except tab/space — protobuf strings usually
	// don't contain CR/LF, and excluding them keeps our runs cleaner.
	if r == '\t' || r == ' ' {
		return true
	}
	if r < 0x20 || r == 0x7f {
		return false
	}
	return true
}

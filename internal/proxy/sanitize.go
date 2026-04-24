package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// maybeDecompressBody inspects Content-Encoding and, for gzip / br encodings,
// decompresses the body into a ratio-capped buffer. Returns the decoded
// payload and an empty reason string on success. A non-empty reason indicates
// the body looked like a decompression bomb and the caller should reject the
// request. A nil slice with an empty reason means the encoding was not
// recognised (no decompression attempted); in that case the caller should
// fall back to the raw body.
//
// ratioCap: max allowed (decompressed / compressed) ratio. 100 is a
// conservative default — real gzip compression ratios top out around 10-20.
// maxBytes: absolute decompressed-size cap.
//
// This function is defensive: any panic from a malformed stream is caught
// and converted to a reject reason, so a hostile payload can't crash the
// proxy. Integer overflow on the limit calculation is also guarded.
func maybeDecompressBody(headers map[string][]string, body []byte, ratioCap int, maxBytes int64) (decoded []byte, rejectReason string) {
	defer func() {
		if r := recover(); r != nil {
			// Brotli/gzip readers occasionally panic on crafted input. Treat
			// this as a bomb rather than letting the daemon crash.
			decoded = nil
			rejectReason = fmt.Sprintf("decompress panic: %v", r)
		}
	}()

	if len(body) == 0 {
		return nil, ""
	}
	enc := strings.ToLower(strings.TrimSpace(firstHeader(headers, "Content-Encoding")))
	if enc == "" || enc == "identity" {
		return nil, ""
	}
	if ratioCap <= 0 {
		ratioCap = 100
	}
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024
	}
	// Overflow-safe limit: len(body) * ratioCap can overflow int64 for a
	// 100 MB body and cap=100, but only if someone set maxBytes absurdly
	// high. Saturate at maxBytes / math.MaxInt64 instead of wrapping.
	var limit int64
	bodyLen := int64(len(body))
	if bodyLen > 0 && int64(ratioCap) > maxBytes/bodyLen {
		limit = maxBytes
	} else {
		limit = bodyLen * int64(ratioCap)
		if limit > maxBytes {
			limit = maxBytes
		}
	}
	if limit < 1024 {
		// A cap under 1 KiB is useless and likely a misconfiguration. Raise
		// to a floor so legitimate small payloads still decode. 1 KiB is
		// well under anything real and well over anything empty.
		limit = 1024
	}

	var r io.ReadCloser
	var err error
	switch {
	case enc == "gzip" || enc == "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Sprintf("gzip decode: %v", err)
		}
	case enc == "br":
		r = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	case enc == "deflate":
		// RFC 7230 says deflate may be raw deflate or zlib-wrapped; most
		// servers emit zlib. Leave unhandled rather than guess wrong — the
		// caller will simply inspect the compressed bytes.
		return nil, ""
	default:
		// Multi-value (e.g. "gzip, br") or unknown encoding — let the caller
		// fall back to raw body rather than risk a wrong decode.
		return nil, ""
	}
	defer func() { _ = r.Close() }()

	// Read one byte past the limit so the caller can detect overflow.
	decompressed, readErr := io.ReadAll(io.LimitReader(r, limit+1))
	// ErrUnexpectedEOF on a truncated stream is still useful — we got some
	// prefix, hand it to the engine for inspection rather than bailing.
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return nil, fmt.Sprintf("decompress: %v", readErr)
	}
	if int64(len(decompressed)) > limit {
		return nil, "decompression ratio exceeded"
	}
	return decompressed, ""
}

func firstHeader(h map[string][]string, key string) string {
	// Case-insensitive lookup since the map is directly indexed by net/http's
	// canonical form but callers sometimes pass lower-case keys.
	if vs, ok := h[key]; ok && len(vs) > 0 {
		return vs[0]
	}
	for k, vs := range h {
		if strings.EqualFold(k, key) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}


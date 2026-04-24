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
func maybeDecompressBody(headers map[string][]string, body []byte, ratioCap int, maxBytes int64) (decoded []byte, rejectReason string) {
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
	limit := int64(len(body)) * int64(ratioCap)
	if limit > maxBytes {
		limit = maxBytes
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
	default:
		// Unknown encoding — leave to caller.
		return nil, ""
	}
	defer r.Close()

	buf := make([]byte, 0, minInt64(limit, 1<<15))
	// Read one byte past the limit so the caller can detect overflow.
	n, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Sprintf("decompress: %v", err)
	}
	if int64(len(n)) > limit {
		return nil, "decompression ratio exceeded"
	}
	buf = append(buf, n...)
	return buf, ""
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

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

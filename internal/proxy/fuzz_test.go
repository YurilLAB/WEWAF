package proxy

import "testing"

// FuzzMaybeDecompressBody feeds arbitrary bodies + Content-Encoding values to
// the request-decompression path. Decompressors are a prime crash/zip-bomb
// surface. The function has an internal recover() (a panic becomes a reject
// reason), so the fuzzer is really checking for hangs / OOM and that the
// documented invariants hold. Run:
//   go test -run=^$ -fuzz=^FuzzMaybeDecompressBody$ -fuzztime=90s ./internal/proxy/
func FuzzMaybeDecompressBody(f *testing.F) {
	f.Add([]byte("hello world"), "gzip")
	f.Add([]byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0}, "gzip") // gzip header, no data
	f.Add([]byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}, "deflate")
	f.Add([]byte("not really deflate"), "deflate")
	f.Add([]byte("x"), "gzip, gzip")
	f.Add([]byte("x"), "br")
	f.Add([]byte("x"), "identity")
	f.Add([]byte(""), "")
	const ratioCap = 100
	const maxBytes int64 = 1 << 20
	f.Fuzz(func(t *testing.T, body []byte, enc string) {
		headers := map[string][]string{"Content-Encoding": {enc}}
		decoded, reason := maybeDecompressBody(headers, body, ratioCap, maxBytes)
		// A reject must not also hand back a payload to inspect.
		if reason != "" && len(decoded) != 0 {
			t.Fatalf("rejected (%q) but returned %d decoded bytes", reason, len(decoded))
		}
		// The ratio/byte cap must hold — a bomb must never expand past maxBytes.
		if int64(len(decoded)) > maxBytes {
			t.Fatalf("decoded %d bytes exceeds maxBytes cap %d (enc=%q)", len(decoded), maxBytes, enc)
		}
	})
}

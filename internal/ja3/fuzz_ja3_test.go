package ja3

import (
	"testing"
)

// The JA3/JA4 fingerprint functions run against the TLS ClientHello — every
// field they read (cipher suites, extensions, supported curves/points,
// signature schemes, and especially the ALPN protocol strings) is fully
// attacker-controlled by a hostile client at handshake time. A panic here is a
// per-connection DoS on the TLS accept path, and a structural slip would corrupt
// the fingerprint the rest of the stack keys rate-limit buckets and blocklists
// on. These fuzzers assert the no-panic + output-shape contracts hold for any
// input, including pathological cipher/extension lists and ALPN values carrying
// raw control bytes.
//
// Run e.g.:  go test ./internal/ja3 -run x -fuzz FuzzComputeJA3 -fuzztime 30s

// bytesToU16 reinterprets a byte slice as a big-endian uint16 list — a cheap way
// to let the fuzzer drive arbitrary cipher/extension/curve lists.
func bytesToU16(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func FuzzComputeJA3(f *testing.F) {
	f.Add([]byte{0x03, 0x03, 0x13, 0x01, 0x00, 0x00}, uint16(0x0303))
	f.Add([]byte{}, uint16(0))
	f.Add([]byte{0x0a, 0x0a, 0x13, 0x01}, uint16(0x0a0a)) // GREASE-heavy
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff}, uint16(0xffff))

	f.Fuzz(func(t *testing.T, data []byte, version uint16) {
		// Slice the fuzz bytes into four independent lists so cipher/ext/curve
		// counts and values vary independently.
		q := len(data) / 4
		in := FingerprintInput{
			Version:         version,
			CipherSuites:    bytesToU16(data[:q]),
			Extensions:      bytesToU16(data[q : 2*q]),
			SupportedCurves: bytesToU16(data[2*q : 3*q]),
			SupportedPoints: append([]uint8(nil), data[3*q:]...),
		}
		jaStr, jaHash := Compute(in)
		// Contract: either both empty ("no fingerprint") or a 32-char lowercase
		// hex MD5 with a non-empty canonical string.
		if jaHash == "" {
			if jaStr != "" {
				t.Fatalf("empty hash but non-empty string %q", jaStr)
			}
			return
		}
		if len(jaHash) != 32 || !isLowerHex(jaHash) {
			t.Fatalf("malformed JA3 hash %q (len %d) from string %q", jaHash, len(jaHash), jaStr)
		}
		// JA3N shares the input prep; it must satisfy the same hash contract.
		if _, nHash := ComputeJA3N(in); nHash != "" && (len(nHash) != 32 || !isLowerHex(nHash)) {
			t.Fatalf("malformed JA3N hash %q", nHash)
		}
	})
}

func FuzzComputeJA4(f *testing.F) {
	f.Add([]byte{0x13, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x0d}, "h2", uint16(0x0304), true)
	f.Add([]byte{}, "", uint16(0), false)
	// ALPN carrying control bytes / underscores / a single byte — the alpnTag is
	// the first+last byte of this string verbatim, so these stress the shape.
	f.Add([]byte{0x00, 0x2f}, "\r\n", uint16(0x0303), true)
	f.Add([]byte{0x00, 0x2f}, "_", uint16(0x0303), false)
	f.Add([]byte{0x00, 0x2f}, "\x00", uint16(0x0301), true)

	f.Fuzz(func(t *testing.T, data []byte, alpn string, version uint16, hasSNI bool) {
		third := len(data) / 3
		in := JA4Input{
			Version:          version,
			HasSNI:           hasSNI,
			CipherSuites:     bytesToU16(data[:third]),
			Extensions:       bytesToU16(data[third : 2*third]),
			SignatureSchemes: bytesToU16(data[2*third:]),
			ALPN:             []string{alpn},
		}
		out := ComputeJA4(in)
		if out == "" {
			return
		}
		// Structural contract: JA4 is a fixed 36 bytes — section A (10) + "_" +
		// section B (12) + "_" + section C (12). The content of the 2-byte ALPN
		// tag is intentionally raw (it may contain underscores or control bytes
		// for a hostile ALPN), so we assert the LENGTH only — a regression that
		// changed the section widths would break this.
		if len(out) != 36 {
			t.Fatalf("JA4 not 36 bytes: %q (len %d) alpn=%q", out, len(out), alpn)
		}
		// Extract sections by FIXED position, not by splitting on '_': the 2-byte
		// ALPN tag inside section A can legitimately contain an underscore for a
		// hostile ALPN, so a delimiter split would mis-slice. Section A is always
		// 10 bytes, so the separators sit at index 10 and 23.
		if out[10] != '_' || out[23] != '_' {
			t.Fatalf("JA4 separators misplaced: %q alpn=%q", out, alpn)
		}
		secB, secC := out[11:23], out[24:36]
		if !isLowerHex(secB) {
			t.Fatalf("JA4 section B not 12-hex: %q", secB)
		}
		if !isLowerHex(secC) {
			t.Fatalf("JA4 section C not 12-hex: %q", secC)
		}
	})
}

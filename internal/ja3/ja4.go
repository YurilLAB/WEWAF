package ja3

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// JA4 implements the FoxIO JA4 TLS client fingerprint
// (https://github.com/FoxIO-LLC/ja4). Where JA3 hashes the *order* of
// fields, JA4 sorts them, which makes it stable against the
// extension-shuffle that Chrome 110+ does natively to defeat naive
// JA3 fingerprinting. JA4 is what we want as the primary fingerprint
// for FP-resistant detection going forward; we keep classic JA3
// alongside for compatibility with public threat-intel feeds that
// still publish JA3 hashes.
//
// JA4 format (36 chars), three underscore-separated sections:
//
//	A: t13d1516h2     protocol info, 10 chars
//	B: 8daaf6152771   SHA-256[:12] of sorted cipher suite list
//	C: b186095e22b6   SHA-256[:12] of (sorted ext list)_(sig_algs in order)
//
// Section A breakdown:
//
//	t   transport ('t' TCP, 'q' QUIC; we only see TCP at the listener)
//	13  TLS version (10/11/12/13 = 1.0/1.1/1.2/1.3)
//	d   SNI present? ('d' = domain in SNI, 'i' = IP / no SNI)
//	15  cipher suite count, two decimal digits, capped at 99
//	16  extension count, two decimal digits, capped at 99 (excluded:
//	    SNI 0x0000 and ALPN 0x0010 per the JA4 spec, since they're
//	    already captured elsewhere in the fingerprint)
//	h2  first/last char of first ALPN value, '00' if none
//
// Section B: cipher suites (GREASE filtered) → 4-hex-digit lowercase
// → sorted lexicographically → comma-joined → SHA-256 → first 12 hex.
//
// Section C: extensions list as for B (GREASE + 0x0000 + 0x0010 filtered,
// then sorted) → join with '_' → append signature_algorithms in their
// original order, also 4-hex lowercase comma-joined → SHA-256 → first 12.

// JA4Input is the subset of a TLS ClientHello that JA4 needs.
type JA4Input struct {
	Version           uint16   // negotiated max TLS version
	HasSNI            bool     // server_name extension present
	CipherSuites      []uint16 // offered ciphers in order
	Extensions        []uint16 // extension IDs in original order
	SignatureSchemes  []uint16 // signature_algorithms contents in order
	ALPN              []string // application_layer_protocol_negotiation, first one is used
}

// ComputeJA4 returns the JA4 fingerprint string. Empty input → "".
func ComputeJA4(in JA4Input) string {
	// A clearly-empty input is "no fingerprint" not a degenerate string.
	if in.Version == 0 && len(in.CipherSuites) == 0 && len(in.Extensions) == 0 {
		return ""
	}

	// --- Section A ---------------------------------------------------------
	transport := byte('t') // we don't see QUIC at this listener

	var ver string
	switch in.Version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	default:
		// Anything else (including SSLv3 0x0300 which would be exotic
		// in 2026) gets reported as "00" so the fingerprint stays a
		// fixed 36 chars and downstream parsers don't break.
		ver = "00"
	}

	sniMarker := byte('i')
	if in.HasSNI {
		sniMarker = 'd'
	}

	cipherCount := countNonGREASE16(in.CipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := countJA4Extensions(in.Extensions)
	if extCount > 99 {
		extCount = 99
	}

	var alpnTag string
	if first := firstALPN(in.ALPN); first != "" {
		alpnTag = string([]byte{first[0], first[len(first)-1]})
	} else {
		alpnTag = "00"
	}

	var a strings.Builder
	a.Grow(10)
	a.WriteByte(transport)
	a.WriteString(ver)
	a.WriteByte(sniMarker)
	a.WriteString(twoDigit(cipherCount))
	a.WriteString(twoDigit(extCount))
	a.WriteString(alpnTag)

	// --- Section B (sorted ciphers) ----------------------------------------
	bHash := hashHexList(sortedHexes(in.CipherSuites, false /* skipExt */))

	// --- Section C (sorted ext list _ sig_algs in original order) ----------
	extPart := strings.Join(sortedHexes(in.Extensions, true /* skipExt */), ",")
	sigPart := strings.Join(rawHexes(in.SignatureSchemes), ",")
	var cInput string
	if sigPart == "" {
		cInput = extPart
	} else {
		cInput = extPart + "_" + sigPart
	}
	cSum := sha256.Sum256([]byte(cInput))
	cHash := hex.EncodeToString(cSum[:])[:12]

	return a.String() + "_" + bHash + "_" + cHash
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func firstALPN(xs []string) string {
	for _, s := range xs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// JA4 spec: only printable ASCII, otherwise treat as no-ALPN.
		ok := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c < 0x20 || c > 0x7e {
				ok = false
				break
			}
		}
		if ok {
			return s
		}
	}
	return ""
}

func countNonGREASE16(xs []uint16) int {
	n := 0
	for _, x := range xs {
		if !IsGREASE(x) {
			n++
		}
	}
	return n
}

// countJA4Extensions reports the JA4 ext count: total minus GREASE,
// minus SNI (0x0000) and ALPN (0x0010), per spec. The hashed list also
// excludes those two because they're already implicit in section A.
func countJA4Extensions(xs []uint16) int {
	n := 0
	for _, x := range xs {
		if IsGREASE(x) {
			continue
		}
		if x == 0x0000 || x == 0x0010 {
			continue
		}
		n++
	}
	return n
}

// sortedHexes converts the uint16 list to 4-hex-digit lowercase strings,
// sorts lexicographically, and returns. GREASE always filtered. When
// skipExt is true, also drops 0x0000 and 0x0010 (JA4 ext-list rule).
func sortedHexes(xs []uint16, skipExt bool) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if IsGREASE(x) {
			continue
		}
		if skipExt && (x == 0x0000 || x == 0x0010) {
			continue
		}
		out = append(out, hex4(x))
	}
	sort.Strings(out)
	return out
}

// rawHexes is sortedHexes minus the sort and the skipExt logic — used
// for sig_algs which the JA4 spec preserves in handshake order.
func rawHexes(xs []uint16) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if IsGREASE(x) {
			continue
		}
		out = append(out, hex4(x))
	}
	return out
}

// hashHexList joins with comma and SHA-256-truncates to 12 hex.
// Empty list → 12 zeros, per the JA4 reference implementation.
func hashHexList(xs []string) string {
	if len(xs) == 0 {
		return "000000000000"
	}
	joined := strings.Join(xs, ",")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])[:12]
}

func hex4(x uint16) string {
	const tab = "0123456789abcdef"
	var b [4]byte
	b[0] = tab[(x>>12)&0xf]
	b[1] = tab[(x>>8)&0xf]
	b[2] = tab[(x>>4)&0xf]
	b[3] = tab[x&0xf]
	return string(b[:])
}

// -----------------------------------------------------------------------------
// JA3N — JA3 with the extension list sorted before hashing. Defeats
// Chrome 110+ extension-order randomization, which causes a "real Chrome"
// to produce a different classic-JA3 hash on every connection. JA3N
// keeps the rest of the JA3 algorithm identical, so the same canonical
// string format applies — we just sort field 3 (extensions) numerically
// before joining.

// ComputeJA3N returns (canonicalString, md5Hash) for the normalized
// JA3 of the given ClientHello fields. Same algorithm as Compute() but
// the extension list is numerically sorted with GREASE filtered.
func ComputeJA3N(in FingerprintInput) (jaString, jaHash string) {
	if in.Version == 0 && len(in.CipherSuites) == 0 && len(in.Extensions) == 0 {
		return "", ""
	}
	sorted := append([]uint16(nil), in.Extensions...)
	// Strip GREASE before sorting so the sort is stable across handshakes.
	w := 0
	for _, e := range sorted {
		if IsGREASE(e) {
			continue
		}
		sorted[w] = e
		w++
	}
	sorted = sorted[:w]
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	in2 := in
	in2.Extensions = sorted
	return Compute(in2)
}

package dpi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Upgrade-gate tests -------------------------------------------------

func TestWSUpgradeRequestDetection(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	if !WSUpgradeRequest(r) {
		t.Fatalf("legit handshake not recognised")
	}

	// Missing Upgrade header.
	r2 := httptest.NewRequest("GET", "/ws", nil)
	r2.Header.Set("Connection", "Upgrade")
	r2.Header.Set("Sec-WebSocket-Version", "13")
	if WSUpgradeRequest(r2) {
		t.Fatalf("detected upgrade without Upgrade header")
	}

	// Connection header that mentions "upgrade" as a substring of another
	// token must not pass — token check is strict.
	r3 := httptest.NewRequest("GET", "/ws", nil)
	r3.Header.Set("Upgrade", "websocket")
	r3.Header.Set("Connection", "nonupgradelike")
	r3.Header.Set("Sec-WebSocket-Version", "13")
	if WSUpgradeRequest(r3) {
		t.Fatalf("substring-not-token must not match")
	}
}

func TestWSUpgradeOriginAllowlist(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Origin", "https://app.example.com")

	cfg := WSUpgradeConfig{OriginAllowlist: []string{"*.example.com"}}
	v := CheckWSUpgrade(r, cfg)
	if !v.Allow {
		t.Fatalf("wildcard allowlist should allow app.example.com: %s", v.Reason)
	}

	r.Header.Set("Origin", "https://evil.com")
	v = CheckWSUpgrade(r, cfg)
	if v.Allow {
		t.Fatalf("evil.com passed an *.example.com allowlist")
	}

	// Wildcard must NOT match the bare apex. `*.example.com` means any
	// subdomain, not example.com itself.
	r.Header.Set("Origin", "https://example.com")
	v = CheckWSUpgrade(r, cfg)
	if v.Allow {
		t.Fatalf("bare apex should not match subdomain wildcard")
	}
}

// TestWSUpgradeOriginBypassClassesRejected covers the bypass class an
// audit found in the previous string-suffix matcher: hand-crafted
// clients can send Origin values that aren't real browser origins,
// and a naive HasSuffix check would let them through. The parser
// must refuse anything that isn't strict scheme://host[:port].
func TestWSUpgradeOriginBypassClassesRejected(t *testing.T) {
	cfg := WSUpgradeConfig{OriginAllowlist: []string{"*.example.com", "https://api.example.com"}}
	bad := []string{
		// Path-bearing origin that would pass HasSuffix(".example.com").
		"https://evil.com/.example.com",
		// Query-bearing variant of the same trick.
		"https://evil.com/?x=.example.com",
		// Fragment-bearing variant.
		"https://evil.com/#.example.com",
		// Suffix substring without a label boundary.
		"https://evilexample.com",
		// Trailing dot used to confuse normalisation. Should normalise
		// to "evil.com" host (not allowed).
		"https://evil.com.",
		// Embedded null byte from a tampered client.
		"https://evil.com\x00.example.com",
		// "null" Origin (sandboxed iframe / file://) — never on an
		// allowlist that uses real domains.
		"null",
		// IDN homograph attempt (Cyrillic 'e' in "exаmple" — U+0430).
		"https://exаmple.com",
		// Empty.
		"",
	}
	for _, o := range bad {
		r := httptest.NewRequest("GET", "/ws", nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Origin", o)
		if v := CheckWSUpgrade(r, cfg); v.Allow {
			t.Fatalf("Origin %q should be refused but was allowed", o)
		}
	}

	// Genuine subdomain — allowed.
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Origin", "https://api.example.com")
	if v := CheckWSUpgrade(r, cfg); !v.Allow {
		t.Fatalf("genuine subdomain should be allowed: %s", v.Reason)
	}
}

func TestWSUpgradeSubprotocolAllowlist(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")

	cfg := WSUpgradeConfig{SubprotocolAllowlist: []string{"chat.v1"}, RequireSubprotocol: true}

	// Missing — rejected.
	if CheckWSUpgrade(r, cfg).Allow {
		t.Fatalf("missing subprotocol should be rejected when required")
	}

	// Wrong value — rejected.
	r.Header.Set("Sec-WebSocket-Protocol", "gossip.v1")
	if CheckWSUpgrade(r, cfg).Allow {
		t.Fatalf("non-allowlisted subprotocol accepted")
	}

	// Multi-value, one match — accepted.
	r.Header.Set("Sec-WebSocket-Protocol", "gossip.v1, chat.v1")
	if !CheckWSUpgrade(r, cfg).Allow {
		t.Fatalf("should accept multi-value with one match")
	}
}

func TestWSUpgradeRejectsOverlongExtensions(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Extensions", strings.Repeat("a", 4096))
	v := CheckWSUpgrade(r, WSUpgradeConfig{MaxExtensionsLen: 256})
	if v.Allow {
		t.Fatalf("should reject 4096-byte Extensions with 256-byte cap")
	}
}

// --- Frame parser tests -------------------------------------------------

// helper: build an unmasked short frame.
func wsFrame(fin bool, opcode WSOpcode, payload []byte, masked bool) []byte {
	var buf bytes.Buffer
	b0 := byte(opcode)
	if fin {
		b0 |= 0x80
	}
	buf.WriteByte(b0)
	plen := len(payload)
	b1 := byte(0)
	if masked {
		b1 |= 0x80
	}
	switch {
	case plen <= 125:
		buf.WriteByte(b1 | byte(plen))
	case plen <= 0xffff:
		buf.WriteByte(b1 | 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(plen))
		buf.Write(ext)
	default:
		buf.WriteByte(b1 | 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(plen))
		buf.Write(ext)
	}
	if masked {
		key := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		buf.Write(key)
		masked := make([]byte, plen)
		for i := 0; i < plen; i++ {
			masked[i] = payload[i] ^ key[i&3]
		}
		buf.Write(masked)
	} else {
		buf.Write(payload)
	}
	return buf.Bytes()
}

func TestWSFrameReadUnmasked(t *testing.T) {
	payload := []byte("hello")
	raw := wsFrame(true, WSOpText, payload, false)
	f, err := ReadWSFrame(bytes.NewReader(raw), 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !f.Fin || f.Opcode != WSOpText {
		t.Fatalf("flags wrong: %+v", f)
	}
	if string(f.Payload) != "hello" {
		t.Fatalf("payload = %q, want hello", f.Payload)
	}
}

func TestWSFrameReadMaskedDeMasksPayload(t *testing.T) {
	payload := []byte("GET /admin HTTP/1.1")
	raw := wsFrame(true, WSOpText, payload, true)
	f, err := ReadWSFrame(bytes.NewReader(raw), 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(f.Payload) != string(payload) {
		t.Fatalf("unmask failed: %q vs %q", f.Payload, payload)
	}
}

func TestWSFrameExtendedLength16(t *testing.T) {
	payload := bytes.Repeat([]byte{'a'}, 300) // > 125, uses 16-bit length
	raw := wsFrame(true, WSOpBinary, payload, false)
	f, err := ReadWSFrame(bytes.NewReader(raw), 4096)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.PayloadLen != 300 {
		t.Fatalf("len = %d, want 300", f.PayloadLen)
	}
}

func TestWSFrameRejectsOversize(t *testing.T) {
	// Forge header claiming 10 MiB payload; we don't need to supply it
	// because ReadWSFrame bails at the length check before reading body.
	hdr := []byte{0x82, 0x7f} // FIN=1, opcode=binary, mask=0, 127 (64-bit len)
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], 10*1024*1024)
	raw := append(hdr, ext[:]...)

	_, err := ReadWSFrame(bytes.NewReader(raw), 1024)
	if !errors.Is(err, ErrWSFrameTooLarge) {
		t.Fatalf("expected ErrWSFrameTooLarge, got %v", err)
	}
}

func TestWSFrameRejectsControlFrameOversize(t *testing.T) {
	// RFC says control frames ≤ 125 bytes. Build one claiming 200.
	hdr := []byte{0x89, 0x7e}
	var ext [2]byte
	binary.BigEndian.PutUint16(ext[:], 200)
	raw := append(hdr, ext[:]...)
	_, err := ReadWSFrame(bytes.NewReader(raw), 4096)
	if !errors.Is(err, ErrWSMalformed) {
		t.Fatalf("expected ErrWSMalformed, got %v", err)
	}
}

func TestWSInspectRejectsNonUTF8Text(t *testing.T) {
	f := WSFrame{Opcode: WSOpText, Payload: []byte{0xff, 0xfe, 0xfd}}
	res := InspectWSDataFrame(f)
	if !res.Blocked {
		t.Fatalf("non-UTF-8 text frame should block")
	}
}

func TestWSInspectExtractsTextTarget(t *testing.T) {
	payload := `{"cmd":"exec","arg":"cat /etc/passwd"}`
	f := WSFrame{Opcode: WSOpText, Payload: []byte(payload)}
	res := InspectWSDataFrame(f)
	if res.Blocked {
		t.Fatalf("should not block benign UTF-8")
	}
	if len(res.Targets) != 1 || res.Targets[0] != payload {
		t.Fatalf("target not surfaced: %+v", res.Targets)
	}
}

func TestWSInspectRejectsReservedOpcode(t *testing.T) {
	f := WSFrame{Opcode: 3, Payload: nil}
	res := InspectWSDataFrame(f)
	if !res.Blocked {
		t.Fatalf("reserved opcode should block")
	}
}

func TestWSInspectSkipsBinaryAndControl(t *testing.T) {
	for _, op := range []WSOpcode{WSOpBinary, WSOpContinuation, WSOpPing, WSOpPong, WSOpClose} {
		res := InspectWSDataFrame(WSFrame{Opcode: op})
		if res.Blocked {
			t.Fatalf("opcode %d should not block", op)
		}
		if len(res.Targets) != 0 {
			t.Fatalf("opcode %d should not produce targets", op)
		}
	}
}

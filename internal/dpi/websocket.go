package dpi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// --- WebSocket upgrade gate ---------------------------------------------
//
// The cheapest and safest intervention point for WebSocket traffic is the
// HTTP upgrade handshake. Once an Upgrade completes, the proxy is either
// hijacking the connection (full MITM, complex to get right, plenty of
// places to leak fds) or transparently tunnelling it (zero protocol
// visibility). The gate below lets operators reject a handshake before
// it completes based on the client's advertised origin, subprotocol, and
// extensions — which catches the majority of "untrusted script trying to
// talk to a real backend" scenarios without touching byte streams.
//
// For deployments that need per-frame inspection, FrameReader below can
// be wrapped around the hijacked io.Reader once the upgrade succeeds.

// WSUpgradeRequest returns true if the request is a WebSocket opening
// handshake. We check all three mandatory headers (Upgrade, Connection,
// Sec-WebSocket-Version) so a stray "Connection: upgrade" on a normal
// request doesn't trigger the gate.
func WSUpgradeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !containsToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") == "" {
		return false
	}
	return true
}

// WSUpgradeConfig tunes what the upgrade gate accepts.
type WSUpgradeConfig struct {
	// OriginAllowlist, if non-empty, restricts Origin to this set.
	// Dot-prefix "*.example.com" matches any subdomain.
	OriginAllowlist []string
	// SubprotocolAllowlist, if non-empty, restricts
	// Sec-WebSocket-Protocol to this set. Empty header is allowed only
	// when RequireSubprotocol=false.
	SubprotocolAllowlist []string
	RequireSubprotocol   bool
	// MaxExtensionsLen caps the byte length of Sec-WebSocket-Extensions
	// (permessage-deflate headers can get absurdly long from fuzzers).
	// 0 disables the check. Default 256 is plenty for legit use.
	MaxExtensionsLen int
}

// WSVerdict captures the upgrade-gate decision.
type WSVerdict struct {
	Allow  bool
	Reason string
}

// CheckWSUpgrade runs the gate. Caller invokes this only after
// WSUpgradeRequest returned true — callers are expected to skip non-WS
// requests so we don't waste work.
func CheckWSUpgrade(r *http.Request, cfg WSUpgradeConfig) WSVerdict {
	if r == nil {
		return WSVerdict{Allow: false, Reason: "nil request"}
	}

	if len(cfg.OriginAllowlist) > 0 {
		origin := r.Header.Get("Origin")
		if !matchOrigin(origin, cfg.OriginAllowlist) {
			return WSVerdict{Allow: false, Reason: "origin not allowlisted: " + origin}
		}
	}

	if cfg.RequireSubprotocol || len(cfg.SubprotocolAllowlist) > 0 {
		sp := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Protocol"))
		if sp == "" {
			if cfg.RequireSubprotocol {
				return WSVerdict{Allow: false, Reason: "subprotocol required"}
			}
		} else if len(cfg.SubprotocolAllowlist) > 0 {
			// Client may offer multiple, comma-separated. At least one
			// must be on our allowlist.
			matched := false
			for _, part := range strings.Split(sp, ",") {
				p := strings.TrimSpace(part)
				for _, allowed := range cfg.SubprotocolAllowlist {
					if strings.EqualFold(p, allowed) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return WSVerdict{Allow: false, Reason: "no allowlisted subprotocol offered"}
			}
		}
	}

	maxExt := cfg.MaxExtensionsLen
	if maxExt <= 0 {
		maxExt = 256
	}
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); len(ext) > maxExt {
		return WSVerdict{Allow: false, Reason: fmt.Sprintf("extensions header too long (%d bytes)", len(ext))}
	}

	return WSVerdict{Allow: true}
}

// containsToken returns true if any comma-separated token in h equals t
// (case-insensitive). HTTP header tokens are case-insensitive per RFC.
func containsToken(h, t string) bool {
	for _, part := range strings.Split(h, ",") {
		if strings.EqualFold(strings.TrimSpace(part), t) {
			return true
		}
	}
	return false
}

// matchOrigin applies allowlist semantics with optional wildcard
// subdomain support.
//
// The previous implementation matched on the raw Origin string with
// strings.HasSuffix. That was bypassable: per RFC 6454 a browser-sent
// Origin is "scheme://host[:port]" with no path or query, but a
// hand-crafted client can submit "https://evil.com/.example.com",
// which strings.HasSuffix(origin, ".example.com") happily accepts and
// the upgrade goes through with an attacker-controlled origin.
// Parsing the value as a URL and comparing only the host (case-fold,
// stripped of port and trailing dot) closes that hole.
func matchOrigin(origin string, allow []string) bool {
	host, port := parseOriginHost(origin)
	if host == "" {
		return false
	}
	hostPort := host
	if port != "" {
		hostPort = host + ":" + port
	}
	for _, raw := range allow {
		a := strings.ToLower(strings.TrimSpace(raw))
		if a == "" {
			continue
		}
		// If the entry has a scheme, parse it the same way as the
		// origin so "https://app.example.com" matches the same
		// host/port pair.
		entryHost, entryPort := parseOriginHost(a)
		// Wildcard subdomain pattern: "*.example.com" — accepts any
		// label preceding the suffix but NOT the bare suffix itself.
		if strings.HasPrefix(a, "*.") {
			suffix := a[1:] // ".example.com"
			// Whole-label suffix match: host must end with suffix
			// AND have at least one character before it. Avoids
			// the previous-implementation issue where a path-bearing
			// origin could fake the suffix.
			if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if entryHost != "" {
			// Exact host:port (or host alone if no port specified).
			if entryPort != "" {
				if host == entryHost && port == entryPort {
					return true
				}
			} else {
				if host == entryHost {
					return true
				}
			}
			continue
		}
		// Plain "host" or "host:port" entry — compare against the
		// origin's host[:port] form.
		if a == host || a == hostPort {
			return true
		}
	}
	return false
}

// parseOriginHost extracts a normalised host + port from an Origin
// header value. Returns ("","") on anything that isn't a real
// browser-shaped Origin (scheme://host[:port], no path, no query).
// Lowercases the host and strips a single trailing dot — modern
// resolvers treat "example.com." and "example.com" as identical.
func parseOriginHost(s string) (host, port string) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return "", ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", ""
	}
	// Origin must have NO path / query / fragment. A path-bearing
	// value is either malformed or hostile; refuse rather than
	// trying to extract a host.
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	port = u.Port()
	return host, port
}

// --- WebSocket frame parser (RFC 6455) ----------------------------------

const (
	// WSMaxFrameBytes is the hard cap on a single data-frame payload we
	// accept for inspection. Legit chat frames are tiny; a 16 MiB frame
	// is someone abusing the protocol and we refuse to decode it.
	WSMaxFrameBytes = 16 << 20
)

// WSOpcode values we care about. 0 continuation, 1 text, 2 binary,
// 8 close, 9 ping, 10 pong. 3-7 and 11-15 are reserved.
type WSOpcode byte

const (
	WSOpContinuation WSOpcode = 0
	WSOpText         WSOpcode = 1
	WSOpBinary       WSOpcode = 2
	WSOpClose        WSOpcode = 8
	WSOpPing         WSOpcode = 9
	WSOpPong         WSOpcode = 10
)

// WSFrame is one parsed frame.
type WSFrame struct {
	Fin        bool
	Opcode     WSOpcode
	Masked     bool
	PayloadLen uint64
	Payload    []byte // already unmasked if Masked=true
}

// IsControl returns true for ping/pong/close. Control frames carry no
// meaningful payload for rule matching; callers typically skip scanning
// them and just count.
func (f WSFrame) IsControl() bool {
	return f.Opcode&0x08 != 0
}

// ErrWSMalformed indicates a frame that doesn't match RFC 6455 shape.
var (
	ErrWSMalformed     = errors.New("websocket: malformed frame")
	ErrWSFrameTooLarge = errors.New("websocket: frame exceeds limit")
)

// ReadWSFrame reads exactly one frame from r. Returns ErrWSFrameTooLarge
// if the declared payload length is over maxBytes so callers can
// distinguish "client misbehaved" from "stream ended" (io.EOF).
//
// We DO unmask the payload in place on a fresh buffer — without this,
// text frames arrive XORed and the rule engine matches garbage. The
// copy is unavoidable because the caller usually needs to forward the
// original bytes to the backend unchanged.
func ReadWSFrame(r io.Reader, maxBytes int) (WSFrame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return WSFrame{}, err
	}

	f := WSFrame{
		Fin:    hdr[0]&0x80 != 0,
		Opcode: WSOpcode(hdr[0] & 0x0f),
		Masked: hdr[1]&0x80 != 0,
	}

	// Reserved bits (RSV1-3 in hdr[0] bits 6-4) may be set by extensions
	// (permessage-deflate sets RSV1). We don't treat them as malformed.

	short := uint64(hdr[1] & 0x7f)
	switch {
	case short <= 125:
		f.PayloadLen = short
	case short == 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return WSFrame{}, err
		}
		f.PayloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case short == 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return WSFrame{}, err
		}
		for i := 0; i < 8; i++ {
			f.PayloadLen = f.PayloadLen<<8 | uint64(ext[i])
		}
		// RFC 6455: MSB of a 64-bit length MUST be zero.
		if f.PayloadLen&(1<<63) != 0 {
			return WSFrame{}, ErrWSMalformed
		}
	}

	if maxBytes > 0 && f.PayloadLen > uint64(maxBytes) {
		return WSFrame{}, ErrWSFrameTooLarge
	}
	// Defensive ceiling for callers that pass maxBytes ≤ 0. A 16 MiB
	// floor per frame is comfortably larger than anything legitimate
	// (browsers cap at 64 KiB) and stops a hostile peer from
	// allocating multi-GiB buffers on us via an inflated 64-bit
	// payload header.
	const wsHardCeiling = 16 * 1024 * 1024
	if maxBytes <= 0 && f.PayloadLen > wsHardCeiling {
		return WSFrame{}, ErrWSFrameTooLarge
	}
	// Control frames have a hard 125-byte limit per RFC.
	if f.IsControl() && f.PayloadLen > 125 {
		return WSFrame{}, ErrWSMalformed
	}

	var maskKey [4]byte
	if f.Masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return WSFrame{}, err
		}
	}

	if f.PayloadLen > 0 {
		f.Payload = make([]byte, f.PayloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return WSFrame{}, err
		}
		if f.Masked {
			for i := range f.Payload {
				f.Payload[i] ^= maskKey[i&3]
			}
		}
	}
	return f, nil
}

// WSInspectionResult tracks what one connection's frames looked like.
// Callers accumulate across frames and decide-per-frame vs
// decide-per-connection based on their policy.
type WSInspectionResult struct {
	Blocked       bool
	Reason        string
	// Targets are text-frame payloads to pass to the rule engine.
	Targets []string
}

// InspectWSDataFrame runs per-frame checks on a fully-read frame. It
// returns a blocked=true when the frame should cause the proxy to close
// the connection; otherwise, any text payload is returned as a target
// so the rule engine can match against it.
//
// Binary frames aren't scanned as strings (too many false positives on
// binary protocols like protobuf-over-ws or msgpack). They still count
// toward frame / byte budgets.
func InspectWSDataFrame(f WSFrame) WSInspectionResult {
	res := WSInspectionResult{}
	switch f.Opcode {
	case WSOpText:
		// RFC 6455 requires text frames to be valid UTF-8. Anything else
		// is either a misbehaving client or a smuggling attempt.
		if !isValidUTF8(f.Payload) {
			res.Blocked = true
			res.Reason = "text frame not valid UTF-8"
			return res
		}
		res.Targets = append(res.Targets, string(f.Payload))
	case WSOpBinary, WSOpContinuation:
		// Pass through without scanning — see comment above.
	case WSOpClose, WSOpPing, WSOpPong:
		// Control frames: nothing to do.
	default:
		// Reserved opcodes — reject.
		res.Blocked = true
		res.Reason = fmt.Sprintf("reserved opcode %d", f.Opcode)
	}
	return res
}

func isValidUTF8(b []byte) bool {
	return utf8.Valid(b)
}

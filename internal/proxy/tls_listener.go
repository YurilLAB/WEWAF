package proxy

import (
	"crypto/tls"
	"errors"
	"sync/atomic"

	"wewaf/internal/ja3"
)

// JA3TLSConfig wraps a base *tls.Config with a GetConfigForClient hook
// that records the ClientHello fingerprint into the given cache. The
// hook returns nil (use the base config) on every handshake — capturing
// the hello is the only side effect.
//
// Returns the augmented config plus a "hooked" boolean so callers can
// log "JA3 native capture: enabled" at startup. Errors when base is nil.
//
// Why we hook GetConfigForClient instead of GetCertificate: the former
// fires once per handshake with the full ClientHelloInfo even when the
// caller doesn't use SNI; the latter only fires when a cert lookup is
// actually needed and may be skipped on session resumption.
func JA3TLSConfig(base *tls.Config, cache *ja3.Cache) (*tls.Config, bool, error) {
	if base == nil {
		return nil, false, errors.New("proxy: nil base TLS config")
	}
	if cache == nil {
		return base, false, nil
	}
	cfg := base.Clone()

	// Preserve any pre-existing hook the caller may have set (cert
	// rotation tooling, ACME challenges, etc.). The wrapper fires our
	// capture first then defers to the original.
	prev := cfg.GetConfigForClient

	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		// Defer panic-recover so a malformed ClientHello in some future
		// tlsdial version can never bring the listener down.
		defer func() { _ = recover() }()

		jaString, jaHash := ja3.FromClientHello(chi)
		if jaHash != "" && chi != nil && chi.Conn != nil {
			cache.Put(chi.Conn.RemoteAddr().String(), ja3.Fingerprint{
				Hash:    jaHash,
				String:  jaString,
				Version: 0, // computed inside ja3.Compute
			})
		}
		if prev != nil {
			return prev(chi)
		}
		return nil, nil
	}
	return cfg, true, nil
}

// We expose a small atomic counter on the listener wrapper so admin-UI
// reads don't depend on listener-internal state.
type listenerHookStats struct {
	captures atomic.Uint64
}

var hookStats listenerHookStats

// JA3CaptureCount returns the number of ClientHellos the JA3 listener
// hook has captured since process start. Used for admin-UI sanity ("is
// the hook actually firing"). Atomic; safe to call from any goroutine.
func JA3CaptureCount() uint64 { return hookStats.captures.Load() }

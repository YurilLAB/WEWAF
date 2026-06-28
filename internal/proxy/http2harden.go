package proxy

import (
	"net/http"

	"golang.org/x/net/http2"
)

// DefaultH2MaxConcurrentStreams pins the per-connection concurrent-stream
// ceiling. Go's runtime default is 250; we set it explicitly so the limit is
// OWNED (and asserted by a test) rather than silently inherited. Under a
// Rapid-Reset-style flood an operator can lower this (Cloudflare pinned 64).
const DefaultH2MaxConcurrentStreams uint32 = 250

// h2MaxReadFrameSize caps a single HTTP/2 frame so a giant HEADERS/DATA frame
// can't force a large allocation. 1 MiB is the conventional safe ceiling
// (valid range is 16 KiB..16 MiB).
const h2MaxReadFrameSize uint32 = 1 << 20

// HardenHTTP2 pins explicit HTTP/2 server limits on srv so the defenses against
// stream/frame floods (Rapid-Reset CVE-2023-44487, MadeYouReset CVE-2025-8671,
// CONTINUATION floods) are owned and tunable instead of inherited from the Go
// runtime defaults. maxStreams==0 uses DefaultH2MaxConcurrentStreams.
//
// Must be called AFTER srv.TLSConfig is set and BEFORE ListenAndServeTLS:
// ConfigureServer registers the h2 handler in srv.TLSNextProto, which also stops
// net/http from auto-configuring HTTP/2 with its defaults.
func HardenHTTP2(srv *http.Server, maxStreams uint32) error {
	if maxStreams == 0 {
		maxStreams = DefaultH2MaxConcurrentStreams
	}
	return http2.ConfigureServer(srv, &http2.Server{
		MaxConcurrentStreams: maxStreams,
		MaxReadFrameSize:     h2MaxReadFrameSize,
		// Reap half-dead h2 connections on the same clock as the HTTP/1 idle
		// timeout so a flood of idle streams can't pin connection slots.
		IdleTimeout: srv.IdleTimeout,
	})
}

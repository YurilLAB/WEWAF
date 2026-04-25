package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

// hardenRequest runs a small set of fast, deterministic checks that
// reject the most common bypass / smuggling patterns before any other
// inspection. These are NOT replacements for the rule engine; they catch
// pathological *protocol-level* abuse that the rule engine isn't well
// suited to:
//
//   - Request smuggling (RFC 7230 §3.3.3 rule 3): if a request has both
//     Content-Length and Transfer-Encoding, downstream servers MUST
//     either treat TE as authoritative or reject. WAFs that pick
//     differently from the origin can be desynced — the textbook
//     smuggling vector. Our policy: refuse the request.
//
//   - CR/LF in header values: header injection is the gateway to
//     response splitting and second-order XSS. Go's net/http rejects
//     CR/LF on the *outbound* side but accepts it inbound, so a
//     proxied backend that re-emits a header verbatim sees the
//     attacker's payload.
//
//   - Double-encoded path traversal: many WAFs decode once and check
//     for ../; we decode twice and match again to catch the classic
//     "%252e%252e/" bypass.
//
//   - Method allowlist: limits surface to the standard verbs. Anything
//     exotic (DEBUG, TRACE, custom) is rejected unless the operator
//     has explicitly opted in via config — but for now we just block
//     the well-known dangerous ones.
//
// On any rejection: returns the reason string and an HTTP status to
// emit. Caller stops the pipeline.
type hardenVerdict struct {
	Reject bool
	Status int
	Reason string
	RuleID string
}

func evaluateHardening(r *http.Request) hardenVerdict {
	if r == nil {
		return hardenVerdict{}
	}

	// 1. Request smuggling — Content-Length + Transfer-Encoding.
	// Even one TE plus one CL is enough; with multiple of either we
	// get into the truly nasty cases (TE: chunked, identity).
	hasCL := r.Header.Get("Content-Length") != ""
	hasTE := r.Header.Get("Transfer-Encoding") != ""
	if hasCL && hasTE {
		return hardenVerdict{
			Reject: true,
			Status: http.StatusBadRequest,
			Reason: "Content-Length and Transfer-Encoding both set (RFC 7230 §3.3.3)",
			RuleID: "HARDEN-SMUGGLE-TE-CL",
		}
	}
	// Multi-valued Transfer-Encoding (most often "chunked, chunked")
	// is also a documented smuggling vector — RFC 7230 says any
	// non-final coding is invalid for the request line case, but real
	// servers behave inconsistently. Refuse outright.
	if tes := r.Header.Values("Transfer-Encoding"); len(tes) > 1 {
		return hardenVerdict{
			Reject: true,
			Status: http.StatusBadRequest,
			Reason: "multi-valued Transfer-Encoding",
			RuleID: "HARDEN-SMUGGLE-TE-MULTI",
		}
	}
	// A Transfer-Encoding that isn't "chunked" (and isn't "identity",
	// which is a no-op) is treated as smuggling-prone. Most CDNs reject
	// these.
	if hasTE {
		te := strings.ToLower(strings.TrimSpace(r.Header.Get("Transfer-Encoding")))
		if te != "chunked" && te != "identity" {
			return hardenVerdict{
				Reject: true,
				Status: http.StatusBadRequest,
				Reason: "unsupported Transfer-Encoding: " + te,
				RuleID: "HARDEN-SMUGGLE-TE-BAD",
			}
		}
	}

	// 2. CR/LF in header values. Net/http unfortunately strips CRLF
	// on inbound only via the underlying http2 path (h1 leaves them).
	// We belt-and-braces here so the rest of the WAF can assume header
	// values are single-line.
	for name, vals := range r.Header {
		for _, v := range vals {
			if strings.ContainsAny(v, "\r\n") {
				return hardenVerdict{
					Reject: true,
					Status: http.StatusBadRequest,
					Reason: "CR/LF in header " + name,
					RuleID: "HARDEN-CRLF-HEADER",
				}
			}
		}
		if strings.ContainsAny(name, "\r\n") {
			return hardenVerdict{
				Reject: true,
				Status: http.StatusBadRequest,
				Reason: "CR/LF in header name",
				RuleID: "HARDEN-CRLF-HEADER-NAME",
			}
		}
	}

	// 3. Double-encoded path traversal. Decode the path twice and look
	// for `..` segments — this catches `%252e%252e/` which a single-
	// pass decoder treats as literal `%2e%2e/` and so misses.
	if r.URL != nil {
		raw := r.URL.RawPath
		if raw == "" {
			raw = r.URL.Path
		}
		for i := 0; i < 2; i++ {
			next, err := url.PathUnescape(raw)
			if err != nil {
				break
			}
			if next == raw {
				break
			}
			raw = next
		}
		// Normalise backslashes (Windows-y origins) so `..\..` lands.
		probe := strings.ReplaceAll(raw, "\\", "/")
		if strings.Contains(probe, "../") || strings.HasSuffix(probe, "/..") || strings.Contains(probe, "/./") {
			return hardenVerdict{
				Reject: true,
				Status: http.StatusBadRequest,
				Reason: "encoded path traversal",
				RuleID: "HARDEN-PATH-TRAVERSAL",
			}
		}
	}

	// 4. Method allowlist (deny well-known dangerous verbs).
	switch strings.ToUpper(r.Method) {
	case "TRACE", "TRACK", "DEBUG", "CONNECT":
		// CONNECT is legal for explicit forward proxies, but WEWAF is a
		// reverse proxy; CONNECT against a backend is almost always
		// abuse. Operators can lift this via a custom rule if needed.
		return hardenVerdict{
			Reject: true,
			Status: http.StatusMethodNotAllowed,
			Reason: "method " + r.Method + " not permitted",
			RuleID: "HARDEN-METHOD",
		}
	}

	// 5. Host header sanity — reject empty Host (HTTP/1.1 §5.4 says it
	// MUST be present and non-empty) and Host values containing a
	// nul / CTL char.
	host := r.Host
	if host == "" {
		return hardenVerdict{
			Reject: true,
			Status: http.StatusBadRequest,
			Reason: "missing Host header",
			RuleID: "HARDEN-HOST-MISSING",
		}
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c < 0x20 || c == 0x7f {
			return hardenVerdict{
				Reject: true,
				Status: http.StatusBadRequest,
				Reason: "control char in Host",
				RuleID: "HARDEN-HOST-CTL",
			}
		}
	}

	return hardenVerdict{}
}

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/engine"
	"wewaf/internal/limits"
	"wewaf/internal/telemetry"
)

// WAFProxy wraps a reverse proxy with WAF inspection.
type WAFProxy struct {
	cfg       *config.Config
	eng       *engine.Engine
	metrics   *telemetry.Metrics
	bf        *bruteforce.Detector
	sema      *limits.Semaphore
	transport http.RoundTripper
	backend   *url.URL
	proxy     *httputil.ReverseProxy
}

// NewWAFProxy creates a proxy that inspects traffic before forwarding.
func NewWAFProxy(cfg *config.Config, eng *engine.Engine, metrics *telemetry.Metrics, bf *bruteforce.Detector) (*WAFProxy, error) {
	backend, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid backend_url: %w", err)
	}

	sema := limits.NewSemaphore(cfg.MaxConcurrentReq)

	wp := &WAFProxy{
		cfg:     cfg,
		eng:     eng,
		metrics: metrics,
		bf:      bf,
		sema:    sema,
		backend: backend,
		transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	wp.proxy = httputil.NewSingleHostReverseProxy(backend)
	wp.proxy.Transport = wp.wafTransport()
	wp.proxy.ErrorHandler = wp.errorHandler

	return wp, nil
}

// ServeHTTP implements http.Handler.
func (wp *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := wp.sema.Acquire(r.Context()); err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer wp.sema.Release()

	// Create WAF transaction.
	tx := core.NewTransaction(w, r, wp.cfg.TrustXFF)
	// Clamp reported ContentLength to avoid uint64 wrap on chunked requests.
	reportedLen := int(r.ContentLength)
	if reportedLen < 0 {
		reportedLen = 0
	}
	wp.metrics.RecordRequest(tx.ClientIP, reportedLen)

	// WebSocket / upgrade passthrough: skip deep inspection.
	if isWebSocket(r) {
		r = WithTransaction(r, tx)
		wp.proxy.ServeHTTP(w, r)
		wp.eng.ProcessLogging(tx)
		return
	}

	// Phase 1: Request Headers.
	if intr := wp.eng.ProcessRequestHeaders(tx); intr != nil {
		wp.metrics.RecordBlock(tx.ClientIP, r.Method, r.URL.Path, "multi", intr.Message, tx.ScoreSnapshot())
		wp.writeBlock(w, intr, tx.ID)
		wp.eng.ProcessLogging(tx)
		return
	}

	// Buffer body for inspection, capped at MaxBodyBytes regardless of Content-Length.
	if r.Body != nil {
		limited := io.LimitReader(r.Body, wp.cfg.MaxBodyBytes)
		body, err := io.ReadAll(limited)
		if err == nil {
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
	}

	// Phase 2: Request Body.
	if intr := wp.eng.ProcessRequestBody(tx); intr != nil {
		wp.metrics.RecordBlock(tx.ClientIP, r.Method, r.URL.Path, "multi", intr.Message, tx.ScoreSnapshot())
		wp.writeBlock(w, intr, tx.ID)
		wp.eng.ProcessLogging(tx)
		return
	}

	// Brute-force check for login endpoints.
	if wp.bf != nil && isLoginRequest(r) {
		key := bruteforce.Key(tx.ClientIP, "")
		count := wp.bf.Record(key)
		if count >= wp.cfg.BruteForceThreshold {
			wp.metrics.RecordBlock(tx.ClientIP, r.Method, r.URL.Path, "BRUTE-FORCE", "Brute-force threshold exceeded", 100)
			wp.writeBlock(w, &core.Interruption{Action: core.ActionBlock, Status: http.StatusForbidden, Message: "Too many login attempts"}, tx.ID)
			wp.eng.ProcessLogging(tx)
			return
		}
	}

	// Wrap response writer to capture pass metrics.
	rec := &responseRecorder{ResponseWriter: w}

	// Attach transaction to context so the response inspector can access it.
	r = WithTransaction(r, tx)

	// Forward to backend.
	wp.proxy.ServeHTTP(rec, r)
	wp.metrics.RecordPass(rec.bytesWritten, rec.statusCode)

	// Phases 3-5 happen inside the transport/response pipeline.
	wp.eng.ProcessLogging(tx)
}

// wafTransport wraps the real transport to intercept responses.
func (wp *WAFProxy) wafTransport() http.RoundTripper {
	return &wafRoundTripper{
		base: wp.transport,
		eng:  wp.eng,
	}
}

// wafRoundTripper inspects backend responses.
type wafRoundTripper struct {
	base http.RoundTripper
	eng  *engine.Engine
}

func (rt *wafRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// We need the transaction context to associate with this request.
	// Since http.Request carries a Context, we stash tx there.
	tx, ok := req.Context().Value(txKey).(*core.Transaction)
	if !ok {
		// No WAF context; pass through directly (should not happen in normal flow).
		return rt.base.RoundTrip(req)
	}

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Phase 3: Response Headers.
	if intr := rt.eng.ProcessResponseHeaders(tx, resp.StatusCode, resp.Header); intr != nil {
		// We cannot rewrite the response after headers are sent in standard RoundTripper,
		// but we can drain the body and return a synthetic response.
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return wpSyntheticResponse(intr), nil
	}

	// Phase 4: Response Body (capped at 1 MiB to limit latency).
	if resp.Body != nil {
		const maxRespBody = 1 << 20 // 1 MiB
		limited := io.LimitReader(resp.Body, maxRespBody)
		body, _ := io.ReadAll(limited)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		if intr := rt.eng.ProcessResponseBody(tx, body); intr != nil {
			resp.Body.Close()
			return wpSyntheticResponse(intr), nil
		}
	}

	return resp, nil
}

// writeBlock writes an HTTP error response for a blocked transaction,
// or silently drops the connection if the action is Drop.
func (wp *WAFProxy) writeBlock(w http.ResponseWriter, intr *core.Interruption, txID string) {
	if intr.Action == core.ActionDrop {
		if h, ok := w.(http.Hijacker); ok {
			conn, _, err := h.Hijack()
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		// Fallback: force close via chunked terminator trick.
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-WAF-Action", intr.Action.String())
	w.WriteHeader(intr.Status)
	_, _ = fmt.Fprintf(w, "403 Forbidden\nRequest blocked by WEWaf.\nIncident ID: %s\n", txID)
}

// errorHandler handles backend connection errors.
func (wp *WAFProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	wp.eng.LogError("proxy: backend error: %v", err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// txKey is a private context key for stashing the WAF transaction.
type txKeyType struct{}

var txKey = txKeyType{}

// wpSyntheticResponse creates a fake HTTP response when the WAF blocks during the response phase.
func wpSyntheticResponse(intr *core.Interruption) *http.Response {
	body := []byte("403 Forbidden\nRequest blocked by WEWaf.\n")
	return &http.Response{
		StatusCode: intr.Status,
		Status:     http.StatusText(intr.Status),
		Header: http.Header{
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"X-WAF-Action":   []string{intr.Action.String()},
			"Content-Length": []string{fmt.Sprintf("%d", len(body))},
		},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// WithTransaction returns a new request with the WAF transaction attached.
func WithTransaction(req *http.Request, tx *core.Transaction) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), txKey, tx))
}

// responseRecorder wraps http.ResponseWriter to capture status and bytes written.
type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
	wroteHeader  bool
}

func (rr *responseRecorder) WriteHeader(code int) {
	if !rr.wroteHeader {
		rr.statusCode = code
		rr.wroteHeader = true
		rr.ResponseWriter.WriteHeader(code)
	}
}

func (rr *responseRecorder) Write(p []byte) (int, error) {
	if !rr.wroteHeader {
		rr.WriteHeader(http.StatusOK)
	}
	n, err := rr.ResponseWriter.Write(p)
	rr.bytesWritten += n
	return n, err
}

func (rr *responseRecorder) Flush() {
	if f, ok := rr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rr.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("responseRecorder: Hijacker not supported by underlying writer")
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func isLoginRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := strings.ToLower(r.URL.Path)
	loginPaths := []string{"/login", "/auth", "/signin", "/wp-login.php", "/admin/login", "/api/login"}
	for _, lp := range loginPaths {
		if path == lp || strings.HasSuffix(path, lp) {
			return true
		}
	}
	return false
}

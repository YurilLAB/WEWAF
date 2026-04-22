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
	"strconv"
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
	cfg     *config.Config
	eng     *engine.Engine
	metrics *telemetry.Metrics
	bf      *bruteforce.Detector
	sema    *limits.Semaphore
	rl      *limits.RateLimiter
	backend *url.URL
	proxy   *httputil.ReverseProxy
}

// seekableBody wraps a bytes.Reader so it can be re-read by the engine.
type seekableBody struct {
	*bytes.Reader
}

func (s *seekableBody) Close() error { return nil }

// NewWAFProxy creates a proxy that inspects traffic before forwarding.
func NewWAFProxy(cfg *config.Config, eng *engine.Engine, metrics *telemetry.Metrics, bf *bruteforce.Detector) (*WAFProxy, error) {
	backend, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid backend_url: %w", err)
	}

	sema := limits.NewSemaphore(cfg.MaxConcurrentReq)
	rl := limits.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	wp := &WAFProxy{
		cfg:     cfg,
		eng:     eng,
		metrics: metrics,
		bf:      bf,
		sema:    sema,
		rl:      rl,
		backend: backend,
	}

	wp.proxy = httputil.NewSingleHostReverseProxy(backend)
	wp.proxy.ModifyResponse = wp.modifyResponse
	wp.proxy.ErrorHandler = wp.errorHandler

	return wp, nil
}

// ServeHTTP implements http.Handler.
func (wp *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			wp.eng.LogError("proxy: panic in ServeHTTP: %v", rec)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()

	if err := wp.sema.Acquire(r.Context()); err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer wp.sema.Release()

	clientIP := getClientIP(r, wp.cfg.TrustXFF)
	if !wp.rl.Allow(clientIP) {
		w.Header().Set("Retry-After", "60")
		wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "RATE-LIMIT", "Rate limit exceeded", 0)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Create WAF transaction.
	tx := core.NewTransaction(w, r, wp.cfg.TrustXFF)
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

	// Buffer body for inspection and forwarding.
	var body []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, wp.cfg.MaxBodyBytes)
		var err error
		body, err = io.ReadAll(limited)
		if err != nil {
			wp.eng.LogError("proxy: body read error: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			wp.eng.ProcessLogging(tx)
			return
		}
		_ = r.Body.Close()
		r.Body = &seekableBody{Reader: bytes.NewReader(body)}
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		r.GetBody = func() (io.ReadCloser, error) {
			return &seekableBody{Reader: bytes.NewReader(body)}, nil
		}
		tx.SetMetadata("body", body)
	}

	// Brute-force record early so blocked attempts still count.
	isLogin := isLoginRequest(r)
	if wp.bf != nil && isLogin {
		key := bruteforce.Key(tx.ClientIP, "")
		wp.bf.Record(key)
	}

	// Phase 1: Request Headers.
	if intr := wp.eng.ProcessRequestHeaders(tx); intr != nil {
		wp.handleBlock(w, tx, intr)
		return
	}

	// Phase 2: Request Body.
	if intr := wp.eng.ProcessRequestBody(tx); intr != nil {
		wp.handleBlock(w, tx, intr)
		return
	}

	// Brute-force enforcement.
	if wp.bf != nil && isLogin {
		key := bruteforce.Key(tx.ClientIP, "")
		if wp.bf.IsBruteForce(key, wp.cfg.BruteForceThreshold) {
			mode := wp.cfg.ModeSnapshot()
			if mode != "detection" && mode != "learning" {
				wp.metrics.RecordBlock(tx.ClientIP, r.Method, r.URL.Path, "BRUTE-FORCE", "Brute-force threshold exceeded", 100)
				intr := &core.Interruption{Action: core.ActionBlock, Status: http.StatusForbidden, Message: "Too many login attempts"}
				tx.SetBlocked(core.PhaseRequestBody)
				tx.AddMatch(core.Match{
					RuleID:    "BRUTE-FORCE",
					RuleName:  "Brute-force threshold exceeded",
					Phase:     core.PhaseRequestBody,
					Target:    "login",
					Value:     "",
					Score:     100,
					Action:    core.ActionBlock,
					Message:   "Too many login attempts",
					Timestamp: time.Now().UTC(),
				})
				wp.handleBlock(w, tx, intr)
				return
			}
		}
	}

	// Wrap response writer to capture pass metrics.
	rec := &responseRecorder{ResponseWriter: w}

	// Attach transaction to context so ModifyResponse can access it.
	r = WithTransaction(r, tx)

	// Forward to backend.
	wp.proxy.ServeHTTP(rec, r)

	if !tx.IsBlocked() {
		wp.metrics.RecordPass(rec.bytesWritten, rec.statusCode)
	}
	wp.eng.ProcessLogging(tx)
}

// modifyResponse inspects backend responses (Phase 3 and 4).
func (wp *WAFProxy) modifyResponse(res *http.Response) error {
	tx, ok := res.Request.Context().Value(txKey).(*core.Transaction)
	if !ok {
		return nil
	}

	// Phase 3: Response Headers.
	if intr := wp.eng.ProcessResponseHeaders(tx, res.StatusCode, res.Header); intr != nil {
		wp.recordBlockFromResponse(tx, intr)
		return wp.replaceWithSynthetic(res, intr)
	}

	// Phase 4: Response Body (inspect capped prefix, forward full body).
	if res.Body == nil {
		return nil
	}
	maxInspect := wp.cfg.MaxBodyBytes
	if maxInspect <= 0 {
		maxInspect = 1 << 20
	}
	limited := io.LimitReader(res.Body, maxInspect)
	inspectBody, err := io.ReadAll(limited)
	if err != nil {
		return err
	}

	if intr := wp.eng.ProcessResponseBody(tx, inspectBody); intr != nil {
		wp.recordBlockFromResponse(tx, intr)
		return wp.replaceWithSynthetic(res, intr)
	}

	// Reconstruct full body: inspected prefix + remainder of original stream.
	res.Body = io.NopCloser(io.MultiReader(bytes.NewReader(inspectBody), res.Body))

	return nil
}

func (wp *WAFProxy) recordBlockFromResponse(tx *core.Transaction, intr *core.Interruption) {
	wp.metrics.RecordBlock(tx.ClientIP, tx.Request.Method, tx.Request.URL.Path, "multi", intr.Message, tx.ScoreSnapshot())
	tx.SetBlocked(core.PhaseResponseBody)
}

func (wp *WAFProxy) replaceWithSynthetic(res *http.Response, intr *core.Interruption) error {
	body := []byte(fmt.Sprintf("%d %s\nRequest blocked by WEWaf.\n", intr.Status, http.StatusText(intr.Status)))
	res.StatusCode = intr.Status
	res.Status = http.StatusText(intr.Status)
	headers := http.Header{
		"Content-Type":   []string{"text/plain; charset=utf-8"},
		"X-WAF-Action":   []string{intr.Action.String()},
		"Content-Length": []string{strconv.Itoa(len(body))},
	}
	if len(intr.Matches) > 0 {
		headers.Set("X-WAF-Rule-ID", intr.Matches[0].RuleID)
	}
	res.Header = headers
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	return nil
}

func (wp *WAFProxy) handleBlock(w http.ResponseWriter, tx *core.Transaction, intr *core.Interruption) {
	wp.metrics.RecordBlock(tx.ClientIP, tx.Request.Method, tx.Request.URL.Path, "multi", intr.Message, tx.ScoreSnapshot())
	wp.writeBlock(w, intr, tx.ID)
	wp.eng.ProcessLogging(tx)
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
		w.Header().Set("Connection", "close")
		w.WriteHeader(intr.Status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-WAF-Action", intr.Action.String())
	w.WriteHeader(intr.Status)
	_, _ = fmt.Fprintf(w, "%d %s\nRequest blocked by WEWaf.\nIncident ID: %s\n", intr.Status, http.StatusText(intr.Status), txID)
}

// errorHandler handles backend connection errors.
func (wp *WAFProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	wp.eng.LogError("proxy: backend error: %v", err)
	wp.metrics.RecordError()
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// txKey is a private context key for stashing the WAF transaction.
type txKeyType struct{}

var txKey = txKeyType{}

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

func getClientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func isLoginRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := strings.ToLower(r.URL.Path)
	loginPaths := []string{"/login", "/auth", "/signin", "/wp-login.php", "/admin/login", "/api/login"}
	for _, lp := range loginPaths {
		if path == lp {
			return true
		}
	}
	return false
}

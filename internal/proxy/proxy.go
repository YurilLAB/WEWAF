package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
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

var credLeakRE = regexp.MustCompile(`(?i)(api_key|password|secret)=([^&\s"']+)`)

// NewWAFProxy creates a proxy that inspects traffic before forwarding.
func NewWAFProxy(cfg *config.Config, eng *engine.Engine, metrics *telemetry.Metrics, bf *bruteforce.Detector) (*WAFProxy, error) {
	backend, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid backend_url: %w", err)
	}
	if backend.Scheme != "http" && backend.Scheme != "https" {
		return nil, fmt.Errorf("proxy: invalid backend_url scheme %q (must be http or https)", backend.Scheme)
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
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			wp.eng.LogError("proxy: panic in ServeHTTP: %v", rec)
			if w != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			wp.eng.LogError("proxy: slow request detected (%v) %s %s", elapsed, r.Method, r.URL.Path)
		}
	}()

	if r == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Reject requests with extremely large headers (>64KB total).
	var totalHeaderSize int
	for k, v := range r.Header {
		totalHeaderSize += len(k) + 2
		for _, val := range v {
			totalHeaderSize += len(val)
		}
	}
	if totalHeaderSize > 64*1024 {
		http.Error(w, "Request Header Fields Too Large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}

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

	// Enforce body size limit before reading.
	if r.ContentLength > wp.cfg.MaxBodyBytes && r.ContentLength > 0 {
		http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
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
			_ = r.Body.Close()
			r.Body = io.NopCloser(&bytes.Reader{})
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
	intrHeaders := wp.eng.ProcessRequestHeaders(tx)
	// Record any bot-fingerprint matches so /api/bots/detected reflects live
	// state. We do this whether or not the request is ultimately blocked
	// because detection happens at this phase.
	for _, m := range tx.MatchesSnapshot() {
		if strings.HasPrefix(m.RuleID, "BOT-") || strings.HasPrefix(m.RuleID, "SCAN-") {
			wp.metrics.RecordBotEvent(tx.ClientIP, r.UserAgent(), m.Value, m.Score)
			break // one bot event per transaction is enough
		}
	}
	if intrHeaders != nil {
		wp.handleBlock(w, tx, intrHeaders)
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
	if res == nil || res.Request == nil {
		return nil
	}

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

	// Redact leaked credentials from the response body before forwarding.
	inspectBody = credLeakRE.ReplaceAll(inspectBody, []byte("${1}=[REDACTED]"))
	res.Header.Del("Content-Length")
	res.ContentLength = -1

	// Reconstruct full body: inspected prefix + remainder of original stream.
	res.Body = io.NopCloser(io.MultiReader(bytes.NewReader(inspectBody), res.Body))

	// Inject security headers and strip identifying ones.
	if wp.cfg.SecurityHeadersEnabled {
		res.Header.Set("X-Content-Type-Options", "nosniff")
		res.Header.Set("X-Frame-Options", "DENY")
		res.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		res.Header.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	}
	res.Header.Del("Server")
	res.Header.Del("X-Powered-By")

	return nil
}

func (wp *WAFProxy) recordBlockFromResponse(tx *core.Transaction, intr *core.Interruption) {
	if tx == nil || tx.Request == nil || intr == nil {
		return
	}
	ruleID, _ := primaryMatch(intr)
	wp.metrics.RecordBlock(tx.ClientIP, tx.Request.Method, tx.Request.URL.Path, ruleID, intr.Message, tx.ScoreSnapshot())
	tx.SetBlocked(core.PhaseResponseBody)
}

func (wp *WAFProxy) replaceWithSynthetic(res *http.Response, intr *core.Interruption) error {
	if intr == nil {
		return errors.New("proxy: replaceWithSynthetic called with nil interruption")
	}

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
	if tx == nil || tx.Request == nil || intr == nil {
		if w != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
		return
	}
	ruleID, _ := primaryMatch(intr)
	wp.metrics.RecordBlock(tx.ClientIP, tx.Request.Method, tx.Request.URL.Path, ruleID, intr.Message, tx.ScoreSnapshot())
	wp.writeBlock(w, intr, tx.ID)
	wp.eng.ProcessLogging(tx)
}

// primaryMatch returns the rule ID + rule name for the first match in an
// interruption. Callers get "multi" if there is no match info at all, which
// keeps the metrics schema consistent with legacy behaviour.
func primaryMatch(intr *core.Interruption) (string, string) {
	if intr == nil || len(intr.Matches) == 0 {
		return "multi", ""
	}
	m := intr.Matches[0]
	return m.RuleID, m.RuleName
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
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-WAF-Action", intr.Action.String())
	w.WriteHeader(intr.Status)
	_, _ = fmt.Fprintf(w, "%d %s\nRequest blocked by WEWaf.\nIncident ID: %s\n", intr.Status, http.StatusText(intr.Status), txID)
}

// errorHandler handles backend connection errors.
func (wp *WAFProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			wp.eng.LogError("proxy: panic in errorHandler: %v", rec)
			if w != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}()
	var logMsg string
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		logMsg = "proxy: backend connection refused"
	case errors.Is(err, syscall.ETIMEDOUT):
		logMsg = "proxy: backend connection timed out"
	default:
		if urlErr, ok := err.(*url.Error); ok {
			if urlErr.Timeout() {
				logMsg = "proxy: backend request timeout"
			} else if dnsErr, ok := urlErr.Err.(*net.DNSError); ok {
				logMsg = fmt.Sprintf("proxy: backend DNS error: %s", dnsErr.Error())
			} else {
				logMsg = fmt.Sprintf("proxy: backend error: %v", err)
			}
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logMsg = "proxy: backend network timeout"
		} else {
			logMsg = fmt.Sprintf("proxy: backend error: %v", err)
		}
	}
	wp.eng.LogError("%s", logMsg)
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
	if r == nil {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func isLoginRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := strings.ToLower(strings.TrimRight(r.URL.Path, "/"))
	loginPaths := []string{
		"/login", "/auth", "/signin", "/wp-login.php", "/admin/login",
		"/api/login", "/api/auth", "/oauth/token", "/v1/login",
		"/api/v1/login", "/api/v2/login", "/authenticate", "/session", "/token",
		"/register", "/signup",
	}
	for _, lp := range loginPaths {
		if path == lp {
			return true
		}
	}
	return false
}

// EgressProxy intercepts outbound HTTP requests from the backend app.
type EgressProxy struct {
	cfg     *config.Config
	eng     *engine.Engine
	metrics *telemetry.Metrics
	banList *core.BanList
	client  *http.Client
}

// NewEgressProxy creates an egress inspection proxy.
func NewEgressProxy(cfg *config.Config, eng *engine.Engine, metrics *telemetry.Metrics, banList *core.BanList) *EgressProxy {
	return &EgressProxy{
		cfg:     cfg,
		eng:     eng,
		metrics: metrics,
		banList: banList,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

func (ep *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			if ep.eng != nil {
				ep.eng.LogError("egress: slow outbound request detected (%v) %s %s", elapsed, r.Method, r.URL.String())
			}
		}
	}()

	if r == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Determine the target URL.
	var targetURL string
	if r.Method == http.MethodConnect {
		targetURL = "https://" + r.Host
	} else {
		if r.URL.IsAbs() {
			targetURL = r.URL.String()
		} else {
			targetURL = "http://" + r.Host + r.URL.RequestURI()
		}
	}

	// Parse for inspection.
	parsed, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Check allowlist — exact host match or dot-bounded subdomain match so
	// "google.com" does NOT allow "googlecompromise.evil.com".
	if len(ep.cfg.EgressAllowlist) > 0 {
		if !allowlistMatch(parsed.Hostname(), ep.cfg.EgressAllowlist) {
			ep.recordEgressBlock(targetURL, "destination not in egress allowlist")
			ep.eng.LogError("egress: blocked request to %s: destination not in egress allowlist", targetURL)
			http.Error(w, "Forbidden: destination not in egress allowlist", http.StatusForbidden)
			return
		}
	}

	// Block private IPs. Resolves the hostname so an attacker-controlled DNS
	// record that points to 127.0.0.1 / 169.254.169.254 is caught too.
	if ep.cfg.EgressBlockPrivateIPs {
		if reason := resolvedDangerReason(parsed.Hostname()); reason != "" {
			ep.recordEgressBlock(targetURL, reason)
			ep.eng.LogError("egress: blocked request to %s: %s", targetURL, reason)
			http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
			return
		}
	}

	// CONNECT tunnel support for HTTPS egress.
	if r.Method == http.MethodConnect {
		ep.recordEgressAllow(targetURL)
		ep.handleConnect(w, r)
		return
	}

	// EgressMaxBodyBytes enforcement.
	if r.ContentLength > ep.cfg.EgressMaxBodyBytes && r.ContentLength > 0 {
		ep.recordEgressBlock(targetURL, "payload too large")
		ep.eng.LogError("egress: blocked request to %s: payload too large", targetURL)
		http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	// Buffer body for inspection.
	var body []byte
	if r.Body != nil {
		limit := ep.cfg.EgressMaxBodyBytes
		if limit <= 0 {
			limit = 10 * 1024 * 1024
		}
		limited := io.LimitReader(r.Body, limit)
		body, _ = io.ReadAll(limited)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	// Create a synthetic transaction for egress inspection.
	tx := core.NewTransaction(w, r, false)
	tx.SetMetadata("body", body)

	targets := map[string]string{
		"url":    targetURL,
		"method": r.Method,
		"body":   string(body),
	}
	for k, v := range r.Header {
		targets["headers."+k] = strings.Join(v, ", ")
	}

	if intr := ep.eng.EvaluateEgress(tx, targets); intr != nil {
		reason := "egress policy violation"
		if len(intr.Matches) > 0 && intr.Matches[0].RuleID != "" {
			reason = "egress rule: " + intr.Matches[0].RuleID
		}
		ep.recordEgressBlock(targetURL, reason)
		ep.eng.LogError("egress: blocked request to %s: %s", targetURL, reason)
		http.Error(w, "Forbidden: egress policy violation", http.StatusForbidden)
		return
	}

	ep.recordEgressAllow(targetURL)

	// Forward the request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	for k, v := range r.Header {
		outReq.Header[k] = v
	}
	if host := parsed.Host; host != "" {
		outReq.Host = host
	}

	resp, err := ep.client.Do(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (ep *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			ep.eng.LogError("egress: panic in CONNECT tunnel: %v", rec)
		}
	}()

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	// Bidirectional pipe. When either direction ends, close both sides so
	// the other goroutine can unblock instead of leaking for io.Copy's
	// lifetime (which was previously unbounded).
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		defer func() {
			_ = recover()
			done <- struct{}{}
		}()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go pipe(destConn, clientConn)
	go pipe(clientConn, destConn)

	// Wait for the first copy to finish, then force-close both sides so the
	// other goroutine unblocks. Previously an idle peer could keep the other
	// direction parked indefinitely.
	<-done
	_ = destConn.Close()
	_ = clientConn.Close()
	<-done
}

func (ep *EgressProxy) recordEgressBlock(targetURL, reason string) {
	if ep.metrics != nil {
		ep.metrics.RecordEgressBlock(targetURL, reason)
	}
}

func (ep *EgressProxy) recordEgressAllow(targetURL string) {
	if ep.metrics != nil {
		ep.metrics.RecordEgressAllow(targetURL)
	}
}

// allowlistMatch returns true if host equals an allowlist entry exactly or is
// a subdomain of an entry (dot-bounded). Patterns prefixed with "*." are
// treated as wildcard subdomain entries ("*.example.com" matches
// "api.example.com" but not "example.com"). The previous implementation used
// strings.Contains which let "google.com" permit "googlecompromise.evil.com".
func allowlistMatch(host string, allowlist []string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	for _, raw := range allowlist {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			suffix := entry[2:]
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
		if strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

// metadataIPs is the set of cloud-provider metadata endpoints we never want
// outbound requests to reach. These are blocked even if the hostname resolves
// indirectly (DNS rebinding or user-controlled CNAMEs).
var metadataIPs = map[string]struct{}{
	"169.254.169.254": {}, // AWS, GCP, Azure, OpenStack, DO
	"100.100.100.200": {}, // Alibaba Cloud
	"fd00:ec2::254":   {}, // AWS IMDSv2 over IPv6
}

// resolvedDangerReason returns a non-empty reason string if host either is or
// resolves to a private / loopback / link-local / cloud-metadata address.
// Returning an empty string means the host is safe to contact.
func resolvedDangerReason(host string) string {
	host = strings.Trim(host, "[]")
	if host == "" {
		return "empty destination host"
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return "internal hostname blocked"
	}
	// Literal IP — direct classification.
	if ip := net.ParseIP(host); ip != nil {
		if reason := classifyIP(ip); reason != "" {
			return reason
		}
		return ""
	}
	// Hostname — resolve and check every answer. A short timeout keeps the
	// hot path snappy; resolution failures fail closed.
	resolver := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "dns resolution failed"
	}
	for _, ip := range ips {
		if reason := classifyIP(ip); reason != "" {
			return reason
		}
	}
	return ""
}

func classifyIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if _, ok := metadataIPs[ip.String()]; ok {
		return "cloud metadata endpoint blocked"
	}
	if ip.IsLoopback() {
		return "loopback IP destination blocked"
	}
	if ip.IsPrivate() {
		return "private IP destination blocked"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local IP destination blocked"
	}
	if ip.IsUnspecified() {
		return "unspecified IP destination blocked"
	}
	if ip.IsMulticast() {
		return "multicast IP destination blocked"
	}
	return ""
}

// isPrivateHost is retained for legacy callers. Prefer resolvedDangerReason.
func isPrivateHost(host string) bool {
	return resolvedDangerReason(host) != ""
}

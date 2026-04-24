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
	"sync/atomic"
	"syscall"
	"time"

	"wewaf/internal/bruteforce"
	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/ddos"
	"wewaf/internal/engine"
	"wewaf/internal/limits"
	"wewaf/internal/shaper"
	"wewaf/internal/telemetry"
	"wewaf/internal/zerotrust"
)

// WAFProxy wraps a reverse proxy with WAF inspection.
type WAFProxy struct {
	cfg       *config.Config
	eng       *engine.Engine
	metrics   *telemetry.Metrics
	bf        *bruteforce.Detector
	sema      *limits.Semaphore
	rl        *limits.RateLimiter
	backend   *url.URL
	proxy     *httputil.ReverseProxy
	ddos      *ddos.Detector
	breaker   *limits.Breaker
	zeroTrust *zerotrust.Engine
	shaper    *shaper.Shaper
	// shaperAttack tracks the shaper's "tightened" state so Tighten/Relax
	// are only invoked at the state-transition edge. Calling them on every
	// request was an unnecessary mutex acquisition per hit.
	shaperAttack atomic.Bool
}

// ShaperStats returns the admission controller's counters.
func (wp *WAFProxy) ShaperStats() map[string]interface{} {
	if wp == nil || wp.shaper == nil {
		return map[string]interface{}{}
	}
	return wp.shaper.StatsSnapshot()
}

// DDoSStats returns the detector's counters for the admin API.
func (wp *WAFProxy) DDoSStats() map[string]interface{} {
	if wp == nil || wp.ddos == nil {
		return map[string]interface{}{}
	}
	return wp.ddos.StatsSnapshot()
}

// BreakerStats returns the breaker's counters for the admin API.
func (wp *WAFProxy) BreakerStats() map[string]interface{} {
	if wp == nil || wp.breaker == nil {
		return map[string]interface{}{}
	}
	return wp.breaker.StatsSnapshot()
}

// ZeroTrustEngine exposes the policy engine so the admin API can update it.
func (wp *WAFProxy) ZeroTrustEngine() *zerotrust.Engine {
	if wp == nil {
		return nil
	}
	return wp.zeroTrust
}

// seekableBody wraps a bytes.Reader so it can be re-read by the engine.
type seekableBody struct {
	*bytes.Reader
}

func (s *seekableBody) Close() error { return nil }

// multiReadCloser combines an in-memory prefix with the original response
// body so Phase-4 can hand the full stream back to the proxy. The underlying
// io.NopCloser+io.MultiReader idiom dropped the upstream Close, leaking the
// backend connection whenever a client disconnected before reading the tail.
// Close here propagates to the original body exactly once — `closed` is an
// atomic.Bool so a handler that calls Close from a goroutine different from
// the reader can't double-close.
type multiReadCloser struct {
	reader io.Reader
	closer io.Closer
	closed atomic.Bool
}

func (m *multiReadCloser) Read(p []byte) (int, error) { return m.reader.Read(p) }

func (m *multiReadCloser) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	if m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

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
		ddos: ddos.New(ddos.Config{
			VolumetricBaseline:      cfg.DDoSVolumetricBaseline,
			VolumetricSpike:         cfg.DDoSVolumetricSpike,
			ConnRateThreshold:       cfg.DDoSConnRateThreshold,
			SlowMinBPS:              cfg.DDoSSlowReadBPS,
			WarmupSeconds:           cfg.DDoSWarmupSeconds,
			MinAbsoluteRPS:          cfg.DDoSMinAbsoluteRPS,
			SpikeWindowsRequired:    cfg.DDoSSpikeWindowsRequired,
			CoolDownSeconds:         cfg.DDoSCoolDownSeconds,
			BotnetUniqueIPThreshold: cfg.DDoSBotnetUniqueIPThreshold,
		}),
		breaker: limits.NewBreaker(
			cfg.BreakerConsecutiveFailures,
			time.Duration(cfg.BreakerOpenTimeoutSec)*time.Second,
		),
		zeroTrust: zerotrust.NewEngine(nil),
		shaper: shaper.New(shaper.Config{
			Enabled: cfg.ShaperEnabled,
			MaxRPS:  cfg.ShaperMaxRPS,
			Burst:   cfg.ShaperBurst,
		}),
	}

	wp.proxy = httputil.NewSingleHostReverseProxy(backend)
	// A reverse proxy left on DefaultTransport has no per-connection timeouts
	// and no pool caps — a slow backend can park proxy goroutines for the full
	// WriteTimeout and unbounded idle connections can exhaust FD limits. We
	// give it a hardened transport with explicit timeouts at every stage of
	// the request lifecycle, a keep-alive idle cap, and an expect-continue
	// timeout so backends that ignore 100-continue don't hang the proxy.
	wp.proxy.Transport = newBackendTransport(cfg)
	wp.proxy.ModifyResponse = wp.modifyResponse
	wp.proxy.ErrorHandler = wp.errorHandler

	return wp, nil
}

// newBackendTransport returns an http.Transport with explicit timeouts and
// bounded connection pools so a stalled backend cannot exhaust proxy
// goroutines or file descriptors. Defaults are deliberately conservative
// enough to detect real failures quickly while still tolerating a WAN-backed
// origin.
func newBackendTransport(cfg *config.Config) *http.Transport {
	dialTimeout := 5 * time.Second
	if cfg.BackendDialTimeoutMs > 0 {
		dialTimeout = time.Duration(cfg.BackendDialTimeoutMs) * time.Millisecond
	}
	respTimeout := 30 * time.Second
	if cfg.BackendResponseHeaderTimeoutMs > 0 {
		respTimeout = time.Duration(cfg.BackendResponseHeaderTimeoutMs) * time.Millisecond
	}
	tlsTimeout := 10 * time.Second
	if cfg.BackendTLSHandshakeTimeoutMs > 0 {
		tlsTimeout = time.Duration(cfg.BackendTLSHandshakeTimeoutMs) * time.Millisecond
	}
	maxIdle := 200
	if cfg.BackendMaxIdleConns > 0 {
		maxIdle = cfg.BackendMaxIdleConns
	}
	maxPerHost := 64
	if cfg.BackendMaxConnsPerHost > 0 {
		maxPerHost = cfg.BackendMaxConnsPerHost
	}
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxPerHost / 2,
		MaxConnsPerHost:       maxPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: respTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ServeHTTP implements http.Handler.
func (wp *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Attach a request ID to every response so operators can correlate UI
	// events, logs, and error records. If the client already supplied one
	// via X-Request-ID, reuse it so upstream trace IDs are preserved.
	reqID := r.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = generateRequestID()
	}
	w.Header().Set("X-Request-ID", reqID)
	r = r.WithContext(contextWithRequestID(r.Context(), reqID))

	defer func() {
		if rec := recover(); rec != nil {
			wp.eng.LogError("proxy: panic in ServeHTTP: %v", rec)
			if w != nil {
				// Failsafe: block on panic unless operator opted into
				// fail-open. 503 + Retry-After lets clients back off.
				if wp.cfg.FailsafeMode == "open" {
					w.Header().Set("X-WAF-Failsafe", "open-pass")
					wp.proxy.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Retry-After", "5")
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			}
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			wp.eng.LogError("proxy: slow request detected (%v) %s %s rid=%s", elapsed, r.Method, r.URL.Path, reqID)
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

	// Pre-WAF admission control: if the shaper is enabled and the global
	// token bucket is empty, we early-reject with 429 before spending any
	// effort on inspection. Under attack the detector tells the shaper to
	// tighten the budget to 20% of base so the WAF keeps enough resources
	// to serve the traffic it DOES admit. In normal operation the budget
	// is well above real traffic so this is a no-op.
	if wp.shaper != nil {
		// Edge-trigger the budget change — Tighten/Relax take a mutex, so
		// firing them on every request during a sustained attack was a
		// measurable contention source. Only flip on state transitions.
		if wp.ddos != nil && wp.ddos.IsUnderAttack() {
			if wp.shaperAttack.CompareAndSwap(false, true) {
				wp.shaper.Tighten(0.2)
			}
		} else {
			if wp.shaperAttack.CompareAndSwap(true, false) {
				wp.shaper.Relax()
			}
		}
		if !wp.shaper.Admit() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	semaStart := time.Now()
	if err := wp.sema.Acquire(r.Context()); err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer wp.sema.Release()
	semaWait := time.Since(semaStart)

	clientIP := getClientIP(r, wp.cfg.TrustXFF)

	// DDoS detection: classify the request before we spend any effort on it.
	// The detector tracks three independent signals (volumetric, per-IP
	// connection rate, distributed/botnet) and only flips "under attack"
	// after several consecutive spike windows — so normal traffic bursts
	// don't trigger false positives.
	switch wp.ddos.RecordRequest(clientIP, r.URL.Path) {
	case ddos.VerdictVolumetric:
		w.Header().Set("Retry-After", "30")
		wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "DDOS-VOLUMETRIC", "global RPS spike (sustained)", 0)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	case ddos.VerdictConnRate:
		w.Header().Set("Retry-After", "30")
		wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "DDOS-CONN-RATE", "connection-rate flood", 0)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	case ddos.VerdictBotnet:
		// Distributed low-rate attack on a sensitive path. Many unique
		// source IPs, each individually beneath the rate limit, all
		// converging on /login-style endpoints. Challenge the request
		// rather than hard-block since some IPs are likely legitimate.
		w.Header().Set("Retry-After", "60")
		wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "DDOS-BOTNET",
			"distributed attack pattern on sensitive path", 80)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if !wp.rl.Allow(clientIP) {
		w.Header().Set("Retry-After", "60")
		wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "RATE-LIMIT", "Rate limit exceeded", 0)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Zero-trust policy evaluation — applies path-scoped IP/country/header
	// rules before the request gets near the rule engine. Policies marked
	// Simulate return DecisionSimulate; we log the would-block but let the
	// request continue so operators can stage a policy before enforcing it.
	if wp.zeroTrust != nil {
		decision, reason, policy := wp.zeroTrust.Evaluate(r, clientIP)
		polID := "-"
		if policy != nil {
			polID = policy.ID
		}
		switch decision {
		case zerotrust.DecisionDeny:
			wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "ZERO-TRUST:"+polID, reason, 100)
			http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
			return
		case zerotrust.DecisionSimulate:
			// Would-block — emit as a log-only record so the dashboard's
			// simulate stats accumulate without breaking production traffic.
			wp.metrics.RecordBlockWithCategory(clientIP, r.Method, r.URL.Path,
				"ZERO-TRUST-SIM:"+polID, "zero_trust_simulate", reason, 0)
		}
	}

	// Circuit breaker — if the backend has been failing, short-circuit
	// before we spend time inspecting a request we can't deliver.
	if !wp.breaker.Allow() {
		w.Header().Set("Retry-After", "10")
		wp.metrics.RecordError()
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
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
		// Slow-read detection: measure total request lifetime (from proxy
		// accept, which is `start`), not just the body-read window. A true
		// Slowloris trickles headers AND body; measuring only the body read
		// hid it from the detector because the read itself completed fast
		// once we called io.ReadAll. The detector gates on SlowMinAge (10 s)
		// to avoid flagging legitimate slow clients with tiny payloads.
		//
		// We subtract `semaWait` so a congested WAF parking this request in
		// the semaphore queue doesn't make its own backlog look like a
		// Slowloris: the detector would otherwise flag legitimate small
		// POSTs during a concurrency-limit spike.
		slowAge := time.Since(start) - semaWait
		if slowAge < 0 {
			slowAge = 0
		}
		if wp.ddos.RecordSlowRead(len(body), slowAge) {
			wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "DDOS-SLOW-READ",
				"slow body read", 0)
			http.Error(w, "Request Timeout", http.StatusRequestTimeout)
			wp.eng.ProcessLogging(tx)
			return
		}
		// Optional gzip/brotli bomb defense. The compressed body passed the
		// MaxBodyBytes gate; decompress it into a ratio-capped buffer before
		// handing it to the engine so a 10 KB bomb expanding to 1 GB cannot
		// starve inspection memory. On failure we reject the request rather
		// than silently forwarding an uninspected compressed payload.
		if wp.cfg.DecompressInspect {
			if decoded, reason := maybeDecompressBody(r.Header, body,
				wp.cfg.DecompressRatioCap, wp.cfg.MaxDecompressBytes); reason != "" {
				wp.metrics.RecordBlock(clientIP, r.Method, r.URL.Path, "COMPRESS-BOMB", reason, 100)
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				wp.eng.ProcessLogging(tx)
				return
			} else if len(decoded) > 0 {
				tx.SetMetadata("decoded_body", decoded)
			}
		}
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
	// A response means the backend was reachable, regardless of status.
	// 5xx responses are still reported to the breaker as errors so a
	// backend that's stuck 500ing trips it.
	if res != nil && wp.breaker != nil {
		if res.StatusCode >= 500 && res.StatusCode <= 599 {
			wp.breaker.RecordFailure()
		} else {
			wp.breaker.RecordSuccess()
		}
	}
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
	// multiReadCloser propagates Close to the original response body so the
	// backend connection is released even if the client disconnects early.
	res.Body = &multiReadCloser{
		reader: io.MultiReader(bytes.NewReader(inspectBody), res.Body),
		closer: res.Body,
	}

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
	// Backend-level failure: count it against the circuit breaker.
	if wp.breaker != nil {
		wp.breaker.RecordFailure()
	}
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

// reqIDKey is a private context key for the per-request correlation ID.
type reqIDKeyType struct{}

var reqIDKey = reqIDKeyType{}

func contextWithRequestID(parent context.Context, id string) context.Context {
	return context.WithValue(parent, reqIDKey, id)
}

// RequestIDFromContext returns the request ID assigned at proxy entry, or
// an empty string if none was set.
func RequestIDFromContext(ctx context.Context) string {
	if v := ctx.Value(reqIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// generateRequestID returns a short, unique-enough ID. We don't need
// cryptographic randomness — just enough to correlate a request across logs
// and the UI within one session.
func generateRequestID() string {
	return fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), reqCounter.Add(1))
}

var reqCounter atomic.Uint64

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
	cfg      *config.Config
	eng      *engine.Engine
	metrics  *telemetry.Metrics
	banList  *core.BanList
	client   *http.Client
	dnsCache *egressDNSCache
	rl       *egressRateLimiter
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
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   16,
				MaxConnsPerHost:       32,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		dnsCache: newEgressDNSCache(60*time.Second, 4096),
		rl:       newEgressRateLimiter(50, 100),
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
	// record that points to 127.0.0.1 / 169.254.169.254 is caught too. The
	// DNS cache avoids hammering the resolver for every request.
	if ep.cfg.EgressBlockPrivateIPs {
		if reason := ep.dangerReason(r.Context(), parsed.Hostname()); reason != "" {
			ep.recordEgressBlock(targetURL, reason)
			ep.eng.LogError("egress: blocked request to %s: %s", targetURL, reason)
			http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
			return
		}
	}

	// Per-destination rate limit — one noisy dependency can't flood a
	// single third-party. We key on the raw hostname so CNAME chains that
	// resolve to the same backing IP are still counted separately.
	if !ep.rl.Allow(strings.ToLower(parsed.Hostname())) {
		ep.recordEgressBlock(targetURL, "egress rate limit exceeded")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
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
		var readErr error
		body, readErr = io.ReadAll(limited)
		_ = r.Body.Close()
		if readErr != nil {
			// Don't forward a truncated body as if it were complete.
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
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
	// Cap the forwarded response size at the configured egress body limit so
	// a huge / slow upstream can't stream megabytes through a rule that was
	// only supposed to relay API results. Without this the request-side
	// EgressMaxBodyBytes check gives a false sense of bounds.
	respLimit := ep.cfg.EgressMaxBodyBytes
	if respLimit <= 0 {
		respLimit = 10 * 1024 * 1024
	}
	_, _ = io.Copy(w, io.LimitReader(resp.Body, respLimit))
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

// dangerReason is the DNS-cached version of resolvedDangerReason. The
// EgressProxy uses this on the hot path so repeated outbound calls to the
// same host don't re-resolve.
func (ep *EgressProxy) dangerReason(ctx context.Context, host string) string {
	host = strings.Trim(host, "[]")
	if host == "" {
		return "empty destination host"
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return "internal hostname blocked"
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := classifyIP(ip); reason != "" {
			return reason
		}
		return ""
	}
	ips, err := ep.dnsCache.Lookup(ctx, host)
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

// resolvedDangerReason is preserved for legacy callers that don't have an
// EgressProxy instance. New code should prefer (*EgressProxy).dangerReason
// which reuses the DNS cache.
func resolvedDangerReason(host string) string {
	host = strings.Trim(host, "[]")
	if host == "" {
		return "empty destination host"
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return "internal hostname blocked"
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := classifyIP(ip); reason != "" {
			return reason
		}
		return ""
	}
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

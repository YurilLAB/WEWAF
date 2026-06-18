package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/core"
	"wewaf/internal/rules"
)

// Engine is the central WAF rule evaluator.
type Engine struct {
	mu      sync.RWMutex
	cfg     *config.Config
	ruleSet *rules.RuleSet
	logger  Logger
}

// Logger is a minimal logging interface.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// noopLogger discards all output.
type noopLogger struct{}

func (n *noopLogger) Debugf(format string, args ...interface{}) {}
func (n *noopLogger) Infof(format string, args ...interface{})  {}
func (n *noopLogger) Warnf(format string, args ...interface{})  {}
func (n *noopLogger) Errorf(format string, args ...interface{}) {}

// NewEngine creates an engine with the given configuration and rule set.
func NewEngine(cfg *config.Config, rs *rules.RuleSet, log Logger) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("engine: config is nil")
	}
	if rs == nil {
		return nil, fmt.Errorf("engine: rule set is nil")
	}
	if log == nil {
		log = &noopLogger{}
	}
	return &Engine{
		cfg:     cfg,
		ruleSet: rs,
		logger:  log,
	}, nil
}

// Reload swaps the rule set at runtime.
func (e *Engine) Reload(rs *rules.RuleSet) {
	if rs == nil {
		e.logger.Warnf("engine: Reload called with nil rule set; ignoring")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ruleSet = rs
}

var (
	headlessUARe = regexp.MustCompile(`(?i)(headlesschrome|phantomjs|selenium|webdriver|puppeteer|playwright|cypress)`)
	toolUARe     = regexp.MustCompile(`(?i)(scrapy|curl|wget|python-requests|java|libwww|httpclient|okhttp|axios)`)

	// crlfInjectionRe detects HTTP response-splitting / header-injection in the
	// RAW (still percent-encoded) request target: an encoded or literal CR/LF
	// — single, paired, or multiply-encoded (%0d, %0a, %250d, …) — followed by
	// an HTTP-header-like "token:". Requiring the trailing header token keeps
	// legitimate multi-line GET parameters (plain "%0a"-separated text) from
	// matching, while catching "%0d%0aSet-Cookie:", "%0d%0aLocation:", etc.
	crlfInjectionRe = regexp.MustCompile(`(?i)(?:%(?:25)*0[ad]|[\r\n])(?:%(?:25)*0[ad]|[\r\n])?(?:%(?:25)*20|\+|\s)*[a-z][a-z0-9-]{1,40}\s*(?:%(?:25)*3a|:)`)

	// nullByteRe detects a NUL byte in the RAW request target — encoded
	// (%00, %2500, …) or literal. The canonicalizer strips NUL before rules
	// run, hiding null-byte injection (CWE-158, e.g. "shell.php%00.jpg" to
	// truncate an extension check). A NUL in a URL has no legitimate use, so
	// flagging it cannot cause false positives.
	nullByteRe = regexp.MustCompile(`(?i)%(?:25)*00|\x00`)
)

// DetectBot analyzes the request for bot signatures.
func (e *Engine) DetectBot(tx *core.Transaction) (isBot bool, botName string, score int) {
	if tx == nil || tx.Request == nil {
		return false, "", 0
	}

	ua := tx.Request.UserAgent()

	// Check User-Agent for headless browser indicators.
	if m := headlessUARe.FindString(ua); m != "" {
		return true, m, 40
	}

	// Check for missing standard browser headers.
	if tx.Request.Header.Get("Accept-Language") == "" || tx.Request.Header.Get("Accept") == "" {
		return true, "MissingBrowserHeaders", 20
	}

	// Check for WebDriver traces in headers.
	for k, v := range tx.Request.Header {
		kv := strings.ToLower(k + ": " + strings.Join(v, ", "))
		if strings.Contains(kv, "selenium") || strings.Contains(kv, "webdriver") || strings.Contains(kv, "phantom") {
			return true, "WebDriverTrace", 30
		}
	}

	// Check for automated tool signatures.
	if m := toolUARe.FindString(ua); m != "" {
		return true, m, 30
	}

	return false, "", 0
}

// ProcessRequestHeaders evaluates rules against the incoming request line and headers.
func (e *Engine) ProcessRequestHeaders(tx *core.Transaction) *core.Interruption {
	if tx == nil || tx.Request == nil {
		return nil
	}
	targets := e.buildRequestHeaderTargets(tx.Request)

	// Bot fingerprinting with panic recovery.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				e.logger.Errorf("engine: panic during bot detection: %v", rec)
			}
		}()
		isBot, botName, score := e.DetectBot(tx)
		if isBot {
			tx.AddMatch(core.Match{
				RuleID:    "BOT-FINGERPRINT",
				RuleName:  "Bot Fingerprint Detected: " + botName,
				Phase:     core.PhaseRequestHeaders,
				Target:    "headers",
				Value:     botName,
				Score:     score,
				Action:    core.ActionLog,
				Message:   "Automated client detected",
				Timestamp: time.Now().UTC(),
			})
		}
	}()

	return e.evaluatePhase(tx, core.PhaseRequestHeaders, targets)
}

// ProcessRequestBody evaluates rules against the buffered request body.
// The caller must have already read and restored the body on the request.
func (e *Engine) ProcessRequestBody(tx *core.Transaction) *core.Interruption {
	if tx == nil {
		return nil
	}
	var body string
	if val, ok := tx.MetadataValue("body"); ok {
		if b, ok := val.([]byte); ok {
			body = string(b)
		}
	}
	if body == "" {
		b, err := e.readBodyString(tx.Request)
		if err != nil {
			e.logger.Warnf("engine: failed to read request body: %v", err)
			body = ""
		} else {
			body = b
		}
	}
	targets := map[string]string{
		"body": body,
	}

	// Whitespace / zero-width normalized body. The raw "body" target is kept
	// verbatim so structural rules that rely on exact bytes (e.g. the SMUG
	// chunked-smuggling rules that match literal "\r\n0\r\n") still fire. This
	// adds a parallel normalized view so injection rules also catch the
	// "UNION\vSELECT" / "U​NION" / NBSP-separator evasions that the raw
	// body would slip past (RE2 \s excludes \v, and the body is otherwise
	// matched un-normalized). Added only when normalization actually changed
	// something, so ordinary ASCII bodies cost nothing extra. Keyed under
	// "body.norm" so it is matched by the "body" target prefix.
	if norm := NormalizeForMatch(body); norm != body {
		targets["body.norm"] = norm
	}

	// Cookie inspection with the full body-phase rule set. Header-phase rules
	// only cover a subset of injection signatures (XSS-001/SQLI-001/RCE-001/…
	// declare a "headers" target but run in the BODY phase, so they never see
	// header values). Apps routinely read cookie values into SQL queries, HTML,
	// shell commands, or template engines, so a cookie is a first-class
	// injection sink. Expose it under "headers.cookie" (matched by the
	// "headers" target prefix) using NormalizeForMatch — NFKC + homoglyph +
	// whitespace folding, but NO URL-decode, since apps read the raw cookie
	// value rather than a percent-decoded one. Avoids the "+"→space mangling
	// that would otherwise false-positive base64 cookies on the crypto rule.
	if tx.Request != nil {
		if c := tx.Request.Header.Get("Cookie"); c != "" {
			// PathUnescape (not QueryUnescape) decodes %XX while leaving "+"
			// intact, so a percent-encoded payload in a cookie is caught
			// without "+"→space mangling that would false-positive base64 /
			// JWT cookies on the crypto rule. Fall back to raw on a malformed
			// escape (e.g. a literal "%").
			if dec, err := url.PathUnescape(c); err == nil {
				c = dec
			}
			targets["headers.cookie"] = NormalizeForMatch(c)
		}
	}

	// Decompressed body inspection. When DecompressInspect is enabled the
	// proxy decodes a gzip/brotli request body and stores the plaintext
	// under "decoded_body" *specifically so body rules can run against the
	// content the backend will actually process*. The raw "body" target is
	// the compressed bytes, which match no signature — so without inspecting
	// the decoded form here, any attack wrapped in Content-Encoding: gzip
	// bypasses every body rule. Keyed as "body.decoded" so existing rules
	// that target "body" match it via the evaluator's prefix rule, with no
	// rule changes required. Only added when it differs from the raw body so
	// a single match can't be scored twice.
	if val, ok := tx.MetadataValue("decoded_body"); ok {
		if b, ok := val.([]byte); ok && len(b) > 0 && string(b) != body {
			targets["body.decoded"] = string(b)
		}
	}

	// Form-urlencoded body decoding. Query-string args are URL-decoded and
	// homoglyph-folded before matching (see buildRequestHeaderTargets); the
	// raw body is not. So `comment=%3Cscript%3E...` in an
	// application/x-www-form-urlencoded POST reaches the backend decoded to
	// `<script>...` while the engine only ever saw the percent-encoded form —
	// a clean bypass of every body/args rule. Parse the body the same way the
	// backend will and expose each value under an "args.NAME" key so the
	// existing arg/body signatures fire. Bounded to maxFormFields so a body
	// packed with parameters can't blow up the target map.
	if e.isFormURLEncoded(tx.Request) && body != "" {
		const maxFormFields = 256
		if values, err := url.ParseQuery(body); err == nil {
			added := 0
			for k, vs := range values {
				if added >= maxFormFields {
					e.logger.Warnf("engine: form-field limit (%d) reached", maxFormFields)
					break
				}
				decoded := strings.Join(vs, ", ")
				targets["args."+k] = FoldHomoglyphs(Canonicalize(decoded))
				added++
			}
		}
	}

	// gRPC string-field inspection. The DPI layer extracts printable runs
	// from protobuf frames into "grpc_targets" so XSS/SQLi signatures get a
	// chance to fire on string fields that the framing bytes would otherwise
	// split apart. Each run is fed under a "body.grpc.N" key (matched by the
	// "body" prefix rule). Capped so a frame full of short runs can't blow up
	// the target map.
	if val, ok := tx.MetadataValue("grpc_targets"); ok {
		if runs, ok := val.([]string); ok {
			const maxGRPCTargets = 256
			for i, s := range runs {
				if i >= maxGRPCTargets {
					e.logger.Warnf("engine: gRPC target limit (%d) reached", maxGRPCTargets)
					break
				}
				if s == "" {
					continue
				}
				targets[fmt.Sprintf("body.grpc.%d", i)] = s
			}
		}
	}

	return e.evaluatePhase(tx, core.PhaseRequestBody, targets)
}

// ProcessResponseHeaders evaluates rules against the backend response headers.
func (e *Engine) ProcessResponseHeaders(tx *core.Transaction, status int, headers http.Header) *core.Interruption {
	if tx == nil {
		return nil
	}
	targets := map[string]string{
		"response_status":  fmt.Sprintf("%d", status),
		"response_headers": headersToString(headers, 64*1024),
	}
	return e.evaluatePhase(tx, core.PhaseResponseHeaders, targets)
}

// ProcessResponseBody evaluates rules against the backend response body (if buffered).
func (e *Engine) ProcessResponseBody(tx *core.Transaction, body []byte) *core.Interruption {
	if tx == nil {
		return nil
	}
	if e == nil || e.cfg == nil {
		return nil
	}
	if len(body) == 0 {
		return nil
	}
	var maxBody int64 = 1 << 20
	if e.cfg != nil && e.cfg.MaxBodyBytes > 0 {
		maxBody = e.cfg.MaxBodyBytes
	}
	if int64(len(body)) > maxBody {
		body = body[:int(maxBody)]
	}
	targets := map[string]string{
		"response_body": string(body),
	}
	return e.evaluatePhase(tx, core.PhaseResponseBody, targets)
}

// EvaluateEgress runs the rule set against an outbound (egress) request.
func (e *Engine) EvaluateEgress(tx *core.Transaction, targets map[string]string) *core.Interruption {
	if e == nil || tx == nil {
		return nil
	}
	return e.evaluatePhase(tx, core.PhaseEgressRequest, targets)
}

// LogError proxies an error to the engine logger.
func (e *Engine) LogError(format string, args ...interface{}) {
	e.logger.Errorf(format, args...)
}

// ProcessLogging finalises the transaction and writes audit data.
func (e *Engine) ProcessLogging(tx *core.Transaction) {
	if tx == nil {
		return
	}
	mode := e.cfg.ModeSnapshot()
	if mode == "learning" {
		e.logger.Infof("[LEARN] tx=%s score=%d matches=%d", tx.ID, tx.ScoreSnapshot(), tx.MatchCount())
	}
	if tx.IsBlocked() {
		e.logger.Warnf("[BLOCK] tx=%s ip=%s score=%d phase=%s", tx.ID, tx.ClientIP, tx.ScoreSnapshot(), tx.BlockedAt)
	} else if tx.ScoreSnapshot() > 0 {
		e.logger.Infof("[ALERT] tx=%s ip=%s score=%d", tx.ID, tx.ClientIP, tx.ScoreSnapshot())
	}
}

// evaluatePhase runs the rule set for a single phase and updates the transaction.
func (e *Engine) evaluatePhase(tx *core.Transaction, phase core.Phase, targets map[string]string) (intr *core.Interruption) {
	// Panic-to-failsafe: if anything inside this function panics (bad regex,
	// nil map, corrupt target) we return a block interruption when the
	// operator has chosen fail-closed. Previously the recover logged and
	// silently returned nil → the request forwarded unblocked even after a
	// mid-score panic. Fail-open deployments still get pass-through.
	defer func() {
		if rec := recover(); rec != nil {
			e.logger.Errorf("engine: panic during evaluation: %v", rec)
			mode := ""
			failsafe := "closed"
			if e.cfg != nil {
				snap := e.cfg.Snapshot()
				mode = snap.ModeSnapshot()
				if snap.FailsafeMode != "" {
					failsafe = snap.FailsafeMode
				}
			}
			if failsafe != "open" && mode != "detection" && mode != "learning" {
				tx.SetBlocked(phase)
				intr = &core.Interruption{
					Action:  core.ActionBlock,
					Status:  503,
					Message: "engine panic — failsafe block",
				}
			}
		}
	}()
	e.mu.RLock()
	rs := e.ruleSet
	cfgSnap := e.cfg.Snapshot()
	e.mu.RUnlock()

	const maxMatches = 1000
	preMatchCount := tx.MatchCount()

	// Isolate rs.Evaluate with its own panic recovery so a bad regex cannot crash the WAF.
	var matches []core.Match
	var hardBlock bool
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				e.logger.Errorf("engine: panic during rule evaluation: %v", rec)
			}
		}()
		matches, hardBlock = rs.EvaluateWithParanoia(phase, targets, cfgSnap.BlockThreshold, cfgSnap.ParanoiaLevel)
	}()

	for _, m := range matches {
		if tx.MatchCount()-preMatchCount >= maxMatches {
			e.logger.Warnf("engine: match limit (%d) reached for phase %s", maxMatches, phase)
			break
		}
		tx.AddMatch(m)
	}

	// Check special non-regex rules.
	specialMatches := e.evaluateSpecialRules(tx, phase, targets)
	for _, m := range specialMatches {
		if tx.MatchCount()-preMatchCount >= maxMatches {
			e.logger.Warnf("engine: match limit (%d) reached for phase %s", maxMatches, phase)
			break
		}
		tx.AddMatch(m)
		if m.Score >= cfgSnap.BlockThreshold || m.Action == core.ActionBlock || m.Action == core.ActionDrop {
			hardBlock = true
		}
	}

	score := tx.ScoreSnapshot()
	mode := cfgSnap.ModeSnapshot()

	if hardBlock || score >= cfgSnap.BlockThreshold {
		tx.SetBlocked(phase)
		if mode == "detection" || mode == "learning" {
			// In detection/learning mode we log but do not interrupt.
			e.logger.Warnf("[DETECT] tx=%s would block (score=%d mode=%s)", tx.ID, score, mode)
			return nil
		}
		// Propagate the most severe action from the triggering matches.
		action := core.ActionBlock
		for _, m := range tx.MatchesSnapshot() {
			if m.Action == core.ActionDrop {
				action = core.ActionDrop
				break
			}
		}
		return &core.Interruption{
			Action:  action,
			Status:  http.StatusForbidden,
			Message: "Request blocked by WEWaf",
			Matches: tx.MatchesSnapshot(),
		}
	}
	return nil
}

// evaluateSpecialRules handles logic that cannot be expressed cleanly with regex.
func (e *Engine) evaluateSpecialRules(tx *core.Transaction, phase core.Phase, targets map[string]string) []core.Match {
	const maxSpecialMatches = 50
	var matches []core.Match
	addMatch := func(m core.Match) {
		if len(matches) >= maxSpecialMatches {
			return
		}
		matches = append(matches, m)
	}

	switch phase {
	case core.PhaseRequestHeaders:
		if tx.Request == nil {
			return matches
		}

		// CRLF / HTTP response-splitting in the raw request target. The
		// canonicalizer URL-decodes "%0d%0a" and then normalises the resulting
		// CR/LF to spaces, so by the time the CRLF-001 regex sees a query arg
		// the evidence is gone. Inspect the RAW request-target (still
		// percent-encoded) instead. We only flag a CR/LF that is followed by a
		// header-like "token:" (the OWASP CRS 921160 approach) so a legitimate
		// multi-line value in a GET parameter does not false-positive.
		rawURI := tx.Request.RequestURI
		if rawURI == "" && tx.Request.URL != nil {
			rawURI = tx.Request.URL.RequestURI()
		}
		if crlfInjectionRe.MatchString(rawURI) {
			addMatch(core.Match{
				RuleID:    "CRLF-002",
				RuleName:  "CRLF Header Injection",
				Phase:     phase,
				Target:    "uri",
				Value:     trunc(rawURI, 64),
				Score:     80,
				Action:    core.ActionBlock,
				Message:   "CR/LF followed by header injection in request target",
				Timestamp: time.Now().UTC(),
			})
		}

		// NUL-byte injection in the raw request target (canonicalisation strips
		// it before the rule engine sees it).
		if nullByteRe.MatchString(rawURI) {
			addMatch(core.Match{
				RuleID:    "NULL-001",
				RuleName:  "Null Byte Injection",
				Phase:     phase,
				Target:    "uri",
				Value:     trunc(rawURI, 64),
				Score:     80,
				Action:    core.ActionBlock,
				Message:   "NUL byte in request target",
				Timestamp: time.Now().UTC(),
			})
		}

		// HTTP Smuggling: Transfer-Encoding + Content-Length
		te := tx.Request.Header.Get("Transfer-Encoding")
		cl := tx.Request.Header.Get("Content-Length")
		if te != "" && cl != "" {
			addMatch(core.Match{
				RuleID:    "SMUG-001",
				RuleName:  "HTTP Smuggling TE.CL",
				Phase:     phase,
				Target:    "headers",
				Value:     fmt.Sprintf("TE=%s CL=%s", trunc(te, 32), trunc(cl, 32)),
				Score:     80,
				Action:    core.ActionBlock,
				Message:   "Transfer-Encoding and Content-Length both present",
				Timestamp: time.Now().UTC(),
			})
		}

		// HTTP Smuggling: duplicate Content-Length values
		if clValues, ok := tx.Request.Header["Content-Length"]; ok && len(clValues) > 1 {
			addMatch(core.Match{
				RuleID:    "SMUG-002",
				RuleName:  "HTTP Smuggling Double CL",
				Phase:     phase,
				Target:    "headers",
				Value:     strings.Join(clValues, ", "),
				Score:     70,
				Action:    core.ActionBlock,
				Message:   "Duplicate Content-Length headers detected",
				Timestamp: time.Now().UTC(),
			})
		}

		// HTTP Smuggling: obfuscated Transfer-Encoding. Catches "chunked,
		// chunked", whitespace-padded variants, and unknown-encoding +
		// chunked combos that several smuggling PoCs use to coerce mismatched
		// parsing between intermediaries.
		if teValues, ok := tx.Request.Header["Transfer-Encoding"]; ok && HasObfuscatedTransferEncoding(teValues) {
			addMatch(core.Match{
				RuleID:    "SMUG-010",
				RuleName:  "HTTP Smuggling Obfuscated TE",
				Phase:     phase,
				Target:    "headers",
				Value:     strings.Join(teValues, ", "),
				Score:     85,
				Action:    core.ActionBlock,
				Message:   "Obfuscated Transfer-Encoding header",
				Timestamp: time.Now().UTC(),
			})
		}

		// HTTP/2 smuggling indicator: presence of both :method pseudo-style
		// hop-by-hop headers and Content-Length where the protocol is h2c.
		// In Go's net/http server, HTTP/2 requests surface through ProtoMajor.
		if tx.Request.ProtoMajor == 2 && tx.Request.Header.Get("Content-Length") != "" {
			if _, hasTE := tx.Request.Header["Transfer-Encoding"]; hasTE {
				addMatch(core.Match{
					RuleID:    "SMUG-011",
					RuleName:  "HTTP/2 CL+TE anomaly",
					Phase:     phase,
					Target:    "headers",
					Value:     "h2 with both TE and CL",
					Score:     80,
					Action:    core.ActionBlock,
					Message:   "HTTP/2 request with Content-Length and Transfer-Encoding",
					Timestamp: time.Now().UTC(),
				})
			}
		}

		// Empty / missing User-Agent
		ua := tx.Request.UserAgent()
		if ua == "" {
			addMatch(core.Match{
				RuleID:    "SCAN-002",
				RuleName:  "Empty User-Agent",
				Phase:     phase,
				Target:    "headers",
				Value:     "",
				Score:     20,
				Action:    core.ActionLog,
				Message:   "Missing or empty User-Agent header",
				Timestamp: time.Now().UTC(),
			})
		}

	case core.PhaseResponseBody:
		body := targets["response_body"]
		if body == "" {
			return matches
		}
		lowerBody := strings.ToLower(body)

		// AWS access key pattern
		if strings.Contains(body, "AKIA") {
			addMatch(core.Match{
				RuleID:    "LEAK-001",
				RuleName:  "Leaked AWS Access Key",
				Phase:     phase,
				Target:    "response_body",
				Value:     "AWS access key pattern detected",
				Score:     20,
				Action:    core.ActionLog,
				Message:   "Potential AWS access key leaked in response",
				Timestamp: time.Now().UTC(),
			})
		}

		// GitHub token pattern
		if strings.Contains(body, "ghp_") || strings.Contains(body, "gho_") {
			addMatch(core.Match{
				RuleID:    "LEAK-002",
				RuleName:  "Leaked GitHub Token",
				Phase:     phase,
				Target:    "response_body",
				Value:     "GitHub token pattern detected",
				Score:     20,
				Action:    core.ActionLog,
				Message:   "Potential GitHub token leaked in response",
				Timestamp: time.Now().UTC(),
			})
		}

		// Generic credential patterns
		if strings.Contains(lowerBody, "api_key=") || strings.Contains(lowerBody, "password=") || strings.Contains(lowerBody, "secret=") {
			addMatch(core.Match{
				RuleID:    "LEAK-003",
				RuleName:  "Leaked Credentials in Response",
				Phase:     phase,
				Target:    "response_body",
				Value:     "credential pattern detected",
				Score:     20,
				Action:    core.ActionLog,
				Message:   "Potential credentials leaked in response",
				Timestamp: time.Now().UTC(),
			})
		}
	}

	return matches
}

// buildRequestHeaderTargets extracts inspectable strings from an HTTP request.
// Individual values are capped at 8 KB and total entries at 100 to prevent DoS.
func (e *Engine) buildRequestHeaderTargets(r *http.Request) map[string]string {
	const maxValueLen = 8192
	const maxEntries = 100

	targets := make(map[string]string, 8)
	add := func(key, value string) bool {
		if len(targets) >= maxEntries {
			return false
		}
		if len(value) > maxValueLen {
			value = value[:maxValueLen]
		}
		targets[key] = value
		return true
	}

	if r == nil {
		return targets
	}

	// URI / path go through Canonicalize + FoldHomoglyphs so double-encoded,
	// unicode-confusable, and mixed-slash variants all collapse to one
	// representation before rules run. Homoglyph folding in particular
	// catches payloads that swap in Cyrillic or fullwidth lookalikes that
	// NFKC alone leaves intact.
	if uri, err := url.PathUnescape(r.URL.RequestURI()); err == nil {
		add("uri", FoldHomoglyphs(Canonicalize(uri)))
	} else {
		add("uri", FoldHomoglyphs(Canonicalize(r.URL.RequestURI())))
	}
	add("method", r.Method)
	add("path", FoldHomoglyphs(CanonicalizePath(r.URL.Path)))
	for k, v := range r.URL.Query() {
		raw := strings.Join(v, ", ")
		if decoded, err := url.QueryUnescape(raw); err == nil {
			if !add("args."+k, FoldHomoglyphs(Canonicalize(decoded))) {
				break
			}
		} else {
			if !add("args."+k, FoldHomoglyphs(Canonicalize(raw))) {
				break
			}
		}
	}
	for k, v := range r.Header {
		if !add("headers."+k, strings.Join(v, ", ")) {
			break
		}
	}
	return targets
}

// headersToString serialises headers for inspection, capped at maxBytes.
func headersToString(h http.Header, maxBytes int) string {
	var b strings.Builder
	for k, v := range h {
		line := k + ": " + strings.Join(v, ", ") + "\n"
		if b.Len()+len(line) > maxBytes {
			if b.Len() < maxBytes {
				remaining := maxBytes - b.Len()
				b.WriteString(line[:remaining])
			}
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

// readBodyString reads the request body (capped at cfg.MaxBodyBytes) and restores it so the proxy can forward it.
// It recovers from panics during body read.
func (e *Engine) readBodyString(r *http.Request) (string, error) {
	defer func() {
		if rec := recover(); rec != nil {
			e.logger.Errorf("engine: panic while reading body: %v", rec)
		}
	}()
	if r == nil || r.Body == nil {
		return "", nil
	}
	var maxBody int64 = 1 << 20
	if e.cfg != nil && e.cfg.MaxBodyBytes > 0 {
		maxBody = e.cfg.MaxBodyBytes
	}
	// If body supports Seek, reset to beginning first (allows re-reading).
	if seeker, ok := r.Body.(io.Seeker); ok {
		_, _ = seeker.Seek(0, io.SeekStart)
	}
	limited := io.LimitReader(r.Body, maxBody)
	body, err := io.ReadAll(limited)
	if err != nil {
		if errors.Is(err, http.ErrBodyReadAfterClose) {
			r.Body = io.NopCloser(bytes.NewReader(nil))
			r.ContentLength = 0
			return "", nil
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(nil))
		r.ContentLength = 0
		return "", err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return string(body), nil
}

// isFormURLEncoded reports whether the request body is
// application/x-www-form-urlencoded so it can be parsed into args targets.
func (e *Engine) isFormURLEncoded(r *http.Request) bool {
	if r == nil {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

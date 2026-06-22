package engine

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

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

	// jwtRe matches a JWT-shaped token. A JWT header is base64url of {"alg"...,
	// which always begins "eyJ", so the prefix is a reliable, low-FP marker.
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)
	// jwtAlgNoneRe matches an unsigned-token "alg":"none" (any case) in a
	// DECODED JWT header — the classic signature-bypass.
	jwtAlgNoneRe = regexp.MustCompile(`(?i)"alg"\s*:\s*"?\s*none\b`)
	// jwtKidRe extracts the "kid" (key id) header parameter value.
	jwtKidRe = regexp.MustCompile(`(?i)"kid"\s*:\s*"([^"]*)"`)
	// jwtDangerousKidRe flags a kid value carrying injection metacharacters or
	// traversal — the kid is used to look up a key and is a documented SQLi /
	// LFI / command-injection sink. Legitimate kids are plain identifiers
	// (alphanumerics, '-', '_', ':') and never contain these.
	jwtDangerousKidRe = regexp.MustCompile("[\"'<>;|$`\\\\]|\\.\\.|\\x00|(?i)\\b(?:union|select|sleep|or\\s+1=1|etc/passwd)\\b")
	// jwtJkuRe flags a client-presented jku/x5u (external key-set URL) header —
	// attacker-supplied key sources (CVE-2018-0114 class). Log-level: some
	// issuers legitimately use jku, so it is recorded rather than blocked.
	jwtJkuRe = regexp.MustCompile(`(?i)"(?:jku|x5u)"\s*:`)

	// nullByteRe detects a NUL byte in the RAW request target — encoded
	// (%00, %2500, …) or literal. The canonicalizer strips NUL before rules
	// run, hiding null-byte injection (CWE-158, e.g. "shell.php%00.jpg" to
	// truncate an extension check). A NUL in a URL has no legitimate use, so
	// flagging it cannot cause false positives.
	nullByteRe = regexp.MustCompile(`(?i)%(?:25)*00|\x00`)

	// openRedirectRe matches a redirect-param value pointing off-site: a
	// protocol-relative "//host" / "/\host" / "\/host" / "\\host", an absolute
	// "scheme://host", or a scheme with a single slash/backslash ("https:/",
	// "https:\"). Tested against the RAW (decoded-once) query value, because
	// the canonicalizer collapses "//evil.com" to "/evil.com" and hides it. A
	// single-slash relative path ("/dashboard") deliberately does NOT match.
	openRedirectRe = regexp.MustCompile(`(?i)^[\s\x00-\x20]*(?:(?:https?|ftp):?)?[\\/]{2}|^[\s\x00-\x20]*https?:[\\/]`)
)

// redirectParamNames are the query parameters commonly used for redirects; an
// off-site value in one of these is an open-redirect indicator.
var redirectParamNames = map[string]bool{
	"redirect": true, "redirect_uri": true, "redirect_url": true, "redirecturl": true,
	"redir": true, "url": true, "next": true, "return": true, "returnurl": true,
	"return_url": true, "returnto": true, "goto": true, "continue": true, "dest": true,
	"destination": true, "callback": true, "forward": true, "location": true, "rurl": true,
}

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
	// The injection signatures (XSS, SQLi, SSTI, NoSQL, prototype pollution,
	// …) are registered at PhaseRequestBody but declare "args"/"uri"/"headers"
	// targets alongside "body" — a reflected payload arrives in the query
	// string or a header value as often as in the body. buildRequestHeaderTargets
	// is the single producer of those request targets; we merge them with the
	// body so a body-phase rule inspects the whole request surface, not just
	// the body. Without this, args.* / headers.* were only ever populated in
	// the request-header phase, so a body-phase rule (e.g. the <script>-tag
	// signature) never saw the query string — GET /x?q=<script>… reached the
	// backend unmatched. The header phase still runs first for cheap early
	// blocks before the body is buffered; this closes the body-phase gap.
	targets := e.buildRequestHeaderTargets(tx.Request)
	targets["body"] = body

	// If the proxy decompressed a Content-Encoding'd request body, inspect the
	// decoded plaintext as well. The proxy stores the still-compressed bytes
	// under "body" and the inflated form under "decoded_body"; without folding
	// the latter into the body target, every gzip/deflate/br-encoded payload
	// bypasses all body-phase signatures (they only ever saw compressed bytes,
	// which never match) while the backend decompresses and processes the
	// attack normally. The compressed bytes are kept too — they are inert under
	// the signatures, so appending the decoded form is purely additive.
	if val, ok := tx.MetadataValue("decoded_body"); ok {
		if db, ok := val.([]byte); ok && len(db) > 0 {
			if targets["body"] == "" {
				targets["body"] = string(db)
			} else {
				targets["body"] += "\n" + string(db)
			}
		}
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

	// JSON-unescaped body view. A JSON payload that hides "<script>" /
	// "UNION SELECT" behind backslash-u escapes is literal text to the regex
	// rules but the app's JSON parser decodes it — a real bypass (confirmed by
	// fuzzing). Inspect the decoded form too, plus its normalized variant so a
	// decoded payload that also uses \v / unicode separators is caught. Added
	// only when decoding changed something, so non-escaped bodies cost nothing.
	if dec := decodeJSONEscapes(body); dec != body {
		targets["body.jsondecoded"] = dec
		if dn := NormalizeForMatch(dec); dn != dec {
			targets["body.jsonnorm"] = dn
		}
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

		// Request-header injection sinks. The injection signatures (XSS / SQLi /
		// RCE / …) run in the body phase, where the cookie was the only header
		// they saw. But apps routinely read other client-controlled headers into
		// the very same sinks: the User-Agent and Referer land in access logs and
		// admin dashboards (stored XSS) and analytics queries (SQLi); the
		// forwarding / real-IP headers are written verbatim into databases (SQLi)
		// and trusted for access decisions. Expose a curated allowlist of these
		// sink-carrying headers to the body-phase rule set under
		// "headers.<name>" (matched by the "headers" prefix) so the same
		// signatures that protect args / body / cookie cover them too. The list
		// is an allowlist — structured negotiation / auth headers (Accept*,
		// Content-*, Authorization, Sec-*) are intentionally excluded to stay
		// false-positive free — and uses the no-URL-decode NormalizeForMatch
		// treatment (NFKC + homoglyph + whitespace fold) so base64 tokens aren't
		// mangled into rule hits.
		const maxHeaderSinkLen = 8192
		for _, name := range injectionSinkHeaders {
			if vs := tx.Request.Header.Values(name); len(vs) > 0 {
				joined := strings.Join(vs, ", ")
				if joined == "" {
					continue
				}
				if len(joined) > maxHeaderSinkLen {
					joined = joined[:maxHeaderSinkLen]
				}
				targets["headers."+strings.ToLower(name)] = NormalizeForMatch(joined)
			}
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

	// Query-string args + request target into the BODY phase. The header phase
	// builds args.* / uri from the query string, but only the SUBSET of rules
	// marked PhaseRequestHeaders runs there — the bulk of the signature set
	// (XSS, XPath, SSI, deserialization, prototype pollution, Spring4Shell,
	// LDAP, JSON NoSQL, …) is PhaseRequestBody and so never saw the query
	// string. The result was a gaping hole: a reflected ?q=<script>alert(1)
	// </script> — the most common XSS vector — bypassed every XSS rule, and
	// likewise for the other body-only classes. Mirror the query args and the
	// URI into the body-phase target map so the FULL rule set inspects them,
	// decoded and homoglyph-folded exactly like the header phase. Query args
	// are merged into the existing "args.NAME" keys (so a name present in both
	// the query and a form body keeps both payloads); the URI is added only if
	// a form body did not already populate it. Bounded so a query packed with
	// params can't blow up the target map.
	if tx.Request != nil && tx.Request.URL != nil {
		const maxQueryFields = 256
		added := 0
		for k, vs := range tx.Request.URL.Query() {
			if added >= maxQueryFields {
				e.logger.Warnf("engine: query-field limit (%d) reached", maxQueryFields)
				break
			}
			raw := strings.Join(vs, ", ")
			decoded := raw
			if d, err := url.QueryUnescape(raw); err == nil {
				decoded = d
			}
			val := FoldHomoglyphs(Canonicalize(decoded))
			key := "args." + k
			if existing, ok := targets[key]; ok && existing != val {
				targets[key] = existing + ", " + val
			} else {
				targets[key] = val
			}
			added++
		}
		if _, ok := targets["uri"]; !ok {
			if uri, err := url.PathUnescape(tx.Request.URL.RequestURI()); err == nil {
				targets["uri"] = FoldHomoglyphs(Canonicalize(uri))
			} else {
				targets["uri"] = FoldHomoglyphs(Canonicalize(tx.Request.URL.RequestURI()))
			}
		}
	}

	// UTF-7 decoded body view. A payload like "+ADw-script+AD4-" is inert ASCII
	// to every signature rule, but a backend that honors charset=utf-7 decodes
	// it to "<script>" — the classic UTF-7 XSS smuggle (confirmed by fuzzing:
	// the bytes reach the app as live <script>/<img onerror> markup). Decode the
	// same content the backend will, but ONLY when the request explicitly
	// declares charset=utf-7. No modern legitimate client sends that charset, so
	// gating on the declaration keeps this zero-false-positive while still
	// covering the attacker who sets it hoping a charset-sniffing backend
	// decodes the body. Keyed "body.utf7" (matched by the "body" prefix) and
	// added only when decoding actually changes the bytes.
	if utf7Charset(tx.Request) {
		if dec := decodeUTF7(body); dec != body {
			targets["body.utf7"] = NormalizeForMatch(dec)
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

		// Open-redirect detection. REDIR-001/002 embed the param NAME in their
		// regex and run against per-arg VALUES, so they never fire on a query
		// param; and the canonicalizer collapses "//evil.com" to "/evil.com",
		// hiding the protocol-relative form. Inspect the RAW (decoded-once)
		// query values of redirect-style params instead. Log-level: legitimate
		// apps DO redirect off-site (OAuth, SSO, share links), so this is
		// visibility, not a block.
		if tx.Request.URL != nil {
			const maxRedirChecks = 32
			checked := 0
			for name, vals := range tx.Request.URL.Query() {
				if checked >= maxRedirChecks {
					break
				}
				if !redirectParamNames[strings.ToLower(name)] {
					continue
				}
				for _, v := range vals {
					checked++
					if openRedirectRe.MatchString(v) {
						addMatch(core.Match{
							RuleID:    "REDIR-003",
							RuleName:  "Open Redirect (off-site param value)",
							Phase:     phase,
							Target:    "args." + name,
							Value:     trunc(v, 64),
							Score:     40,
							Action:    core.ActionLog,
							Message:   "Redirect parameter points to an off-site/protocol-relative URL",
							Timestamp: time.Now().UTC(),
						})
						break
					}
				}
			}
		}

		// JWT header attacks. JWTs are base64url-encoded, so alg:none / kid
		// injection / jku abuse are invisible to the regular regex rules
		// (JWT-001 only sees a literal "alg":"none"). Decode the header and
		// inspect it. Scan the Authorization and Cookie headers plus query
		// args — the placements where a token is presented.
		for key, val := range targets {
			if !strings.Contains(val, "eyJ") {
				continue
			}
			lk := strings.ToLower(key)
			if lk == "headers.authorization" || lk == "headers.cookie" ||
				strings.HasPrefix(lk, "args.") || lk == "uri" {
				for _, m := range detectJWTAttacks(val) {
					addMatch(m)
				}
			}
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

	case core.PhaseRequestBody:
		// Raw Java serialization magic bytes (0xAC 0xED 0x00 0x05 = STREAM_MAGIC
		// + STREAM_VERSION). The DESER-001 / DESER-JAVA-001 rules only match the
		// base64 ("rO0AB") and hex-text ("aced0005") representations; an
		// endpoint that accepts raw serialized objects (custom binary APIs,
		// some RMI/JMX-over-HTTP bridges) receives the literal bytes, which
		// Go's UTF-8-oriented regexp cannot express. A body that STARTS with the
		// magic is unambiguous; embedded (e.g. multipart) we additionally
		// require the following TC_OBJECT/TC_BLOCKDATA type byte so a stray
		// 4-byte coincidence in a binary upload can't false-positive.
		if b, ok := targets["body"]; ok && b != "" {
			const javaMagic = "\xac\xed\x00\x05"
			hit := strings.HasPrefix(b, javaMagic) ||
				strings.Contains(b, javaMagic+"\x73") || // TC_OBJECT
				strings.Contains(b, javaMagic+"\x77") || // TC_BLOCKDATA
				strings.Contains(b, javaMagic+"\x7a") // TC_BLOCKDATALONG
			if hit {
				addMatch(core.Match{
					RuleID:    "DESER-JAVA-002",
					RuleName:  "Java Serialized Object (raw)",
					Phase:     phase,
					Target:    "body",
					Value:     "raw java serialization stream header",
					Score:     90,
					Action:    core.ActionBlock,
					Message:   "Raw Java serialized object stream (0xACED0005)",
					Timestamp: time.Now().UTC(),
				})
			}
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
	// Raw URI with percent-encoding intact. The encoding-detection rules
	// (CRLF injection, overlong-UTF-8 traversal, encoded path traversal) match
	// on the PRE-decode form — e.g. `%0d%0a` or `%c0%af`. Canonicalize()
	// deliberately decodes and strips exactly those bytes for the `uri`/`args`
	// targets, which would otherwise blind those signatures to a payload a
	// decoding backend still interprets. Keeping a raw copy lets both the
	// canonical injection rules and the raw encoding rules do their job.
	add("uri_raw", r.URL.RequestURI())
	add("method", r.Method)
	add("path", FoldHomoglyphs(CanonicalizePath(r.URL.Path)))
	// Parse the query LENIENTLY from the raw query string rather than via
	// r.URL.Query(): the stdlib parser silently DROPS any key=value pair whose
	// percent-escape is malformed (e.g. "?q=%zz%3cscript%3e"), so an attacker
	// could hide a payload behind a single bad escape and have the arg vanish
	// from inspection entirely, while a per-character-decoding backend still
	// decoded "<script>". Canonicalize() does the lenient %XX decode; we only
	// split on &/= here. Repeated keys are joined so no value is lost.
	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		argVals := make(map[string]string)
		argKeys := make([]string, 0, 8)
		for _, pair := range strings.Split(rawQuery, "&") {
			if pair == "" {
				continue
			}
			key, val, _ := strings.Cut(pair, "=")
			cv := FoldHomoglyphs(Canonicalize(val))
			if prev, ok := argVals[key]; ok {
				argVals[key] = prev + ", " + cv
			} else {
				argVals[key] = cv
				argKeys = append(argKeys, key)
			}
		}
		for _, key := range argKeys {
			if !add("args."+key, argVals[key]) {
				break
			}
		}
		// Inspect parameter NAMES too, not just values. A payload hidden in a
		// query-parameter name (e.g. ?<script>alert(1)>=1, or ?a' OR '1'='1=x)
		// is otherwise invisible to args-targeted signatures, which only ever
		// see the value — yet backends that read parameter names (PHP extract,
		// key-binding frameworks, log/echo sinks) treat the name as a sink. The
		// decoded, homoglyph-folded names are joined into one synthetic args
		// target so the existing XSS/SQLi/NoSQL rules (which target "args", and
		// therefore "args.*") evaluate them.
		if len(argKeys) > 0 {
			var names strings.Builder
			for _, key := range argKeys {
				names.WriteString(FoldHomoglyphs(Canonicalize(key)))
				names.WriteByte('\n')
			}
			add("args._names", names.String())
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

// detectJWTAttacks finds JWT-shaped tokens in s, base64url-decodes each
// header segment, and returns matches for attacks the encoded form hides from
// regular regex rules: alg:none signature bypass, kid header injection
// (SQLi/LFI/command), and a client-presented jku/x5u external key source. It
// is bounded (maxJWTs) so a body packed with eyJ-prefixed strings can't blow
// up cost, and never panics on malformed base64.
func detectJWTAttacks(s string) []core.Match {
	const maxJWTs = 8
	if !strings.Contains(s, "eyJ") {
		return nil
	}
	var matches []core.Match
	found := jwtRe.FindAllString(s, maxJWTs)
	for _, tok := range found {
		seg := tok
		if i := strings.IndexByte(seg, '.'); i >= 0 {
			seg = seg[:i]
		}
		hdrBytes, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			// Tolerate accidental padding.
			if hb, err2 := base64.StdEncoding.DecodeString(seg); err2 == nil {
				hdrBytes = hb
			} else {
				continue
			}
		}
		hdr := string(hdrBytes)
		if !strings.Contains(hdr, "alg") && !strings.Contains(hdr, "kid") && !strings.Contains(hdr, "jku") && !strings.Contains(hdr, "x5u") {
			continue // decoded to something that isn't a JWT header
		}
		if jwtAlgNoneRe.MatchString(hdr) {
			matches = append(matches, core.Match{
				RuleID: "JWT-002", RuleName: "JWT alg:none signature bypass", Phase: core.PhaseRequestHeaders,
				Target: "jwt.header", Value: trunc(hdr, 64), Score: 90, Action: core.ActionBlock,
				Message: "JWT header declares alg:none (unsigned token)", Timestamp: time.Now().UTC(),
			})
		}
		if m := jwtKidRe.FindStringSubmatch(hdr); m != nil && jwtDangerousKidRe.MatchString(m[1]) {
			matches = append(matches, core.Match{
				RuleID: "JWT-003", RuleName: "JWT kid header injection", Phase: core.PhaseRequestHeaders,
				Target: "jwt.header", Value: trunc(m[1], 64), Score: 90, Action: core.ActionBlock,
				Message: "JWT kid parameter contains injection metacharacters", Timestamp: time.Now().UTC(),
			})
		}
		if jwtJkuRe.MatchString(hdr) {
			matches = append(matches, core.Match{
				RuleID: "JWT-004", RuleName: "JWT external key source", Phase: core.PhaseRequestHeaders,
				Target: "jwt.header", Value: trunc(hdr, 64), Score: 50, Action: core.ActionLog,
				Message: "JWT header references an external key set (jku/x5u)", Timestamp: time.Now().UTC(),
			})
		}
	}
	return matches
}

// decodeJSONEscapes reveals JSON string escape sequences so signature rules
// see the content the backend's JSON parser will produce. A JSON value that
// uses backslash-u escapes for "<", ">", or a letter inside a keyword reads as
// literal text to a regex but decodes to "<script>" / "UNION SELECT" once the
// app parses the JSON — a real WAF-bypass class. The decoder correctly handles
// an escaped backslash so a doubly-escaped sequence is not mis-decoded. Non-JSON
// input is returned essentially unchanged (the result is only ever used as an
// ADDITIONAL match target; the verbatim body is preserved).
func decodeJSONEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch s[i+1] {
		case 'u':
			if i+6 <= len(s) {
				if r, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += 5
					continue
				}
			}
			b.WriteByte(c)
		case '/':
			b.WriteByte('/')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case '"':
			b.WriteByte('"')
			i++
		case '\\':
			// Escaped backslash: emit one '\' and consume BOTH, so a literal
			// "\\u003c" is left as "<" (not decoded to "<").
			b.WriteByte('\\')
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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

// injectionSinkHeaders is the curated set of client-controlled request headers
// that commonly reach injection sinks — access logs, admin dashboards,
// analytics SQL, and IP allowlists. They are inspected by the body-phase
// signature rules in addition to the cookie. Structured negotiation / auth /
// fetch-metadata headers are deliberately omitted to avoid false positives,
// since they carry tokens and q-value lists that no app feeds to an injection
// sink.
var injectionSinkHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Real-IP",
	"X-Client-IP",
	"X-Originating-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"Forwarded",
	"Via",
	"From",
	"X-Requested-With",
}

// utf7Charset reports whether the request explicitly declares a UTF-7 body
// charset. UTF-7 is honored by essentially no modern client, so gating the
// decode-and-inspect pass on this declaration keeps it zero-false-positive:
// ordinary traffic never enters the path.
func utf7Charset(r *http.Request) bool {
	if r == nil {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	// Tolerate "charset=utf-7", quoted, and the non-hyphenated "utf7" spelling.
	return strings.Contains(ct, "charset=utf-7") ||
		strings.Contains(ct, "charset=\"utf-7\"") ||
		strings.Contains(ct, "charset=utf7")
}

// decodeUTF7 decodes RFC 2152 modified-UTF-7 into UTF-8. A '+' opens a
// modified-base64 run encoding UTF-16BE code units, closed by '-' (or any
// non-base64 byte); "+-" is a literal '+'. Anything that isn't a valid
// sequence is passed through, so the result is always usable as a matching
// target. Used only when the body explicitly declares charset=utf-7.
func decodeUTF7(s string) string {
	rev := func(c byte) int {
		switch {
		case c >= 'A' && c <= 'Z':
			return int(c - 'A')
		case c >= 'a' && c <= 'z':
			return int(c-'a') + 26
		case c >= '0' && c <= '9':
			return int(c-'0') + 52
		case c == '+':
			return 62
		case c == '/':
			return 63
		}
		return -1
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '+' {
			out.WriteByte(c)
			i++
			continue
		}
		i++ // consume '+'
		if i < len(s) && s[i] == '-' {
			out.WriteByte('+') // "+-" => literal '+'
			i++
			continue
		}
		var bits uint32
		var nbits int
		var units []uint16
		for i < len(s) {
			v := rev(s[i])
			if v < 0 {
				break
			}
			bits = bits<<6 | uint32(v)
			nbits += 6
			i++
			if nbits >= 16 {
				nbits -= 16
				units = append(units, uint16(bits>>uint(nbits)))
			}
		}
		out.WriteString(string(utf16.Decode(units)))
		if i < len(s) && s[i] == '-' {
			i++ // consume explicit terminator
		}
	}
	return out.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

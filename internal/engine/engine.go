package engine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
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

// ProcessRequestHeaders evaluates rules against the incoming request line and headers.
func (e *Engine) ProcessRequestHeaders(tx *core.Transaction) *core.Interruption {
	targets := e.buildRequestHeaderTargets(tx.Request)
	return e.evaluatePhase(tx, core.PhaseRequestHeaders, targets)
}

// ProcessRequestBody evaluates rules against the buffered request body.
// The caller must have already read and restored the body on the request.
func (e *Engine) ProcessRequestBody(tx *core.Transaction) *core.Interruption {
	var body string
	if val, ok := tx.MetadataValue("body"); ok {
		if b, ok := val.([]byte); ok {
			body = string(b)
		}
	}
	if body == "" {
		body = readBodyString(tx.Request)
	}
	targets := map[string]string{
		"body": body,
	}
	return e.evaluatePhase(tx, core.PhaseRequestBody, targets)
}

// ProcessResponseHeaders evaluates rules against the backend response headers.
func (e *Engine) ProcessResponseHeaders(tx *core.Transaction, status int, headers http.Header) *core.Interruption {
	targets := map[string]string{
		"response_status":  fmt.Sprintf("%d", status),
		"response_headers": headersToString(headers),
	}
	return e.evaluatePhase(tx, core.PhaseResponseHeaders, targets)
}

// ProcessResponseBody evaluates rules against the backend response body (if buffered).
func (e *Engine) ProcessResponseBody(tx *core.Transaction, body []byte) *core.Interruption {
	targets := map[string]string{
		"response_body": string(body),
	}
	return e.evaluatePhase(tx, core.PhaseResponseBody, targets)
}

// LogError proxies an error to the engine logger.
func (e *Engine) LogError(format string, args ...interface{}) {
	e.logger.Errorf(format, args...)
}

// ProcessLogging finalises the transaction and writes audit data.
func (e *Engine) ProcessLogging(tx *core.Transaction) {
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
func (e *Engine) evaluatePhase(tx *core.Transaction, phase core.Phase, targets map[string]string) *core.Interruption {
	e.mu.RLock()
	rs := e.ruleSet
	cfgSnap := e.cfg.Snapshot()
	e.mu.RUnlock()

	matches, hardBlock := rs.Evaluate(phase, targets, cfgSnap.BlockThreshold)
	for _, m := range matches {
		tx.AddMatch(m)
	}

	// Check special non-regex rules.
	specialMatches := e.evaluateSpecialRules(tx, phase, targets)
	for _, m := range specialMatches {
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
	var matches []core.Match
	if phase != core.PhaseRequestHeaders {
		return matches
	}

	// HTTP Smuggling: Transfer-Encoding + Content-Length
	te := tx.Request.Header.Get("Transfer-Encoding")
	cl := tx.Request.Header.Get("Content-Length")
	if te != "" && cl != "" {
		matches = append(matches, core.Match{
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
		matches = append(matches, core.Match{
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

	// Empty / missing User-Agent
	ua := tx.Request.UserAgent()
	if ua == "" {
		matches = append(matches, core.Match{
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

	return matches
}

// buildRequestHeaderTargets extracts inspectable strings from an HTTP request.
func (e *Engine) buildRequestHeaderTargets(r *http.Request) map[string]string {
	targets := make(map[string]string, 8)
	targets["uri"] = r.URL.RequestURI()
	targets["method"] = r.Method
	targets["path"] = r.URL.Path
	for k, v := range r.URL.Query() {
		targets["args."+k] = strings.Join(v, ", ")
	}
	for k, v := range r.Header {
		targets["headers."+k] = strings.Join(v, ", ")
	}
	return targets
}

// headersToString serialises headers for inspection.
func headersToString(h http.Header) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v, ", "))
		b.WriteString("\n")
	}
	return b.String()
}

// readBodyString reads the request body (capped at 1 MiB) and restores it so the proxy can forward it.
func readBodyString(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	const maxBody = 1 << 20 // 1 MiB hard cap for engine inspection
	// If body supports Seek, reset to beginning first (allows re-reading).
	if seeker, ok := r.Body.(io.Seeker); ok {
		_, _ = seeker.Seek(0, io.SeekStart)
	}
	limited := io.LimitReader(r.Body, maxBody)
	body, err := io.ReadAll(limited)
	if err != nil {
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(nil))
		r.ContentLength = 0
		return ""
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return string(body)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

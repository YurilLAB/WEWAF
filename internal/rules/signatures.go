package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"wewaf/internal/core"
)

// CompiledRule holds a regex-backed rule ready for evaluation.
type CompiledRule struct {
	core.Rule
	Re *regexp.Regexp
}

// RuleSet is a thread-safe collection of compiled rules.
type RuleSet struct {
	mu    sync.RWMutex
	rules []CompiledRule
}

// NewRuleSet builds a RuleSet from raw rules. Returns error if any pattern fails to compile.
func NewRuleSet(raw []core.Rule) (*RuleSet, error) {
	rs := &RuleSet{rules: make([]CompiledRule, 0, len(raw))}
	for _, r := range raw {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rules: compile pattern for rule %q: %w", r.ID, err)
		}
		rs.rules = append(rs.rules, CompiledRule{Rule: r, Re: re})
	}
	return rs, nil
}

// DefaultRules returns the built-in high-value signatures.
func DefaultRules() []core.Rule {
	return []core.Rule{
		// === XSS — immediate blocks ===
		{ID: "XSS-001", Name: "XSS Script Tag", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "HTML script tag detected", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<script[^>]*>.*?</script>`},
		{ID: "XSS-002", Name: "XSS JavaScript Protocol", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "javascript: protocol in URL/header", Targets: []string{"args", "headers"}, Pattern: `(?i)javascript\s*:`},
		{ID: "XSS-003", Name: "XSS Event Handler + Sink", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "DOM event handler with sink", Targets: []string{"args", "body"}, Pattern: `(?i)on\w+\s*=([^>]*>|\s*["'])(.*?(alert|confirm|prompt|eval)\s*\()`},
		{ID: "XSS-004", Name: "XSS Template Injection", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Possible template injection", Targets: []string{"args", "body"}, Pattern: `(?i)\{\{.*?\}\}`},

		// === SQL Injection — immediate / high score ===
		{ID: "SQLI-001", Name: "SQLi Union Select", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "UNION SELECT pattern", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)union\s+(all\s+)?select`},
		{ID: "SQLI-002", Name: "SQLi Stacked Destructive", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Stacked destructive query", Targets: []string{"args", "body"}, Pattern: `(?i);\s*(drop|delete|truncate|insert|update)\s`},
		{ID: "SQLI-003", Name: "SQLi Tautology + Comment", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Tautology with comment sequence", Targets: []string{"args", "body"}, Pattern: `(?i)'\s*or\s+'[^']*'\s*=\s*'[^']*'\s*(--|#|/\*.*\*/)`},
		{ID: "SQLI-004", Name: "SQLi Time-based Function", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Time-based SQLi function", Targets: []string{"args", "body"}, Pattern: `(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)`},

		// === Command Injection / RCE ===
		{ID: "RCE-001", Name: "RCE Command Substitution", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Command substitution $() or backticks", Targets: []string{"args", "body", "headers"}, Pattern: "(?i)(\\$\\([^)]+\\)|`[^`]+`)"},
		{ID: "RCE-002", Name: "RCE Reverse Shell", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Reverse shell indicator", Targets: []string{"args", "body"}, Pattern: `(?i)(bash\s+-i|nc\s+-[ev]|python\s+-c\s*['"]import socket)`},
		{ID: "RCE-003", Name: "RCE Dangerous Chain", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Shell meta-char followed by binary", Targets: []string{"args", "body"}, Pattern: `(?i)[;&|]\s*(curl|wget|python|perl|ruby|bash|sh|cmd|powershell)\s+`},
		{ID: "RCE-004", Name: "RCE IFS Evasion", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionLog, Description: "IFS evasion pattern", Targets: []string{"args", "body"}, Pattern: `(?i)\$\{IFS\}`},

		// === Path Traversal / LFI / RFI ===
		{ID: "TRAV-001", Name: "Traversal Null Byte", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Null byte in path", Targets: []string{"args", "uri"}, Pattern: `\x00`},
		{ID: "TRAV-002", Name: "Traversal Dot-Dot-Slash", Phase: core.PhaseRequestHeaders, Score: 75, Action: core.ActionBlock, Description: "Directory traversal sequence", Targets: []string{"args", "uri"}, Pattern: `(?i)(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)`},
		{ID: "TRAV-003", Name: "Traversal PHP Wrapper", Phase: core.PhaseRequestBody, Score: 75, Action: core.ActionBlock, Description: "PHP/file wrapper in parameter", Targets: []string{"args", "body"}, Pattern: `(?i)(file|php|expect|data|input|zip|compress)://`},
		{ID: "TRAV-004", Name: "Traversal Sensitive File", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Sensitive system file requested", Targets: []string{"args", "uri"}, Pattern: `(?i)(/etc/passwd|boot\.ini|win\.ini|web\.config|\.htaccess|\.env|\.git/)`},

		// === SSRF / Protocol Attacks ===
		{ID: "SSRF-001", Name: "SSRF Cloud Metadata", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Cloud metadata endpoint", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)169\.254\.169\.254`},
		{ID: "SSRF-002", Name: "SSRF Private IP", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Private IP in URL parameter", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`},
		{ID: "SMUG-001", Name: "HTTP Smuggling TE.CL", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Transfer-Encoding + Content-Length conflict", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // handled by special logic, not regex
		{ID: "SMUG-002", Name: "HTTP Smuggling Double CL", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "Duplicate Content-Length headers", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // handled by special logic

		// === Scanner / Bot UA ===
		{ID: "SCAN-001", Name: "Known Scanner UA", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Known malicious scanner User-Agent", Targets: []string{"headers"}, Pattern: `(?i)(sqlmap|nikto|nmap|gobuster|dirbuster|wfuzz|burpsuite|burp|masscan|zgrab|commix)`},
		{ID: "SCAN-002", Name: "Empty User-Agent", Phase: core.PhaseRequestHeaders, Score: 20, Action: core.ActionLog, Description: "Missing or empty User-Agent", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // special logic
	}
}

// Count returns the number of compiled rules.
func (rs *RuleSet) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.rules)
}

// RulesSnapshot returns a copy of the current rule slice.
func (rs *RuleSet) RulesSnapshot() []CompiledRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]CompiledRule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Evaluate runs all rules for the given phase against the provided targets.
// It returns matches and whether an immediate block/drop was triggered.
func (rs *RuleSet) Evaluate(phase core.Phase, targets map[string]string, maxScore int) (matches []core.Match, interrupted bool) {
	rs.mu.RLock()
	rules := make([]CompiledRule, len(rs.rules))
	copy(rules, rs.rules)
	rs.mu.RUnlock()

	for _, cr := range rules {
		if cr.Phase != phase {
			continue
		}
		for tKey, tVal := range targets {
			if !targetMatches(cr.Targets, tKey) {
				continue
			}
			if cr.ID == "SMUG-001" || cr.ID == "SMUG-002" || cr.ID == "SCAN-002" {
				// These are handled by special logic in the engine, skip regex here.
				continue
			}
			if cr.Re.MatchString(tVal) {
				m := core.Match{
					RuleID:    cr.ID,
					RuleName:  cr.Name,
					Phase:     phase,
					Target:    tKey,
					Value:     truncate(tVal, 128),
					Score:     cr.Score,
					Action:    cr.Action,
					Message:   cr.Description,
					Timestamp: time.Now().UTC(),
				}
				matches = append(matches, m)
				if cr.Action == core.ActionBlock || cr.Action == core.ActionDrop {
					interrupted = true
				}
			}
		}
	}
	return matches, interrupted
}

// targetMatches checks whether a target key belongs to the rule's target list.
func targetMatches(targets []string, key string) bool {
	for _, t := range targets {
		if strings.EqualFold(t, key) {
			return true
		}
		// Allow "args" to match "args.foo" etc.
		if t != "" && strings.HasPrefix(strings.ToLower(key), strings.ToLower(t)+".") {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

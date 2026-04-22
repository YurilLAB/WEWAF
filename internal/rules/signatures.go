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
		{ID: "XSS-001", Name: "XSS Script Tag", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "HTML script tag detected", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<script\b[^>]*>[\s\S]{0,1000}</script>`},
		{ID: "XSS-002", Name: "XSS JavaScript Protocol", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "javascript: protocol in URL/header", Targets: []string{"args", "headers"}, Pattern: `(?i)javascript\s*:`},
		{ID: "XSS-003", Name: "XSS Event Handler + Sink", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "DOM event handler with sink", Targets: []string{"args", "body"}, Pattern: `(?i)\bon\w+\s*=\s*["']?[^"'>]{0,200}\b(alert|confirm|prompt|eval)\s*\(`},
		{ID: "XSS-004", Name: "XSS Template Injection", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Possible template injection", Targets: []string{"args", "body"}, Pattern: `(?i)\{\{.*?\}\}`},
		{ID: "XSS-005", Name: "XSS IMG Onerror", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "IMG tag with onerror handler", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<img\b[^>]*\bonerror\s*=`},
		{ID: "XSS-006", Name: "XSS SVG Onload", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "SVG tag with onload handler", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<svg\b[^>]*\bonload\s*=`},
		{ID: "XSS-007", Name: "XSS Iframe JavaScript", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Iframe with javascript: src", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<iframe\b[^>]*\bsrc\s*=\s*["']?\s*javascript:`},
		{ID: "XSS-008", Name: "XSS Data Text HTML", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "data:text/html payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)data:text/html`},
		{ID: "XSS-009", Name: "XSS CSS Expression", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "IE CSS expression payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)expression\s*\(`},
		{ID: "XSS-010", Name: "XSS CSS Behaviour", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "IE CSS behaviour payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)behaviour\s*:\s*#`},
		{ID: "XSS-011", Name: "XSS MHTML Protocol", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "MHTML protocol payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)mhtml:`},

		// === SQL Injection — immediate / high score ===
		{ID: "SQLI-001", Name: "SQLi Union Select", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "UNION SELECT pattern", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)union\s+(all\s+)?select`},
		{ID: "SQLI-002", Name: "SQLi Stacked Destructive", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Stacked destructive query", Targets: []string{"args", "body"}, Pattern: `(?i);\s*(drop|delete|truncate|insert|update)\s`},
		{ID: "SQLI-003", Name: "SQLi Tautology + Comment", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Tautology with comment sequence", Targets: []string{"args", "body"}, Pattern: `(?i)'\s*or\s+'[^']*'\s*=\s*'[^']*'\s*(--|#|/\*.*\*/)`},
		{ID: "SQLI-004", Name: "SQLi Time-based Function", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Time-based SQLi function", Targets: []string{"args", "body"}, Pattern: `(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)`},
		{ID: "SQLI-005", Name: "SQLi Blind Boolean", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Blind boolean tautology", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(\band\b\s*\(?\s*1\s*=\s*1|\bor\b\s*\(?\s*1\s*=\s*1|\band\b\s*\(?\s*2\s*>\s*1|\bor\b\s*\(?\s*2\s*>\s*1)`},
		{ID: "SQLI-006", Name: "SQLi Error Based", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Error-based SQLi information extraction", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(convert\s*\(\s*int\s*,\s*@@version|@@datadir|@@version|@@hostname|db_name\s*\()`},
		{ID: "SQLI-007", Name: "SQLi Hex Encoding", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Hex encoded SQLi payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)\b0x[0-9a-f]{4,}\b`},
		{ID: "SQLI-008", Name: "SQLi CHAR Concatenation", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "CHAR concatenation SQLi payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)char\s*\(\s*\d{1,3}\s*(,\s*\d{1,3}\s*)*\)`},
		{ID: "SQLI-009", Name: "SQLi Inline Comment", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "MySQL inline comment obfuscation", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)/\*!\d{5}`},

		// === NoSQL Injection ===
		{ID: "NOSQL-001", Name: "NoSQL MongoDB Operators", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "MongoDB operator in payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)["']?\s*\$(where|ne|gt|regex|func|eq|lt|exists)\s*["']?`},
		{ID: "NOSQL-002", Name: "NoSQL JSON Operators", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "NoSQL JSON-like operator payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)["']?\$(eq|gt|lt|ne|in|nin|exists|regex)\s*["']?\s*:`},

		// === XXE / XML ===
		{ID: "XXE-001", Name: "XXE DOCTYPE", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "XML DOCTYPE declaration", Targets: []string{"body"}, Pattern: `(?i)<!DOCTYPE\s`},
		{ID: "XXE-002", Name: "XXE ENTITY", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "XML ENTITY declaration", Targets: []string{"body"}, Pattern: `(?i)<!ENTITY\s`},
		{ID: "XXE-003", Name: "XXE External Entity", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "External entity SYSTEM/PUBLIC reference", Targets: []string{"body"}, Pattern: `(?i)\b(SYSTEM|PUBLIC)\s+["']`},

		// === LDAP Injection ===
		{ID: "LDAP-001", Name: "LDAP Meta Characters", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "LDAP special characters in query", Targets: []string{"args", "body"}, Pattern: `(?i)[\*\|&!\x00]`},

		// === CRLF Injection ===
		{ID: "CRLF-001", Name: "CRLF Injection", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "CRLF line injection sequence", Targets: []string{"args", "headers", "uri"}, Pattern: `(?i)(%0[dD]%0[aA]|%0[aA]%0[dD]|\r\n)`},

		// === Prototype Pollution ===
		{ID: "PROTO-001", Name: "Prototype Pollution", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Prototype pollution payload", Targets: []string{"args", "body"}, Pattern: `(?i)(__proto__|constructor\.prototype|constructor\[prototype\])`},

		// === JNDI / Log4j ===
		{ID: "JNDI-001", Name: "JNDI Lookup", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "JNDI lookup payload", Targets: []string{"args", "headers", "body"}, Pattern: `(?i)\$\{jndi:`},
		{ID: "JNDI-002", Name: "JNDI Nested Lookup", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Nested JNDI lookup payload", Targets: []string{"args", "headers", "body"}, Pattern: `(?i)\$\{(lower|env|sys):`},

		// === File Upload Threats ===
		{ID: "UPLOAD-001", Name: "Upload Double Extension", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Double extension in upload filename", Targets: []string{"body", "headers"}, Pattern: `(?i)filename\s*=\s*["']?[^"']*\.(php|jsp|asp|aspx|sh|py|rb)\.(jpg|jpeg|png|gif|txt|pdf|zip|doc|docx)`},
		{ID: "UPLOAD-002", Name: "Upload Null Byte", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Null byte in upload filename", Targets: []string{"body", "headers"}, Pattern: `(?i)filename\s*=\s*["']?[^"']*%00`},
		{ID: "UPLOAD-003", Name: "Upload Dangerous Extension", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Dangerous file extension in upload", Targets: []string{"body", "headers"}, Pattern: `(?i)filename\s*=\s*["']?[^"']*\.(php[345]?|phtml|jsp|asp|aspx|ashx|sh|py|rb|pl|cgi)\b`},
		{ID: "UPLOAD-004", Name: "Upload Executable MIME", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Executable MIME type in upload", Targets: []string{"body", "headers"}, Pattern: `(?i)Content-Type\s*:\s*[^;\r\n]*(application/x-php|application/x-httpd-php|application/x-sh|application/x-python|application/x-ruby|application/x-perl)`},

		// === Open Redirect ===
		{ID: "REDIR-001", Name: "Open Redirect Protocol Relative", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Open redirect with protocol-relative URL", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(redirect|url|next|return|goto|continue|destination)\s*=\s*(//|/\\)[^&\s]*`},
		{ID: "REDIR-002", Name: "Open Redirect External URL", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Open redirect to external URL", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(redirect|url|next|return|goto|continue|destination)\s*=\s*https?://[^&\s]*`},

		// === SSRF / Protocol Attacks ===
		{ID: "SSRF-001", Name: "SSRF Cloud Metadata", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Cloud metadata endpoint", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)169\.254\.169\.254`},
		{ID: "SSRF-002", Name: "SSRF Private IP", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Private IP in URL parameter", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`},
		{ID: "SSRF-003", Name: "SSRF Dangerous Protocol", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Dangerous protocol in request", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(dict|gopher|ftp|tftp|ldap)://`},
		{ID: "SSRF-004", Name: "SSRF File Protocol", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "File protocol in request", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)file://`},
		{ID: "SSRF-005", Name: "SSRF IP Bypass", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "SSRF IP address bypass", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)http://(0[./]|0177\.|0x7f)`},

		// === HTTP Smuggling ===
		{ID: "SMUG-001", Name: "HTTP Smuggling TE.CL", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Transfer-Encoding + Content-Length conflict", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // handled by special logic, not regex
		{ID: "SMUG-002", Name: "HTTP Smuggling Double CL", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "Duplicate Content-Length headers", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // handled by special logic

		// === Scanner / Bot UA ===
		{ID: "SCAN-001", Name: "Known Scanner UA", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Known malicious scanner User-Agent", Targets: []string{"headers"}, Pattern: `(?i)(sqlmap|nikto|nmap|gobuster|dirbuster|wfuzz|burpsuite|burp|masscan|zgrab|commix)`},
		{ID: "SCAN-002", Name: "Empty User-Agent", Phase: core.PhaseRequestHeaders, Score: 20, Action: core.ActionLog, Description: "Missing or empty User-Agent", Targets: []string{"headers"}, Pattern: `(?i)\A\z`}, // special logic
		{ID: "SCAN-003", Name: "Extended Scanner UA", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Extended scanner User-Agent list", Targets: []string{"headers"}, Pattern: `(?i)(acunetix|netsparker|w3af|arachni|wpscan|openvas|skipfish|nessus|appscan|whatweb|wappalyzer)`},

		// === Command Injection / RCE ===
		{ID: "RCE-001", Name: "RCE Command Substitution", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Command substitution $() or backticks", Targets: []string{"args", "body", "headers"}, Pattern: "(?i)(\\$\\([^)]+\\)|`[^`]+`)"},
		{ID: "RCE-002", Name: "RCE Reverse Shell", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Reverse shell indicator", Targets: []string{"args", "body"}, Pattern: `(?i)(bash\s+-i|nc\s+-[ev]|python\s+-c\s*['"]import socket)`},
		{ID: "RCE-003", Name: "RCE Dangerous Chain", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Shell meta-char followed by binary", Targets: []string{"args", "body"}, Pattern: `(?i)[;&|]\s*(curl|wget|python|perl|ruby|bash|sh|cmd|powershell)\s+`},
		{ID: "RCE-004", Name: "RCE IFS Evasion", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionLog, Description: "IFS evasion pattern", Targets: []string{"args", "body"}, Pattern: `(?i)\$\{IFS\}`},
		{ID: "RCE-005", Name: "RCE Scripting One-Liners", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Scripting language one-liner execution", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(base64\s+-d|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)`},
		{ID: "RCE-006", Name: "RCE Dangerous Functions", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Dangerous PHP/function execution", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(eval\s*\(|assert\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|shell_exec\s*\()`},

		// === Path Traversal / LFI / RFI ===
		{ID: "TRAV-001", Name: "Traversal Null Byte", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Null byte in path", Targets: []string{"args", "uri"}, Pattern: `\x00`},
		{ID: "TRAV-002", Name: "Traversal Dot-Dot-Slash", Phase: core.PhaseRequestHeaders, Score: 75, Action: core.ActionBlock, Description: "Directory traversal sequence", Targets: []string{"args", "uri"}, Pattern: `(?i)(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)`},
		{ID: "TRAV-003", Name: "Traversal PHP Wrapper", Phase: core.PhaseRequestBody, Score: 75, Action: core.ActionBlock, Description: "PHP/file wrapper in parameter", Targets: []string{"args", "body"}, Pattern: `(?i)(file|php|expect|data|input|zip|compress)://`},
		{ID: "TRAV-004", Name: "Traversal Sensitive File", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Sensitive system file requested", Targets: []string{"args", "uri"}, Pattern: `(?i)(/etc/passwd|boot\.ini|win\.ini|web\.config|\.htaccess|\.env|\.git/)`},
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

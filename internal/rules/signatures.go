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
		{ID: "XSS-002", Name: "XSS JavaScript Protocol", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "javascript: protocol in URL/header", Targets: []string{"args", "headers"}, Pattern: `(?i)java(?:\s|%0[9aAdD]|%20|&#[xX]?[0-9a-fA-F]+;)*script(?:\s|%0[9aAdD]|%20|&#[xX]?[0-9a-fA-F]+;)*:`},
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
		{ID: "SQLI-001", Name: "SQLi Union Select", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "UNION SELECT pattern", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)union(\s+|/\*[\s\S]{0,100}\*/)+(all(\s+|/\*[\s\S]{0,100}\*/)+)?select`},
		{ID: "SQLI-002", Name: "SQLi Stacked Destructive", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Stacked destructive query", Targets: []string{"args", "body"}, Pattern: `(?i);\s*(drop|delete|truncate|insert|update)\s`},
		{ID: "SQLI-003", Name: "SQLi Tautology + Comment", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Tautology with comment sequence", Targets: []string{"args", "body"}, Pattern: `(?i)(['"]?\s*\b(?:or|and)\b\s*['"]?[^'"\s=]+['"]?\s*=\s*['"]?[^'"\s=]+|\d+\s*=\s*\d+)`},
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
		// LDAP filter syntax requires parenthesised expressions with
		// attribute=value. The old `[*|&!\x00]` pattern matched any form
		// post with ampersands. Tightened to require an LDAP-ish filter
		// shape: (attr=*) or (|(...) or similar.
		{ID: "LDAP-001", Name: "LDAP Filter Injection", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "LDAP filter syntax in user input", Targets: []string{"args", "body"}, Pattern: `\(\s*[|&!]\s*\(|\(\s*(?:cn|uid|sn|objectClass|userPassword|mail|member|sAMAccountName)\s*=\s*[*]`},

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
		{ID: "RCE-001", Name: "RCE Command Substitution", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Command substitution $() or backticks", Targets: []string{"args", "body", "headers"}, Pattern: "(?i)(\\$\\([\\s\\S]{0,300}\\)|`[\\s\\S]{0,300}`)"},
		{ID: "RCE-002", Name: "RCE Reverse Shell", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Reverse shell indicator", Targets: []string{"args", "body"}, Pattern: `(?i)(bash\s+-i|nc\s+-[ev]|python\s+-c\s*['"]import socket)`},
		{ID: "RCE-003", Name: "RCE Dangerous Chain", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Shell meta-char followed by binary", Targets: []string{"args", "body"}, Pattern: `(?i)[;&|]\s*(curl|wget|python|perl|ruby|bash|sh|cmd|powershell|php|node|nodejs|lua|luajit|awk|gawk|nawk|expect|telnet|ssh|scp|ftp|tftp|nc|netcat|socat)\s+`},
		{ID: "RCE-004", Name: "RCE IFS Evasion", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionLog, Description: "IFS evasion pattern", Targets: []string{"args", "body"}, Pattern: `(?i)\$\{IFS\}`},
		{ID: "RCE-005", Name: "RCE Scripting One-Liners", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Scripting language one-liner execution", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(base64\s+-d|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)`},
		{ID: "RCE-006", Name: "RCE Dangerous Functions", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Dangerous PHP/function execution", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(eval\s*\(|assert\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|shell_exec\s*\()`},

		// === Path Traversal / LFI / RFI ===
		{ID: "TRAV-001", Name: "Traversal Null Byte", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Null byte in path", Targets: []string{"args", "uri"}, Pattern: `\x00`},
		{ID: "TRAV-002", Name: "Traversal Dot-Dot-Slash", Phase: core.PhaseRequestHeaders, Score: 75, Action: core.ActionBlock, Description: "Directory traversal sequence", Targets: []string{"args", "uri"}, Pattern: `(?i)(?:(?:\.|%2e|%252e|%c0%ae|%e0%80%ae|%f0%80%80%ae){2}(?:/|\\|%2f|%5c|%252f|%255c|%c0%af|%c1%9c|%e0%80%af|%f0%80%80%af))`},
		{ID: "TRAV-003", Name: "Traversal PHP Wrapper", Phase: core.PhaseRequestBody, Score: 75, Action: core.ActionBlock, Description: "PHP/file wrapper in parameter", Targets: []string{"args", "body"}, Pattern: `(?i)(file|php|expect|data|input|zip|compress)://`},
		// Word boundary on .env so "/static/my.environment.notes.txt" no
		// longer matches. Similarly anchor .htaccess to either end-of-path
		// or a slash so we don't false-positive on unrelated text.
		{ID: "TRAV-004", Name: "Traversal Sensitive File", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Sensitive system file requested", Targets: []string{"args", "uri"}, Pattern: `(?i)(/etc/passwd\b|\bboot\.ini\b|\bwin\.ini\b|\bweb\.config\b|\.htaccess(?:$|/)|\.env(?:$|[/?])|\.git/)`},

		// === JWT / Token Attacks ===
		{ID: "JWT-001", Name: "JWT Alg None", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "JWT algorithm none attack", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)"alg"\s*:\s*["']?\s*none\s*["']?`},

		// === GraphQL Abuse ===
		{ID: "GRAPHQL-001", Name: "GraphQL Introspection", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "GraphQL introspection query", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(__schema|__type|__typename|introspectionquery|query\s+introspectionquery)`},

		// === Host Header Attacks ===
		{ID: "HOST-001", Name: "Host Header Injection", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Suspicious Host header manipulation", Targets: []string{"headers"}, Pattern: `(?i)(X-Forwarded-Host|X-HTTP-Host-Override|X-Original-Host|X-Host)\s*:\s*[^:\s]{3,}`},

		// === XML-RPC / WordPress Attacks ===
		{ID: "XMLRPC-001", Name: "XML-RPC WordPress Attack", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "XML-RPC or WordPress attack payload", Targets: []string{"args", "uri", "body"}, Pattern: `(?i)<methodcall>|<methodname>wp\.|xmlrpc\.php|system\.multicall`},

		// === OAuth Abuse ===
		{ID: "OAUTH-001", Name: "OAuth Redirect Abuse", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "OAuth redirect_uri pointing to internal/localhost", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)redirect_uri\s*=\s*https?://[^&\s]*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\.local|\.internal)`},

		// === Base64 Encoded Payloads ===
		{ID: "B64-001", Name: "Base64 Decode Execution", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Execution after base64 decode", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:eval|exec|system|assert|passthru)\s*\(\s*(?:base64_decode|atob)\s*\(\s*["']?[A-Za-z0-9+/]{20,}=?["']?\s*\)\s*\)`},

		// === HTTP Parameter Pollution ===
		{ID: "HPP-001", Name: "HTTP Parameter Pollution", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Duplicate parameters suggesting HPP", Targets: []string{"args", "uri"}, Pattern: `(?i)([?&]id=[^&]*&.*[?&]id=|[?&]user=[^&]*&.*[?&]user=|[?&]role=[^&]*&.*[?&]role=)`},

		// === XPath Injection ===
		{ID: "XPATH-001", Name: "XPath Injection", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "XPath injection payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(/'?\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|count\s*\(\s*child::|local-name\s*\(\s*\)|namespace-uri\s*\(\s*\)|/text\s*\(\s*\)|substring\s*\(\s*|\]\s*\|\s*//|\*/\*)`},

		// === SSI Injection ===
		{ID: "SSI-001", Name: "SSI Injection", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Server-Side Include directive", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)<!--#(?:include|exec|printenv|config|fsize|flastmod|echo)\s+`},

		// === Cache Poisoning ===
		{ID: "CACHE-001", Name: "Cache Poisoning Headers", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Suspicious cache poisoning headers", Targets: []string{"headers"}, Pattern: `(?i)(X-Original-Url|X-Rewrite-Url|X-Forwarded-Host|X-Forwarded-Scheme|X-HTTP-Method-Override|Transfer-Encoding)\s*:\s*[^:\r\n]{2,}`},

		// === HTTP Method Override ===
		{ID: "METHOD-001", Name: "HTTP Method Override", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "HTTP method override header", Targets: []string{"headers"}, Pattern: `(?i)(X-HTTP-Method|X-HTTP-Method-Override|X-Method-Override|_method)\s*:\s*(?:GET|POST|PUT|DELETE|PATCH|TRACE|CONNECT|OPTIONS)`},

		// === Spring4Shell ===
		{ID: "SPRING-001", Name: "Spring4Shell", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Spring4Shell classloader manipulation", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)class\.module\.classLoader\.`},

		// === SSRF Cloud Variants (IMDSv2, etc.) ===
		{ID: "SSRF-006", Name: "SSRF Cloud Metadata Variants", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Cloud metadata endpoint variant", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(169\.254\.169\.254/(?:latest|metadata|api)|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|192\.0\.0\.192)`},

		// === Additional RCE ===
		{ID: "RCE-007", Name: "RCE Python Import OS", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Python one-liner importing dangerous modules", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)python\s+-c\s*['"][^'"]*import\s+(?:os|subprocess|socket|pty)`},
		{ID: "RCE-008", Name: "RCE Perl Open", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Perl open command execution", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)perl\s+-e\s*['"][^'"]*\bopen\s*[\s\(]`},

		// === XSS Template Injection / Polyglots ===
		{ID: "XSS-012", Name: "XSS Template Injection", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Template expression or polyglot payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)\$\{[^}]{0,200}\}`},

		// === JSON Injection ===
		{ID: "JSON-001", Name: "JSON Injection", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Suspicious JSON privilege escalation", Targets: []string{"args", "body"}, Pattern: `(?i)\{\s*["']?(?:admin|role|isAdmin|permissions|access)\s*["']?\s*:\s*(?:true|1|null)\s*\}`},

		// === CORS Bypass ===
		{ID: "CORS-001", Name: "CORS Bypass", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Suspicious CORS origin header", Targets: []string{"headers"}, Pattern: `(?i)(Origin|Access-Control-Request-Method)\s*:\s*(?:[^:\r\n]*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|null)|\s*\*)`},

		// === Additional Scanner / Bot UAs ===
		{ID: "SCAN-004", Name: "Extended Recon UA", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Reconnaissance scanner User-Agent", Targets: []string{"headers"}, Pattern: `(?i)(censys|shodan|zoomeye|fofa|binaryedge|onyphe|spyse|greynoise|internet-measurement|nuclei|jaeles|xray|goby)`},

		// === PHP Specific Attacks ===
		{ID: "PHP-001", Name: "PHP Dangerous Functions", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "PHP dangerous function call", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(pcntl_exec\s*\(|create_function\s*\(|call_user_func(?:_array)?\s*\(\s*["']?(?:assert|eval|system|exec|passthru))`},

		// === Header Manipulation ===
		{ID: "HEADER-001", Name: "IP Header Spoofing", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Private IP in forwarding header", Targets: []string{"headers"}, Pattern: `(?i)(X-Forwarded-For|X-Real-IP|True-Client-IP)\s*:\s*.*(?:127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})`},

		// === Insecure Deserialization ===
		{ID: "DESER-001", Name: "Java Serialized Object", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Java serialized object payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(rO0AB|ACED00)`},
		{ID: "DESER-002", Name: "PHP Serialized Object", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "PHP serialized object payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(O:\d+:"|a:\d+:\{|s:\d+":)`},
		{ID: "DESER-003", Name: "NET Serialized Object", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: ".NET serialized object payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)AAEAAAD`},

		// === Server-Side Template Injection ===
		{ID: "SSTI-001", Name: "SSTI Jinja2 Twig", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Jinja2 or Twig template injection", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)\{\{\s*(?:7\*7|config|self|_self|lipsum|joiner|namespace|cycler)\s*\}\}`},
		{ID: "SSTI-002", Name: "SSTI Velocity Freemarker", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Velocity or Freemarker template injection", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(\$class|\$runtime\.exec|<#assign|\$\{\.new|\$\{.*\.getRuntime\(\))`},

		// === WebShell Uploads ===
		{ID: "SHELL-001", Name: "PHP WebShell Eval", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "PHP eval web shell payload", Targets: []string{"body", "headers"}, Pattern: `(?i)(eval\s*\(\s*\$_POST|assert\s*\(\s*\$_REQUEST|<\?php\s+@?eval\s*\(|<\?=\s*@?\$_POST|system\s*\(\s*\$_GET)`},
		{ID: "SHELL-002", Name: "PHP WebShell Disguised", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Disguised PHP web shell upload", Targets: []string{"body", "headers"}, Pattern: `(?i)(GIF89a<\?php|shell_exec\s*\(|passthru\s*\(\s*\$_GET|exec\s*\(\s*\$_POST)`},

		// === Log Injection ===
		{ID: "LOG-001", Name: "Log Injection Newline", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Newline injection in log field", Targets: []string{"headers"}, Pattern: `(?i)(\x0a|\x0d|%0a|%0d)`},

		// === Padding Oracle / Crypto ===
		{ID: "CRYPTO-001", Name: "Padding Oracle Pattern", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Repeated base64 blocks suggesting padding oracle", Targets: []string{"args", "body"}, Pattern: `(?i)(?:[A-Za-z0-9+/]{40,}=?\s*){3,}`},

		// === Mass Assignment ===
		{ID: "MASS-001", Name: "Mass Assignment Privilege", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Mass assignment privilege escalation", Targets: []string{"args", "body"}, Pattern: `(?i)["']?(admin|role|is_admin|isAdmin|superuser|is_superuser|privilege)\s*["']?\s*[:=]\s*["']?(true|1|admin|root)["']?`},

		// === Content-Type Confusion ===
		{ID: "CT-001", Name: "Content-Type Confusion JSON XML", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "application/json request with XML-like body", Targets: []string{"body", "headers"}, Pattern: `(?i)Content-Type\s*:\s*application/json[\s\S]{0,300}<\?xml`},

		// === API Key / Secret Leakage ===
		{ID: "LEAK-001", Name: "API Key Secret Leak", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Potential API key or secret in payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(api[_-]?key\s*[:=]\s*['"]?[a-z0-9]{16,}|aws_secret|private[_-]?key|secret[_-]?key)`},

		// === DNS Rebinding ===
		{ID: "DNS-001", Name: "DNS Rebinding Host", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionLog, Description: "IP-as-domain in Host header suggesting DNS rebinding", Targets: []string{"headers"}, Pattern: `(?i)Host\s*:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`},

		// === Credential Stuffing ===
		{ID: "STUFF-001", Name: "Credential Stuffing Pattern", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Bulk credential stuffing pattern", Targets: []string{"args", "body"}, Pattern: `(?i)((?:username|email|user)\s*[:=]\s*[^&\s]{3,50}&(?:password|pass|pwd)\s*[:=]\s*[^&\s]{3,50})`},
		{ID: "STUFF-002", Name: "Credential Stuffing Tool", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Credential stuffing tool signature", Targets: []string{"headers"}, Pattern: `(?i)(sentry\s*mba|open\s*bullet|snipr|storm|blackbullet|silverbullet)`},

		// === Additional Bot / Scrapers ===
		{ID: "BOT-001", Name: "Automated Client UA", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Automated HTTP client User-Agent", Targets: []string{"headers"}, Pattern: `(?i)(python-requests|scrapy|libwww-perl|java\/|httpclient|http-client|axios|okhttp)`},

		// === Business Logic Abuse ===
		{ID: "BL-001", Name: "Business Logic Negative Value", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Negative price or quantity manipulation", Targets: []string{"args", "body"}, Pattern: `(?i)(price|amount|quantity|cost|total|value|coupon|discount)\s*[:=]\s*-\d+`},

		// === Insecure Direct Object Reference ===
		{ID: "IDOR-001", Name: "IDOR Sequential Enumeration", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Sequential ID enumeration in parameters", Targets: []string{"args", "uri"}, Pattern: `(?i)[?&](?:id|user_id|account_id|order_id|doc_id)\s*[:=]\s*\d{1,6}\b`},

		// === Clickjacking / UI Redress ===
		{ID: "CLICK-001", Name: "Clickjacking Frame Options Bypass", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Clickjacking frame options bypass attempt", Targets: []string{"headers"}, Pattern: `(?i)(X-Frame-Options|Content-Security-Policy|frame-ancestors)`},

		// Egress / Outbound SSRF protection
		{ID: "EGRESS-001", Name: "SSRF Private IP", Phase: core.PhaseEgressRequest, Score: 100, Action: core.ActionBlock, Description: "Outbound request to private IP range", Targets: []string{"url"}, Pattern: `(?i)(https?://)(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0|localhost|\[::1\]|::1)`},
		{ID: "EGRESS-002", Name: "SSRF Metadata Endpoint", Phase: core.PhaseEgressRequest, Score: 100, Action: core.ActionBlock, Description: "Outbound request to cloud metadata endpoint", Targets: []string{"url"}, Pattern: `(?i)(169\.254\.169\.254|metadata\.google\.internal|instance-data|metadata\.svc|alibaba\.ecs\.meta)`},
		{ID: "EGRESS-003", Name: "Suspicious Outbound TLD", Phase: core.PhaseEgressRequest, Score: 50, Action: core.ActionBlock, Description: "Outbound request to suspicious TLD", Targets: []string{"url"}, Pattern: `(?i)\.(tk|ml|ga|cf|top|xyz|bid|loan|men|date|wang|party|review|country|stream|gdn|mom|xin|kim)\b`},
		{ID: "EGRESS-004", Name: "Data Exfiltration Large Body", Phase: core.PhaseEgressRequest, Score: 30, Action: core.ActionLog, Description: "Outbound request body larger than 1KB", Targets: []string{"body"}, Pattern: `.{1000,}`},

		// === Bot / Scanner Detection ===
		{ID: "BOT-002", Name: "Headless Chrome Puppeteer", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "Headless Chrome or Puppeteer User-Agent detected", Targets: []string{"headers"}, Pattern: `(?i)(HeadlessChrome|Puppeteer|PhantomJS)`},
		{ID: "BOT-003", Name: "Selenium WebDriver", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "Selenium WebDriver signature in headers", Targets: []string{"headers"}, Pattern: `(?i)(Selenium|WebDriver|SeleniumIDE|SeleniumHQ|selenium-wire)`},
		// Only trigger on the canonical `curl/X.Y.Z` UA form so headers that
		// mention curl in other contexts (service names, scripts, etc.)
		// don't constantly fire. curl is a legitimate ops / CI tool, so
		// this stays at ActionLog and a modest score.
		{ID: "BOT-004", Name: "cURL User-Agent", Phase: core.PhaseRequestHeaders, Score: 25, Action: core.ActionLog, Description: "curl command-line tool User-Agent", Targets: []string{"headers.User-Agent"}, Pattern: `(?i)^curl/\d`},
		{ID: "BOT-005", Name: "Wget Client", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Wget command-line tool detected", Targets: []string{"headers"}, Pattern: `(?i)\bwget\b`},
		{ID: "SCAN-005", Name: "Nmap Scanner", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Nmap scanning tool detected", Targets: []string{"headers"}, Pattern: `(?i)\bnmap\b`},
		{ID: "SCAN-006", Name: "Nikto Scanner", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Nikto vulnerability scanner detected", Targets: []string{"headers"}, Pattern: `(?i)\bnikto\b`},
		{ID: "SCAN-007", Name: "SQLMap Scanner", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "SQLMap injection tool detected", Targets: []string{"headers"}, Pattern: `(?i)\bsqlmap\b`},
		{ID: "SCAN-008", Name: "DirBuster Gobuster", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Directory brute-forcer detected", Targets: []string{"headers"}, Pattern: `(?i)(dirbuster|gobuster)`},
		{ID: "SCAN-009", Name: "Masscan Zmap", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Internet-scale port scanner detected", Targets: []string{"headers"}, Pattern: `(?i)(masscan|zmap)`},
		{ID: "BOT-006", Name: "SEO Scraper Bot", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "Commonly abused SEO scraper bot detected", Targets: []string{"headers"}, Pattern: `(?i)(ahrefsbot|semrushbot|majestic|mozbot|screaming\s*frog|rogerbot|dotbot)`},
		// === Protocol Attacks ===
		{ID: "PROTO-002", Name: "HTTP2 Pseudo Header Abuse", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "HTTP/2 pseudo-header in HTTP/1.1 request", Targets: []string{"headers"}, Pattern: `(?i)[\r\n]:(authority|method|path|scheme)\s*:`},
		{ID: "SMUG-003", Name: "HTTP Smuggling Chunked Abuse", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Chunked encoding body containing embedded HTTP request", Targets: []string{"body"}, Pattern: `(?i)\r\n0\r\n[\s\S]{0,1000}(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/`},
		{ID: "HOST-002", Name: "Host Header Injection", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Multiple or injected Host headers", Targets: []string{"headers"}, Pattern: `(?i)Host\s*:[^:\r\n]*[\r\n][\s\S]{0,200}Host\s*:`},
		{ID: "HOST-003", Name: "X-Forwarded-Host Poisoning", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "X-Forwarded-Host pointing to loopback or metadata", Targets: []string{"headers"}, Pattern: `(?i)X-Forwarded-Host\s*:\s*[^:\r\n]*(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1|\.local|\.internal|169\.254\.\d+\.\d+)`},

		// === Cloud Metadata Attacks ===
		{ID: "CLOUD-001", Name: "AWS Metadata Access", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "AWS metadata endpoint or token in request", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:/latest/meta-data|/latest/user-data|/latest/dynamic/instance-identity|X-aws-ec2-metadata-token)`},
		{ID: "CLOUD-002", Name: "Azure Metadata Access", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Azure metadata endpoint in request", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:/metadata/instance|/metadata/identity|metadata\.azure\.com|api-version=.*metadata|169\.254\.169\.254/metadata)`},
		{ID: "CLOUD-003", Name: "GCP Metadata Header Spoof", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "Client-sent GCP Metadata-Flavor header", Targets: []string{"headers"}, Pattern: `(?i)Metadata-Flavor\s*:\s*Google`},

		// === Infrastructure Access ===
		{ID: "K8S-001", Name: "Kubernetes API Access", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Kubernetes API endpoint in URL", Targets: []string{"uri"}, Pattern: `(?i)/api/v\d+/namespaces|/api/v\d+/pods|/api/v\d+/secrets|/api/v\d+/services|/apis/apps/v\d+/deployments|/apis/rbac\.authorization\.k8s\.io`},
		{ID: "DOCKER-001", Name: "Docker Socket Access", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Docker Unix socket access attempt", Targets: []string{"args", "body", "headers", "uri"}, Pattern: `(?i)(?:/var/run/docker\.sock|/docker\.sock|unix://.*docker)`},

		// === Reverse Shell in Headers / Cookies ===
		{ID: "RCE-009", Name: "Reverse Shell in Headers", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Reverse shell indicator in headers or cookies", Targets: []string{"headers"}, Pattern: `(?i)(?:bash\s+-i|/bin/bash\s+-i|sh\s+-i|/bin/sh\s+-i|nc\s+-[ev]|netcat\s+-[ev]|python\s+-c\s*['"]import socket|ruby\s+-rsocket\s+-e|perl\s+-e\s*['"]use Socket)`},
		// === API Abuse & Injection Variants ===
		{ID: "GRAPHQL-002", Name: "GraphQL Introspection Query", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionLog, Description: "GraphQL introspection query with schema/types fields", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:query\s+introspectionquery|\{\s*__schema\s*\{\s*(?:types|queryType|mutationType|subscriptionType)\s*\{|__type\s*\(\s*name\s*:|__field|__inputValue|__enumValue|__directive)`},
		{ID: "GRAPHQL-003", Name: "GraphQL Mutation Abuse", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "GraphQL mutation for destructive or bulk operations", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)mutation\s*\{[^}]*(?:delete|remove|destroy|bulkDelete|bulkUpdate|updateMany|deleteMany|drop|truncate)`},
		{ID: "SQLI-010", Name: "JSON SQL Injection", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "SQL injection payload inside JSON string value", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)"[^"]*(?:union\s+select|'\s*or\s+'1'\s*=\s*'1|"\s*or\s+"1"\s*=\s*"1|;\s*(?:drop|delete|truncate|insert|update)\s|(?:and|or)\s+\d+\s*=\s*\d+)[^"]*"`},
		{ID: "NOSQL-003", Name: "MongoDB JSON Operator Injection", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "MongoDB NoSQL operator injection inside JSON body", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)\{\s*["']?\$(?:where|gt|gte|lt|lte|ne|eq|regex|exists|in|nin)\s*["']?\s*:`},
		{ID: "NOSQL-004", Name: "Elasticsearch Query Injection", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Elasticsearch query DSL injection", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)"query"\s*:\s*\{[\s\S]{0,500}"(?:script|template|wildcard|regexp|fuzzy|match_phrase|query_string)"`},
		{ID: "LDAP-002", Name: "LDAP Search Injection", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "LDAP injection in search filter parameters", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:\*\)|\(\||\(&|\)\()[\s\S]{0,200}(?:objectclass|objectCategory|uid|cn|dc|ou|\*)(?:\s*=\s*\*|\))`},
		{ID: "SSTI-003", Name: "SSTI Jinja2 Flask Django", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Jinja2, Flask or Django template injection pattern", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:\{\{\s*request\s*\|(?:\s*attr)?|\{\{\s*config\s*\.\s*items\s*\(|\{\{\s*self\s*\.__class__\s*\}\}|\{%\s*(?:for|if)\s+.*?request|\{\{\s*.*?\.__class__\s*\.__bases__\s*\}\})`},
		{ID: "EL-001", Name: "Expression Language Injection", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "EL injection with dangerous class or runtime access", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:\$\{[^}]*(?:java|runtime|exec|process|environment|classloader)[^}]*\}|\#\{[^}]*(?:java|runtime|exec|process|environment)[^}]*\})`},
		{ID: "XPATH-002", Name: "XPath Injection Variant", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "XPath injection with axis or boolean bypass", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:\/(?:child|parent|descendant|ancestor|attribute|self)::|count\s*\(\s*\/\/|(?:'|")\s*(?:or|and)\s+(?:'|")?\d+(?:'|")?\s*=\s*(?:'|")?\d+|\/\/\*\[|\]\s*\|\s*\/\/|\*\[local-name\s*\()`},
		{ID: "XSS-013", Name: "CSS Style Attribute Injection", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "CSS injection or style attribute XSS payload", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:style\s*=\s*["']?[^"'>]{0,200}(?:javascript\s*:|@import\s+|(?:-moz-binding|behavior)\s*:|data\s*:\s*text\/css|url\s*\(\s*["']?\s*javascript\s*:))`},
		// === Information Disclosure ===
		{ID: "INFO-001", Name: "Stack Trace Disclosure", Phase: core.PhaseResponseBody, Score: 50, Action: core.ActionLog, Description: "Stack trace or exception details leaked in response", Targets: []string{"body"}, Pattern: `(?i)(stack\s*trace|traceback\s*\(most\s*recent\s*call\s*last\)|exception\s*in\s*thread|error\s*at\s*line\s*\d+|caused\s*by\s*:\s*\S{3,})`},
		{ID: "INFO-002", Name: "Git Directory Exposure", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Git repository directory exposed in URL", Targets: []string{"uri"}, Pattern: `(?i)/\.git(/|$|\s|\?|&)`},
		{ID: "INFO-003", Name: "ENV File Exposure", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Environment configuration file requested", Targets: []string{"uri"}, Pattern: `(?i)/\.env(\.local|\.production|\.development|\.staging|\.test)?(/|$|\?|&|\s)`},
		{ID: "INFO-004", Name: "PHP Info Page Access", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionBlock, Description: "Access to PHP information page", Targets: []string{"uri"}, Pattern: `(?i)/(phpinfo|php_info|info)\.php$`},
		{ID: "INFO-005", Name: "CMS Config File Exposure", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "CMS configuration file access attempt", Targets: []string{"uri"}, Pattern: `(?i)/(wp-config\.php|configuration\.php|config\.inc\.php|settings\.php|database\.yml|db\.ini|\.htpasswd)\b`},

		// === Business Logic Abuse ===
		{ID: "BL-002", Name: "Admin Panel Brute Force", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionLog, Description: "Request to known admin panel endpoint", Targets: []string{"uri"}, Pattern: `(?i)/(admin|wp-admin|wp-login|manager|administrator|login|signin|backend|controlpanel)(/|\.(php|asp|aspx|jsp))?$`},
		{ID: "BL-003", Name: "Credit Card Pattern in Request", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Credit card number pattern detected in request", Targets: []string{"args", "body"}, Pattern: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`},
		{ID: "BL-004", Name: "Carding Attack Pattern", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Small amount with card details suggests carding", Targets: []string{"args", "body"}, Pattern: `(?i)(?:amount|price|total|sum)\s*[:=]\s*(?:0\.0[1-9]|0\.[1-9]\d?|\d{1,3})(?:\.\d+)?\b.*(?:cvv|ccv|cvc|security[_\s]?code|expir|exp[_\s]?date)`},
		{ID: "BL-005", Name: "Comment Spam URLs", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Excessive URLs in form data suggests comment spam", Targets: []string{"args", "body"}, Pattern: `(?i)(?:https?://[^\s&"<>]{4,}.*?){8,}`},
		{ID: "BL-006", Name: "XML-RPC Pingback Abuse", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "XML-RPC pingback.ping method detected", Targets: []string{"body", "uri"}, Pattern: `(?i)pingback\.ping`},

		// --- CVE-specific and framework exploitation patterns ---
		{ID: "CVE-LOG4J-001", Name: "Log4Shell JNDI Injection", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "JNDI lookup in request (CVE-2021-44228)", Targets: []string{"args", "headers", "body", "uri"}, Pattern: `(?i)\$\{(?:jndi|j\$\{::-n\}dnl?i|j[^}]*ndi)[:\s]*(?:ldap|rmi|dns|nis|iiop|corba|nds|http)s?:`},
		{ID: "CVE-LOG4J-002", Name: "Log4Shell Obfuscated", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Obfuscated JNDI with ${lower} / ${upper} / ${env}", Targets: []string{"args", "headers", "body", "uri"}, Pattern: `(?i)\$\{(?:\$\{(?:lower|upper|env|sys|::-)[^}]*\}|[^}]*\$\{[^}]*\}){2,}`},
		{ID: "CVE-SPRING4SHELL-001", Name: "Spring4Shell ClassLoader", Phase: core.PhaseRequestBody, Score: 100, Action: core.ActionBlock, Description: "Spring4Shell class-loader path traversal (CVE-2022-22965)", Targets: []string{"args", "body", "uri"}, Pattern: `(?i)class\.module\.classLoader|class\.classLoader\.resources\.context`},
		{ID: "CVE-STRUTS-S2-001", Name: "Struts OGNL", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Struts OGNL expression injection", Targets: []string{"headers", "args", "body", "uri"}, Pattern: `(?i)%\{.*(?:#context|#request|#response|@java\.lang|@?ognl\.)`},
		{ID: "CVE-CONFLUENCE-2022-26134", Name: "Confluence OGNL", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Atlassian Confluence OGNL injection CVE-2022-26134", Targets: []string{"uri", "args"}, Pattern: `(?i)\$\{[^}]*@java\.lang\.(?:Runtime|ProcessBuilder)`},
		{ID: "CVE-PROXYSHELL-001", Name: "Exchange ProxyShell path", Phase: core.PhaseRequestHeaders, Score: 90, Action: core.ActionBlock, Description: "Exchange ProxyShell URL rewrite (CVE-2021-34473)", Targets: []string{"uri", "path"}, Pattern: `(?i)/autodiscover/autodiscover\.json.*@.*/(?:powershell|mapi|ews)`},
		{ID: "CVE-MOVEIT-001", Name: "MOVEit Transfer SQLi", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "MOVEit Transfer human.aspx abuse (CVE-2023-34362)", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:human|guestaccess)\.aspx.*(?:transaction|folderid|groupid)=.{0,20}(?:union|select|\-\-)`},
		{ID: "CVE-F5-BIG-IP-001", Name: "F5 iControl RCE", Phase: core.PhaseRequestHeaders, Score: 90, Action: core.ActionBlock, Description: "F5 iControl REST RCE (CVE-2022-1388)", Targets: []string{"uri"}, Pattern: `(?i)/mgmt/tm/util/bash`},
		{ID: "CVE-GITLAB-EXIFTOOL", Name: "GitLab ExifTool RCE path", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "GitLab user-avatar DjVu/ExifTool RCE (CVE-2021-22205)", Targets: []string{"body"}, Pattern: `(?i)\(metadata\s+"[^"]*\\\s*"`},

		// --- SSTI (Server-Side Template Injection) ---
		{ID: "SSTI-JINJA-001", Name: "Jinja2 Template Injection", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "Jinja2 {{ }} with attribute traversal", Targets: []string{"args", "body", "uri"}, Pattern: `\{\{[^{}]*(?:config|self|request|__class__|__mro__|__subclasses__|__globals__|__import__)[^{}]*\}\}`},
		{ID: "SSTI-TWIG-001", Name: "Twig / Symfony SSTI", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "Twig _self or app object escape", Targets: []string{"args", "body"}, Pattern: `\{\{[^{}]*(?:_self\.env|app\.request|registerUndefinedFilterCallback|getFilter\()[^{}]*\}\}`},
		{ID: "SSTI-ERB-001", Name: "ERB / Ruby SSTI", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "ERB <%= ... system/exec ... %>", Targets: []string{"args", "body"}, Pattern: `(?i)<%=?\s*(?:system|exec|%x|IO\.popen|open3|File\.(?:read|open)|eval|instance_eval)\b`},
		{ID: "SSTI-VELOCITY-001", Name: "Velocity SSTI", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "Velocity #set / $class.forName", Targets: []string{"args", "body"}, Pattern: `(?i)\$class\.(?:forName|newInstance|getDeclared)`},
		{ID: "SSTI-FREEMARKER-001", Name: "Freemarker SSTI", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "Freemarker Execute or freemarker.template.utility", Targets: []string{"args", "body"}, Pattern: `(?i)<#assign[^>]*freemarker\.template\.utility\.Execute`},
		{ID: "SSTI-SMARTY-001", Name: "Smarty SSTI", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Smarty {php} or getStreamVariable", Targets: []string{"args", "body"}, Pattern: `(?i)\{(?:php|Smarty_Internal|getStreamVariable)\}`},

		// --- GraphQL abuse ---
		{ID: "GQL-001", Name: "GraphQL Introspection Abuse", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "Introspection query from non-tooling client", Targets: []string{"body", "args"}, Pattern: `(?i)__schema\s*\{[^}]*types\s*\{`},
		{ID: "GQL-002", Name: "GraphQL Field Duplication DoS", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Same field queried >50 times in one op (batch DoS)", Targets: []string{"body"}, Pattern: `(?:\b(\w{3,20})\b[^\w]+){50,}`},
		{ID: "GQL-003", Name: "GraphQL Mutation Injection", Phase: core.PhaseRequestBody, Score: 50, Action: core.ActionLog, Description: "Unauthenticated-looking mutation with payload", Targets: []string{"body"}, Pattern: `(?i)mutation\s*\{[^}]*(?:deleteUser|updateRole|grantAdmin|resetPassword)`},
		{ID: "GQL-004", Name: "GraphQL Deep Nesting", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Excessively nested GraphQL query", Targets: []string{"body"}, Pattern: `(?:\{[^{}]*){8,}`},

		// --- Insecure Deserialization ---
		{ID: "DESER-JAVA-001", Name: "Java Serialized Object Header", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "aced0005 / rO0 Java serialized header", Targets: []string{"body", "headers"}, Pattern: `(?:aced0005|rO0[AB])`},
		{ID: "DESER-PHP-001", Name: "PHP Serialized Gadget", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "PHP serialize() output with object marker", Targets: []string{"body"}, Pattern: `O:\d+:"[A-Za-z_][A-Za-z0-9_\\]{0,100}":\d+:\{`},
		{ID: "DESER-NODE-001", Name: "Node Deserialization RCE", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "node-serialize _$$ND_FUNC$$_ gadget", Targets: []string{"body", "args"}, Pattern: `_\$\$ND_FUNC\$\$_function`},
		{ID: "DESER-PYTHON-001", Name: "Python Pickle / base64", Phase: core.PhaseRequestBody, Score: 60, Action: core.ActionBlock, Description: "Python cPickle / __reduce__ byte markers", Targets: []string{"body"}, Pattern: `(?:\\x80\\x04\\x95|cposix\nsystem|c__builtin__\nglobals)`},
		{ID: "DESER-RUBY-001", Name: "Ruby Marshal Gadget", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Ruby Marshal.load / DeprecatedInstance gadget", Targets: []string{"body"}, Pattern: `(?i)Gem::DependencyList|Rails::Info|DeprecatedInstanceVariableProxy`},
		{ID: "DESER-YAML-001", Name: "YAML Ruby tag injection", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "!!ruby/object or !!python/object tag", Targets: []string{"body"}, Pattern: `(?i)!!(?:ruby|python)/(?:object|struct|module)(?::[^\s]+)?\s`},

		// --- Server-Side Includes / Edge-Side Includes ---
		{ID: "SSI-001", Name: "SSI exec cmd", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "<!--#exec cmd= SSI injection", Targets: []string{"args", "body", "uri"}, Pattern: `(?i)<!--#\s*(?:exec|include|printenv|config)\s`},
		{ID: "ESI-001", Name: "ESI Include Injection", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "ESI <esi:include> payload in user input", Targets: []string{"args", "body"}, Pattern: `(?i)<esi:(?:include|vars|eval|choose)`},

		// --- HTTP Request Smuggling + H2 ---
		{ID: "SMUG-003", Name: "Obfuscated Transfer-Encoding", Phase: core.PhaseRequestHeaders, Score: 90, Action: core.ActionBlock, Description: "TE header with non-standard token", Targets: []string{"headers.Transfer-Encoding", "headers"}, Pattern: `(?i)transfer[-\s_]*encoding\s*:\s*(?:\s*chunked\s*[;,].+|[^\w,]*chunked[^\w,]*\S)`},
		{ID: "SMUG-004", Name: "Content-Length Chunk Conflict", Phase: core.PhaseRequestBody, Score: 70, Action: core.ActionBlock, Description: "Body claims chunked but has length marker", Targets: []string{"body"}, Pattern: `(?s)^0+\r?\n\r?\nGET\s|^[0-9a-f]+\r?\n[\s\S]*?\r?\n0\r?\n[A-Z]`},

		// --- Advanced bot / scanner fingerprints ---
		{ID: "SCAN-010", Name: "Nuclei scanner", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionBlock, Description: "Nuclei user-agent", Targets: []string{"headers.User-Agent"}, Pattern: `(?i)\bNuclei\b`},
		{ID: "SCAN-011", Name: "Nikto scanner", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionBlock, Description: "Nikto user-agent", Targets: []string{"headers.User-Agent"}, Pattern: `(?i)Nikto/`},
		{ID: "SCAN-012", Name: "masscan / zmap", Phase: core.PhaseRequestHeaders, Score: 40, Action: core.ActionBlock, Description: "Mass-scanner fingerprints", Targets: []string{"headers.User-Agent"}, Pattern: `(?i)(?:masscan|zmap|zgrab)\b`},
		{ID: "SCAN-013", Name: "acunetix / netsparker", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionBlock, Description: "Commercial vuln scanners", Targets: []string{"headers.User-Agent", "headers"}, Pattern: `(?i)(?:acunetix|netsparker|invicti|qualys|tenable|nessus)\b`},
		{ID: "SCAN-014", Name: "Probing path signatures", Phase: core.PhaseRequestHeaders, Score: 35, Action: core.ActionLog, Description: "Well-known scanner paths", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:\.env|\.git/(?:HEAD|config)|wp-admin/install\.php|phpinfo\.php|\.aws/credentials|\.ssh/id_rsa|actuator/(?:env|heapdump|trace))\b`},
		{ID: "SCAN-015", Name: "Common webshell names", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Known webshell filenames in URL", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:c99|r57|b374k|wso|adminer|filesman|weevely)\.(?:php|jsp|aspx?)\b`},

		// --- Headers / Cookie abuse ---
		{ID: "HDR-001", Name: "Host Header Injection", Phase: core.PhaseRequestHeaders, Score: 50, Action: core.ActionBlock, Description: "CRLF or URL in Host header", Targets: []string{"headers.Host"}, Pattern: `[\r\n]|(?i)https?://`},
		{ID: "HDR-002", Name: "Forwarded Header Spoof", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "Forwarded with SSRF-range host", Targets: []string{"headers.X-Forwarded-For", "headers.Forwarded"}, Pattern: `(?i)(?:127\.|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|::1|localhost|metadata)`},
		{ID: "HDR-003", Name: "Oversized Cookie Header", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "Cookie header >4KB used in scanner probes", Targets: []string{"headers.Cookie"}, Pattern: `.{1000}.{1000}.{1000}.{1000}`},

		// --- Path traversal / file inclusion variants ---
		{ID: "LFI-010", Name: "Unicode traversal", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "Unicode / alt-encoded ../ sequences", Targets: []string{"uri", "path", "args"}, Pattern: `(?i)(?:%c0%ae|%c1%9c|%uff0e|%u002e|\.\\\.\\|\.\./\\)`},
		{ID: "LFI-011", Name: "PHP wrapper", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "PHP stream wrappers (data, expect, phar, zip)", Targets: []string{"args", "body", "uri"}, Pattern: `(?i)\b(?:data|expect|phar|zip|compress\.zlib|compress\.bzip2|glob|ogg|ssh2|rar):/{0,2}[^\s]`},
		{ID: "LFI-012", Name: "Windows sensitive file", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "Windows system path in request", Targets: []string{"uri", "args"}, Pattern: `(?i)\b(?:c:\\windows\\system32\\|boot\.ini|win\.ini|\\sam|\\security|\\ntds\.dit)\b`},

		// --- SQLi extensions ---
		{ID: "SQLI-020", Name: "PostgreSQL pg_sleep", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Time-based pg_sleep injection", Targets: []string{"args", "body", "uri"}, Pattern: `(?i)pg_sleep\s*\(`},
		{ID: "SQLI-021", Name: "MSSQL waitfor delay", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "MSSQL waitfor delay time-based", Targets: []string{"args", "body", "uri"}, Pattern: `(?i)waitfor\s+delay\s+["']\d`},
		{ID: "SQLI-022", Name: "Hex-encoded SQLi payload", Phase: core.PhaseRequestHeaders, Score: 80, Action: core.ActionBlock, Description: "0x68657870... hex-encoded strings", Targets: []string{"args", "body"}, Pattern: `(?i)0x[0-9a-f]{20,}`},
		{ID: "SQLI-023", Name: "Stacked queries", Phase: core.PhaseRequestHeaders, Score: 90, Action: core.ActionBlock, Description: "Semicolon-separated query followed by keyword", Targets: []string{"args", "body"}, Pattern: `(?i);\s*(?:select|insert|update|delete|drop|create|alter|exec|xp_cmdshell)\b`},
		{ID: "SQLI-024", Name: "Comment-based evasion", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "MySQL /*!...*/ or -- evasion", Targets: []string{"args", "body"}, Pattern: `(?i)/\*!\d{5}.*\*/|\bunion\b\s*(?:/\*.*?\*/\s*)?select`},

		// --- RCE / command injection extensions ---
		{ID: "RCE-010", Name: "Powershell encoded command", Phase: core.PhaseRequestBody, Score: 90, Action: core.ActionBlock, Description: "PowerShell -EncodedCommand / IEX DownloadString", Targets: []string{"args", "body"}, Pattern: `(?i)(?:-EncodedCommand|iex\s*\(\s*new-object\s+net\.webclient|DownloadString\s*\()`},
		{ID: "RCE-011", Name: "bash curl|sh", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Classic curl ... | (sh|bash) install pattern", Targets: []string{"args", "body"}, Pattern: `(?i)(?:curl|wget|fetch)\s+[^|&]{3,}\s*\|\s*(?:sh|bash|zsh|python|perl|ruby|php)\b`},
		{ID: "RCE-012", Name: "Shellshock", Phase: core.PhaseRequestHeaders, Score: 100, Action: core.ActionBlock, Description: "Bash Shellshock (CVE-2014-6271) function definition", Targets: []string{"headers"}, Pattern: `\(\s*\)\s*\{\s*[:_].*?\}\s*;`},
		{ID: "RCE-013", Name: "Python one-liner revshell", Phase: core.PhaseRequestBody, Score: 80, Action: core.ActionBlock, Description: "Python socket-based reverse shell one-liner", Targets: []string{"args", "body"}, Pattern: `(?i)python.{0,20}-c.{0,50}(?:socket|subprocess).{0,100}(?:connect|dup2)`},

		// --- Request shape anomalies ---
		// ANOM-001 (GET with body) was removed in 2026-04 — as a pure regex
		// against the method target it fired on every GET request and flooded
		// the log. The CRS equivalent uses SecLang chaining across method +
		// Content-Length headers, which needs engine-level support we don't
		// have; if the structural check ever lands it should come back.
		{ID: "ANOM-002", Name: "Long URL", Phase: core.PhaseRequestHeaders, Score: 25, Action: core.ActionLog, Description: "URL longer than 2000 chars — likely fuzzing", Targets: []string{"uri"}, Pattern: `.{1000}.{1000}`},
		{ID: "ANOM-003", Name: "Null byte in URL", Phase: core.PhaseRequestHeaders, Score: 70, Action: core.ActionBlock, Description: "Null byte in URL — parser confusion", Targets: []string{"uri", "path", "args"}, Pattern: `\x00|%00|\\x00|\\u0000`},

		// --- Credential-stuffing patterns ---
		{ID: "CS-001", Name: "Combo-list format", Phase: core.PhaseRequestBody, Score: 40, Action: core.ActionLog, Description: "user:pass colon-separated payload", Targets: []string{"body"}, Pattern: `(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+:[^\s]{4,}$`},
		{ID: "CS-002", Name: "openbullet config markers", Phase: core.PhaseRequestHeaders, Score: 60, Action: core.ActionBlock, Description: "OpenBullet / BAS tool signatures", Targets: []string{"headers.User-Agent", "headers"}, Pattern: `(?i)(?:openbullet|blackbullet|anomaly|storm|silverbullet|sentrymba)\b`},

		// --- JSONP / callback abuse ---
		{ID: "JSONP-001", Name: "Suspicious JSONP callback", Phase: core.PhaseRequestHeaders, Score: 30, Action: core.ActionLog, Description: "JSONP callback param with JS payload", Targets: []string{"args"}, Pattern: `(?i)^(?:callback|jsonp|cb)=[^a-z0-9_$.]+`},

		// ============================================================
		// 2024 / 2025 CVEs and recent exploit classes
		// ============================================================

		// Next.js middleware bypass (CVE-2025-29927)
		{ID: "CVE-2025-29927", Name: "Next.js middleware bypass", Phase: core.PhaseRequestHeaders, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "Next.js x-middleware-subrequest header forging (CVE-2025-29927)", Targets: []string{"headers.x-middleware-subrequest", "headers"}, Pattern: `(?i)middleware(?::middleware)*`},

		// Next.js cache poisoning variants
		{ID: "CVE-2024-34351", Name: "Next.js Server Action SSRF", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 80, Action: core.ActionBlock, Description: "Next.js Server Action host-header SSRF", Targets: []string{"headers.host", "headers.origin"}, Pattern: `(?i)^(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|::1|metadata\.internal)`},

		// PHP CGI argument injection (CVE-2024-4577)
		{ID: "CVE-2024-4577", Name: "PHP CGI argument injection", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "PHP-CGI argv injection via soft-hyphen / %ad (CVE-2024-4577)", Targets: []string{"uri", "args"}, Pattern: `(?i)(?:%ad|\xad|%e2%80%90)-d\+|\?-d\+allow_url_include|\?-d\+auto_prepend_file`},

		// Palo Alto PAN-OS GlobalProtect command injection (CVE-2024-3400)
		{ID: "CVE-2024-3400", Name: "PAN-OS GlobalProtect command inject", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "PAN-OS GlobalProtect SESSID path traversal (CVE-2024-3400)", Targets: []string{"headers.cookie", "headers"}, Pattern: `(?i)SESSID=[^;]*(?:\.\.|%2e%2e|/\./)`},

		// Ivanti Connect Secure auth bypass chain (CVE-2023-46805 + CVE-2024-21887)
		{ID: "CVE-2024-21887", Name: "Ivanti Connect Secure RCE", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "Ivanti Connect Secure /api/v1/license/keys-status path (CVE-2024-21887)", Targets: []string{"uri", "path"}, Pattern: `(?i)/api/v1/(?:totp/user-backup-code|license/keys-status/[^/]*;|system/maintenance/archiving/cloud-server-test-connection)`},

		// Fortinet FortiOS SSL-VPN out-of-bounds write (CVE-2024-21762)
		{ID: "CVE-2024-21762", Name: "FortiOS SSL-VPN OOB write probe", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 80, Action: core.ActionBlock, Description: "Fortinet SSL-VPN /remote/hostcheck_validate probe", Targets: []string{"uri", "path"}, Pattern: `(?i)/remote/hostcheck_(?:validate|save)\b`},

		// JetBrains TeamCity auth bypass (CVE-2024-27198)
		{ID: "CVE-2024-27198", Name: "TeamCity auth bypass", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "TeamCity path-traversal auth bypass (CVE-2024-27198)", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:\.\.|%2e%2e)(?:/|%2f);(?:jsessionid|sid)=[^/]+/(?:app/rest|admin)`},

		// GitLab account takeover (CVE-2023-7028)
		{ID: "CVE-2023-7028", Name: "GitLab password reset takeover", Phase: core.PhaseRequestBody, Category: "cve.2023", Score: 80, Action: core.ActionBlock, Description: "GitLab password reset with array email param (CVE-2023-7028)", Targets: []string{"body", "args"}, Pattern: `(?i)user\[email\]\[\]=.+(?:&|$).*user\[email\]\[\]=`},

		// Citrix NetScaler ADC memory disclosure (CVE-2023-4966, "CitrixBleed")
		{ID: "CVE-2023-4966", Name: "CitrixBleed probe", Phase: core.PhaseRequestHeaders, Category: "cve.2023", Score: 90, Action: core.ActionBlock, Description: "Citrix NetScaler /oauth/idp/.well-known with oversized Host (CVE-2023-4966)", Targets: []string{"uri"}, Pattern: `(?i)/oauth/idp/\.well-known/openid-configuration`},

		// Confluence template injection (CVE-2023-22527)
		{ID: "CVE-2023-22527", Name: "Confluence OGNL template injection", Phase: core.PhaseRequestBody, Category: "cve.2023", Score: 100, Action: core.ActionBlock, Description: "Confluence template OGNL injection (CVE-2023-22527)", Targets: []string{"body", "args"}, Pattern: `(?i)\\u0027\s*\+\s*(?:#[^+]+\.getMethod|@java\.lang|\$\{.*@java)`},

		// XWiki unauthenticated RCE (CVE-2025-24893)
		{ID: "CVE-2025-24893", Name: "XWiki SolrSearch RCE", Phase: core.PhaseRequestHeaders, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "XWiki SolrSearch Groovy injection (CVE-2025-24893)", Targets: []string{"uri", "args"}, Pattern: `(?i)SolrSearch[^?]*\?[^=]*text=[^&]*\{\{async[^}]*\}\}`},

		// Spring Cloud Function RCE (CVE-2022-22963) — still seen in scans
		{ID: "CVE-2022-22963", Name: "Spring Cloud Function SpEL", Phase: core.PhaseRequestHeaders, Category: "cve.2022", Score: 100, Action: core.ActionBlock, Description: "spring.cloud.function.routing-expression header SpEL", Targets: []string{"headers"}, Pattern: `(?i)spring\.cloud\.function\.routing-expression\s*[:=]`},

		// ConnectWise ScreenConnect auth bypass (CVE-2024-1709)
		{ID: "CVE-2024-1709", Name: "ScreenConnect SetupWizard bypass", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "ConnectWise /SetupWizard.aspx path-normalization bypass", Targets: []string{"uri", "path"}, Pattern: `(?i)/SetupWizard\.aspx/[a-z]+`},

		// Veeam Backup RCE (CVE-2024-40711)
		{ID: "CVE-2024-40711", Name: "Veeam Backup RCE probe", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 80, Action: core.ActionBlock, Description: "Veeam backup /triggers SOAP endpoint probe", Targets: []string{"uri"}, Pattern: `(?i)/triggers/v2/.+\?credentialsId=`},

		// Windows CUPS RCE (CVE-2024-47176 / 47076 / 47175 / 47177)
		{ID: "CVE-2024-47176", Name: "CUPS IPP printer injection", Phase: core.PhaseRequestBody, Category: "cve.2024", Score: 90, Action: core.ActionBlock, Description: "CUPS ipp protocol FoomaticRIP injection", Targets: []string{"body"}, Pattern: `(?i)FoomaticRIPCommandLine:\s+`},

		// GeoServer SQL injection (CVE-2023-35042) / RCE (CVE-2024-36401)
		{ID: "CVE-2024-36401", Name: "GeoServer OGC eval", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "GeoServer OGC filter eval injection (CVE-2024-36401)", Targets: []string{"args", "body"}, Pattern: `(?i)exec\s*\(\s*java\.lang\.Runtime|Runtime\.getRuntime\(\)\.exec\(|SystemFunction`},

		// HTTP/2 Rapid Reset — pattern-detected through header probing
		{ID: "HTTP2-RESET-001", Name: "HTTP/2 Rapid Reset probe", Phase: core.PhaseRequestHeaders, Category: "cve.2023", Score: 60, Action: core.ActionLog, Description: "HTTP/2 Rapid Reset (CVE-2023-44487) — very high request rate from single source is caught by DDoS detector; this flags crafted high-concurrency probes", Targets: []string{"headers.user-agent"}, Pattern: `(?i)\brapid[-_]?reset|http2-reset-test`},

		// Next.js / React SSR template injection pattern (operator called this
		// "React2Shell" — covers SSR payload-as-template exploits including
		// React renderToString XSS through user-controlled children)
		{ID: "REACT2SHELL-001", Name: "React SSR payload injection", Phase: core.PhaseRequestBody, Category: "react", Score: 80, Action: core.ActionBlock, Description: "React SSR prop/children with script or dangerouslySetInnerHTML attempt", Targets: []string{"body", "args"}, Pattern: `(?i)dangerouslySetInnerHTML\s*[:=]\s*\{\s*__html\s*:\s*["'` + "`" + `]?\s*<script`},
		{ID: "REACT2SHELL-002", Name: "React Server Component eval", Phase: core.PhaseRequestBody, Category: "react", Score: 80, Action: core.ActionBlock, Description: "RSC payload invoking require/eval through user input", Targets: []string{"body"}, Pattern: `(?i)"\$\$typeof":\s*Symbol\(react\.[^)]*\).{0,200}(?:require|eval|Function)\s*\(`},

		// LangChain / LLM prompt injection markers — for ingress to AI gateways
		{ID: "LLM-001", Name: "Prompt-injection marker", Phase: core.PhaseRequestBody, Category: "llm", Score: 40, Action: core.ActionLog, Description: "Classic prompt-injection prelude in user input", Targets: []string{"body", "args"}, Pattern: `(?i)(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:the\s+)?system\s+prompt|you\s+are\s+now\s+in\s+(?:developer|DAN)\s+mode)`},
		{ID: "LLM-002", Name: "LangChain tool bypass", Phase: core.PhaseRequestBody, Category: "llm", Score: 50, Action: core.ActionBlock, Description: "LangChain / LlamaIndex tool-use exploit patterns", Targets: []string{"body"}, Pattern: `(?i)(?:PythonREPL|PythonAstREPL|ShellTool|RequestsGet|shell\s*:\s*true)\s*\(\s*["'` + "`" + `]?\s*(?:import\s+os|subprocess|__import__|open\(|exec\()`},

		// Hyper-v / Azure / AWS metadata abuse headers
		{ID: "METAHEADER-001", Name: "GCP/Azure metadata header", Phase: core.PhaseRequestHeaders, Category: "cloud", Score: 60, Action: core.ActionBlock, Description: "Metadata-Flavor / X-Forwarded-Host pointing at metadata svc", Targets: []string{"headers.metadata-flavor", "headers.x-metadata", "headers.x-identity-full"}, Pattern: `(?i).+`},

		// Mass-assignment / hidden-field tampering (low severity, log)
		{ID: "MASSASSIGN-001", Name: "Role/admin mass-assignment", Phase: core.PhaseRequestBody, Category: "app", Score: 50, Action: core.ActionLog, Description: "Suspicious role / is_admin / permission field in body", Targets: []string{"body"}, Pattern: `(?i)(?:^|[&{,"])["']?(?:is_admin|isAdmin|role|role_id|permissions|privilege|superuser|is_staff)["']?\s*[=:]\s*["']?(?:true|1|admin|root|superuser)`},

		// ============================================================
		// 2025 / 2026 exploits — research-backed
		// ============================================================

		// CVE-2025-55182 "React2Shell" — React Server Components / Next.js
		// prototype-pollution RCE through Flight-protocol deserialization.
		// Exploits pollute Object.prototype.then via "$1:__proto__:then" and
		// gain Function constructor access through "$1:constructor:constructor".
		// Trend Micro, Akamai, and Datadog Security Labs document the
		// payloads; the signature here catches the characteristic
		// "$N:__proto__:" and "$N:constructor:constructor" tokens in bodies.
		{ID: "CVE-2025-55182", Name: "React2Shell RSC RCE", Phase: core.PhaseRequestBody, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "React Server Components prototype-pollution RCE (React2Shell)", Targets: []string{"body", "args"}, Pattern: `\$[0-9a-zA-Z]+:(?:__proto__|constructor):(?:then|constructor)\b`},
		{ID: "CVE-2025-66478", Name: "Next.js RSC RCE (companion)", Phase: core.PhaseRequestBody, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "Next.js RSC deserialization gadget (CVE-2025-66478)", Targets: []string{"body"}, Pattern: `(?i)"\$\d+"\s*:\s*"(?:__proto__|prototype|constructor)"`},

		// CVE-2025-3248 — Langflow /api/v1/validate/code unauthenticated
		// Python RCE via exec() on user-supplied AST. Detects the vulnerable
		// path, and the decorator-based / default-argument payload shapes
		// documented by Zscaler ThreatLabz and Trend Micro.
		{ID: "CVE-2025-3248", Name: "Langflow validate/code RCE", Phase: core.PhaseRequestHeaders, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "Langflow /api/v1/validate/code endpoint abuse (CVE-2025-3248)", Targets: []string{"uri", "path"}, Pattern: `(?i)/api/v1/validate/code\b`},
		{ID: "CVE-2025-3248-B", Name: "Langflow exec payload", Phase: core.PhaseRequestBody, Category: "cve.2025", Score: 90, Action: core.ActionBlock, Description: "Python exec()/subprocess gadget in validate/code body", Targets: []string{"body"}, Pattern: `(?i)@\s*(?:exec|eval|compile|subprocess\.(?:check_output|run|Popen|call))\s*\(|def\s+\w+\s*\([^)]*=\s*(?:exec|eval|subprocess\.|__import__)\s*\(`},

		// CVE-2026-39987 — Marimo /terminal/ws pre-auth websocket RCE.
		// Exploited within 10 hours of disclosure per CISA KEV.
		{ID: "CVE-2026-39987", Name: "Marimo /terminal/ws pre-auth RCE", Phase: core.PhaseRequestHeaders, Category: "cve.2026", Score: 100, Action: core.ActionBlock, Description: "Marimo terminal websocket without auth (CVE-2026-39987)", Targets: []string{"uri", "path"}, Pattern: `(?i)/terminal/ws(?:\?|/|$)`},

		// CVE-2026-21858 — n8n form-upload content-type bypass + LFI → RCE.
		{ID: "CVE-2026-21858", Name: "n8n form upload file-read", Phase: core.PhaseRequestHeaders, Category: "cve.2026", Score: 90, Action: core.ActionBlock, Description: "n8n /form upload content-type manipulation (CVE-2026-21858)", Targets: []string{"uri", "path"}, Pattern: `(?i)/webhook/.+/form-trigger|/form/.+/submit`},

		// CVE-2026-21643 — FortiClient EMS pre-auth SQLi via Site header on
		// /api/v1/init_consts. A single HTTP request is sufficient.
		{ID: "CVE-2026-21643", Name: "FortiClient EMS init_consts SQLi", Phase: core.PhaseRequestHeaders, Category: "cve.2026", Score: 100, Action: core.ActionBlock, Description: "FortiClient EMS /api/v1/init_consts Site-header SQLi (CVE-2026-21643)", Targets: []string{"uri", "path"}, Pattern: `(?i)/api/v1/init_consts\b`},

		// CVE-2026-20122 / CVE-2026-20128 / CVE-2026-20133 — Cisco Catalyst
		// SD-WAN Manager (vManage) API abuse, actively exploited per CISA.
		{ID: "CVE-2026-20122", Name: "Cisco vManage SD-WAN API probe", Phase: core.PhaseRequestHeaders, Category: "cve.2026", Score: 70, Action: core.ActionLog, Description: "Cisco Catalyst SD-WAN Manager dataservice/fileUpload endpoint (CVE-2026-20122)", Targets: []string{"uri", "path"}, Pattern: `(?i)/dataservice/(?:fileUpload|system/device|cluster/[^/]+/restart)`},

		// CVE-2025-54068 — Livewire v3 ≤3.6.3 hydration RCE. Detection
		// signature: the update-payload snapshot with object-type properties
		// that trigger unsafe hydration.
		{ID: "CVE-2025-54068", Name: "Livewire v3 hydration RCE", Phase: core.PhaseRequestBody, Category: "cve.2025", Score: 90, Action: core.ActionBlock, Description: "Livewire v3 component update with object-type hydration gadget (CVE-2025-54068)", Targets: []string{"body"}, Pattern: `(?i)"snapshot"\s*:\s*"(?:[^"]|\\")*\\"s\\":\\"(?:IntBackedEnum|StringBackedEnum|Stringable|Collection|SupportCollection|Enumerable)`},

		// CVE-2025-31161 — CrushFTP S3-auth-header pre-auth admin bypass on
		// /WebInterface/function/. AWS4-HMAC-SHA256 Credential=crushadmin/.
		{ID: "CVE-2025-31161", Name: "CrushFTP auth bypass", Phase: core.PhaseRequestHeaders, Category: "cve.2025", Score: 100, Action: core.ActionBlock, Description: "CrushFTP S3 AWS4-HMAC Credential=crushadmin auth bypass (CVE-2025-31161)", Targets: []string{"headers.authorization", "headers"}, Pattern: `(?i)AWS4-HMAC-SHA256[^\n]*Credential\s*=\s*crushadmin/`},

		// CVE-2024-24919 — Check Point Quantum Gateway /clients/MyCRL
		// arbitrary file read via CSHELL/../../.. traversal.
		{ID: "CVE-2024-24919", Name: "Check Point Quantum Gateway file read", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "Check Point /clients/MyCRL CSHELL/ traversal (CVE-2024-24919)", Targets: []string{"uri", "path", "body"}, Pattern: `(?i)(?:/clients/MyCRL\b|aCSHELL/\.\.|CSHELL/\.\.)`},

		// CVE-2024-50623 / CVE-2024-55956 — Cleo Harmony/VLTrader/LexiCom
		// /Synchronization endpoint arbitrary file write → autorun RCE.
		{ID: "CVE-2024-50623", Name: "Cleo Harmony /Synchronization abuse", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 100, Action: core.ActionBlock, Description: "Cleo MFT /Synchronization arbitrary file write (CVE-2024-50623 / 55956)", Targets: []string{"uri", "path"}, Pattern: `(?i)/Synchronization(?:\?|/|$)`},
		{ID: "CVE-2024-50623-B", Name: "Cleo VLSync header", Phase: core.PhaseRequestHeaders, Category: "cve.2024", Score: 80, Action: core.ActionBlock, Description: "Cleo VLSync command header probe", Targets: []string{"headers.vlsync", "headers"}, Pattern: `(?i)VLSync:\s*(?:ADD|DELETE|REPLACE)\b`},

		// Chrome zero-day (CVE-2026-5281) exploits are binary-level; not
		// directly WAF-addressable, but the associated exploit-kit JS that
		// gets delivered often carries the marker.
		{ID: "CVE-2026-5281-KIT", Name: "Chrome UAF exploit-kit marker", Phase: core.PhaseRequestBody, Category: "cve.2026", Score: 60, Action: core.ActionLog, Description: "Exploit-kit JS referencing Chrome UAF gadgets", Targets: []string{"body"}, Pattern: `(?i)(?:WebGPU|Dawn|ANGLE)Pipeline[^"']{0,40}(?:\.destroy|setBindGroup)\s*\([^)]{0,100}(?:0xffffffff|0x7fffffff|-1\s*\/\s*0)`},

		// === Extended scanner user-agent list from OWASP CRS ===
		// OWASP CRS maintains scanner UAs in scanners-user-agents.data.
		// Adding the high-confidence ones we didn't already have.
		{ID: "SCAN-020", Name: "Arachni / Commix / WhatWaf scanners", Phase: core.PhaseRequestHeaders, Category: "scanner", Score: 50, Action: core.ActionBlock, Description: "OWASP-CRS-aligned scanner UA list (batch 1)", Targets: []string{"headers.user-agent"}, Pattern: `(?i)\b(?:arachni|commix|whatwaf|jbrofuzz|jorgee|fimap|havij|morfeus|webbandit|webshag|wfuzz|whatweb|wprecon|wpscan|feroxbuster|l9explore|l9tcpid|wapiti|vega|appspider|ironwasp|skipfish|qualysguard|n-stalker|cmsmap|sqlninja|xsstrike|xsser|joomscan|droopescan|Ghauri|zmeu|WPProbe|SSTIMap|tplmap|DotDotPwn|shortscan|Kadimus|LFISuite|LFImap|graphw00f|graphql-cop|jSQL|noseyparker|TruffleHog|TInjA|Mozilla/4\.0 \(Hydra\)|Mozilla/5\.g|Panoptic|AppScan|Detectify|BFAC|bewica-security-scan|betabot|hexometer|libwhisker|netlab360|securityagent|sitelockspider|sysscan|TsunamiSecurityScanner|w3af\.org|gobuster|dirbuster|fuzz faster)\b`},

		// === Restricted file-path list from OWASP CRS (restricted-files.data) ===
		// The upstream CRS file is 400+ entries; these are the highest-value
		// paths that frequently appear in scanner probes and opportunistic
		// exploitation. Matched against the canonicalized path.
		{ID: "SCAN-RESTRICTED-001", Name: "Restricted dotfile access", Phase: core.PhaseRequestHeaders, Category: "scanner", Score: 70, Action: core.ActionBlock, Description: "OWASP-CRS: dotfile / secrets-file probe", Targets: []string{"uri", "path"}, Pattern: `(?i)/\.(?:env(?:rc)?|git/(?:config|HEAD|index)|aws/credentials|ssh/(?:id_rsa|authorized_keys)|bash_history|zsh_history|mysql_history|psql_history|npmrc|pypirc|netrc|pgpass|docker/config\.json|kube/config|htpasswd|htaccess|DS_Store|terraform/terraform\.tfstate|git-credentials|gitconfig|gitlab-ci\.yml|travis\.yml|travis\.yaml|ws_ftp\.ini|vscode/settings\.json)\b`},
		{ID: "SCAN-RESTRICTED-002", Name: "Restricted config file probe", Phase: core.PhaseRequestHeaders, Category: "scanner", Score: 60, Action: core.ActionBlock, Description: "OWASP-CRS: config/database/secrets file probe", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:wp-config\.(?:php|bak|old|save)|database\.ya?ml|config/(?:parameters|secrets|database)\.ya?ml|app/etc/(?:env|local)\.(?:php|xml)|sites/default/settings\.(?:php|local\.php)|web\.config|credentials\.json|secrets\.(?:json|ya?ml)|php\.ini|user_secrets\.ya?ml|gitlab\.rb|initial_root_password|composer\.lock|package-lock\.json|yarn\.lock|pm2\.log)\b`},
		{ID: "SCAN-RESTRICTED-003", Name: "Proc/sys sensitive read", Phase: core.PhaseRequestHeaders, Category: "scanner", Score: 80, Action: core.ActionBlock, Description: "OWASP-CRS: /proc or /sys leak probe", Targets: []string{"uri", "path", "args"}, Pattern: `(?i)/proc/(?:self/(?:environ|cmdline|maps|status|fd/)|[0-9]+/(?:environ|cmdline)|meminfo|version|kallsyms|kcore|mounts)|/sys/(?:class|devices|firmware|kernel|module)\b`},
		{ID: "SCAN-RESTRICTED-004", Name: "Java WEB-INF / META-INF", Phase: core.PhaseRequestHeaders, Category: "scanner", Score: 70, Action: core.ActionBlock, Description: "Java webapp internal-path probe", Targets: []string{"uri", "path"}, Pattern: `(?i)/(?:WEB-INF|META-INF)/`},

		// === Extended OWASP CRS coverage ===
		// REQUEST-911 method enforcement — common CRS pattern. Rather than
		// hard-block, log uncommon methods (PATCH/DELETE on unfiltered paths).
		{ID: "CRS-911100", Name: "CRS-aligned unusual method", Phase: core.PhaseRequestHeaders, Category: "crs.method", Paranoia: 2, Score: 20, Action: core.ActionLog, Description: "CRS-aligned: uncommon HTTP verb (SEARCH/TRACE/PROPFIND/etc)", Targets: []string{"method"}, Pattern: `^(?:TRACE|TRACK|DEBUG|SEARCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT|MKACTIVITY|VERSION-CONTROL|CHECKOUT|MERGE|BASELINE-CONTROL)$`},

		// REQUEST-920 — header anomalies that don't require chain joins.
		{ID: "CRS-920450", Name: "CRS Oversized Content-Length", Phase: core.PhaseRequestHeaders, Category: "crs.protocol", Paranoia: 2, Score: 30, Action: core.ActionLog, Description: "Content-Length greater than a sensible digit count", Targets: []string{"headers.content-length"}, Pattern: `^\d{10,}$`},
		{ID: "CRS-920500", Name: "CRS Range header with too many bytes", Phase: core.PhaseRequestHeaders, Category: "crs.protocol", Paranoia: 2, Score: 40, Action: core.ActionBlock, Description: "Range header with too many ranges (amplification abuse)", Targets: []string{"headers.range"}, Pattern: `(?i)bytes=(?:[0-9,\-]+,){6,}`},

		// REQUEST-941 XSS — additional high-value patterns from OWASP CRS.
		{ID: "CRS-941260", Name: "CRS XSS attribute payload", Phase: core.PhaseRequestBody, Category: "crs.xss", Paranoia: 1, Score: 70, Action: core.ActionBlock, Description: "CRS-aligned: srcdoc attribute injection", Targets: []string{"args", "body"}, Pattern: `(?i)<iframe[^>]+srcdoc\s*=\s*["'][^"']*<(?:script|iframe|img|svg|body)`},
		{ID: "CRS-941270", Name: "CRS XSS formaction hijack", Phase: core.PhaseRequestBody, Category: "crs.xss", Paranoia: 1, Score: 70, Action: core.ActionBlock, Description: "formaction attribute with javascript: / data: URL", Targets: []string{"args", "body"}, Pattern: `(?i)formaction\s*=\s*["']?\s*(?:javascript|data|vbscript):`},

		// REQUEST-942 SQLi — additional operators seen in 2025 campaigns.
		{ID: "CRS-942540", Name: "CRS SQL EXTRACTVALUE/XMLTYPE", Phase: core.PhaseRequestBody, Category: "crs.sqli", Paranoia: 1, Score: 80, Action: core.ActionBlock, Description: "Error-based SQLi via EXTRACTVALUE / XMLTYPE / UPDATEXML / XMLTYPE.GETSTRINGVAL", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:extractvalue|updatexml|xmltype|xmltype\.(?:getstringval|getclobval))\s*\(`},
		{ID: "CRS-942550", Name: "CRS SQL JSON extraction abuse", Phase: core.PhaseRequestBody, Category: "crs.sqli", Paranoia: 2, Score: 50, Action: core.ActionBlock, Description: "JSON SQL function abuse (json_extract/json_value/json_query)", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:json_extract|json_value|json_query|json_table|json_keys|openjson)\s*\([^)]*(?:\$|'|"|--)`},

		// Supply-chain / dependency abuse — prototype pollution via body JSON.
		{ID: "PROTO-POLL-001", Name: "Prototype pollution payload", Phase: core.PhaseRequestBody, Category: "app", Score: 70, Action: core.ActionBlock, Description: "JSON body with __proto__ / constructor.prototype polluter", Targets: []string{"body"}, Pattern: `(?i)"(?:__proto__|prototype|constructor)"\s*:\s*\{`},

		// Credential exfil via common header exfil paths (Metadata-Flavor was
		// already there — add broader cloud metadata UA indicators).
		{ID: "CLOUDMETA-002", Name: "Cloud metadata UA exfil", Phase: core.PhaseRequestHeaders, Category: "cloud", Score: 50, Action: core.ActionLog, Description: "User-Agent matching known cloud metadata fetcher libraries", Targets: []string{"headers.user-agent"}, Pattern: `(?i)\b(?:ec2-metadata|gce-metadata|azure-instance-metadata|imds)\b`},
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
// Rules with Paranoia > maxParanoia are skipped so operators can band their
// rule set by false-positive tolerance.
func (rs *RuleSet) Evaluate(phase core.Phase, targets map[string]string, maxScore int) (matches []core.Match, interrupted bool) {
	return rs.EvaluateWithParanoia(phase, targets, maxScore, 4)
}

// EvaluateWithParanoia is Evaluate with an explicit paranoia ceiling.
// Rules with Paranoia==0 are treated as level 1 and always run.
func (rs *RuleSet) EvaluateWithParanoia(phase core.Phase, targets map[string]string, maxScore, maxParanoia int) (matches []core.Match, interrupted bool) {
	if maxParanoia <= 0 {
		maxParanoia = 1
	}
	rs.mu.RLock()
	rules := make([]CompiledRule, 0, len(rs.rules))
	for _, r := range rs.rules {
		pl := r.Paranoia
		if pl <= 0 {
			pl = 1
		}
		if pl > maxParanoia {
			continue
		}
		rules = append(rules, r)
	}
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

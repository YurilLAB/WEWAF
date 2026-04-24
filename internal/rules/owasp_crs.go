package rules

// OWASP Core Rule Set port for WEWAF.
//
// This file ports the detection patterns from the OWASP ModSecurity Core
// Rule Set v4 into WEWAF's rule format. CRS rules are organised by request
// phase and subject area; each group gets a numeric prefix that matches
// the upstream CRS file numbering so operators who already know the
// canonical IDs can map between the two:
//
//   920 — protocol enforcement        (REQUEST-920-PROTOCOL-ENFORCEMENT)
//   921 — protocol attack             (REQUEST-921-PROTOCOL-ATTACK)
//   930 — LFI — local file inclusion  (REQUEST-930-APPLICATION-ATTACK-LFI)
//   931 — RFI — remote file inclusion (REQUEST-931-APPLICATION-ATTACK-RFI)
//   932 — RCE — remote code execution (REQUEST-932-APPLICATION-ATTACK-RCE)
//   933 — PHP injection               (REQUEST-933-APPLICATION-ATTACK-PHP)
//   934 — generic (NodeJS, misc)      (REQUEST-934-APPLICATION-ATTACK-GENERIC)
//   941 — XSS                          (REQUEST-941-APPLICATION-ATTACK-XSS)
//   942 — SQL injection               (REQUEST-942-APPLICATION-ATTACK-SQLI)
//   943 — session fixation            (REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION)
//   944 — Java                         (REQUEST-944-APPLICATION-ATTACK-JAVA)
//   950+ — data leakage / outbound    (RESPONSE-950...)
//
// Paranoia is preserved from upstream (1-4, higher = more aggressive with
// higher false-positive risk). The engine filters by cfg.ParanoiaLevel so
// operators can start at PL1 and ratchet up as they tune.
//
// Patterns are WEWAF-friendly RE2 regexes (no lookahead/backreferences);
// where upstream CRS relied on SecLang features that RE2 can't express, the
// pattern has been rewritten to match the same attack class with a
// comparable rule-of-thumb on false positives. The Description field notes
// when a rule is "CRS-adapted" vs "CRS-derived" vs "CRS-aligned".

import "wewaf/internal/core"

// CRSRules returns the curated OWASP CRS rule pack. Callers concatenate
// this with DefaultRules() when cfg.CRSEnabled is true.
func CRSRules() []core.Rule {
	return []core.Rule{
		// ============================================================
		// REQUEST-920: Protocol Enforcement (PL1-PL2)
		// ============================================================
		{ID: "CRS-920100", Name: "CRS Invalid HTTP Request Line", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 50, Action: core.ActionBlock, Description: "CRS-adapted: malformed request line", Targets: []string{"method"}, Pattern: `(?i)^(?:[^a-z]|$)`},
		{ID: "CRS-920120", Name: "CRS Malicious Multipart Filename", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.protocol", Score: 50, Action: core.ActionBlock, Description: "CRS-derived: multipart filename with null / CRLF / path traversal", Targets: []string{"body"}, Pattern: `(?i)filename\s*=\s*"[^"]*(?:\x00|\\r|\\n|\.\./)`},
		{ID: "CRS-920121", Name: "CRS Multipart Quote Mismatch", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.protocol", Score: 30, Action: core.ActionBlock, Description: "CRS-derived: unmatched quotes in Content-Disposition", Targets: []string{"body"}, Pattern: `(?i)Content-Disposition:[^\r\n]*filename\s*=\s*(?:[^"'\s]\S*[ \t]|'[^']*$|"[^"]*$)`},
		{ID: "CRS-920160", Name: "CRS Content-Length Not Numeric", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 50, Action: core.ActionBlock, Description: "CRS: Content-Length is not a number", Targets: []string{"headers.Content-Length"}, Pattern: `[^0-9]`},
		{ID: "CRS-920170", Name: "CRS GET with Body", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 20, Action: core.ActionLog, Description: "CRS-derived: GET/HEAD carrying a body", Targets: []string{"headers.Transfer-Encoding"}, Pattern: `(?i)\bchunked\b`},
		// CRS-920180 was removed in 2026-04 — as a pure-regex match on
		// method alone it fires on every single POST/PUT/PATCH request.
		// The upstream CRS rule uses SecLang chaining across method +
		// Content-Length + Transfer-Encoding, which our regex-only engine
		// can't express. Until the engine learns to join targets, this
		// check stays off.
		{ID: "CRS-920190", Name: "CRS Range: Invalid", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 40, Action: core.ActionBlock, Description: "CRS: Range header with invalid specifier", Targets: []string{"headers.Range"}, Pattern: `(?i)bytes=(?:[^0-9,-]|\d*-\d*,\s*\d*-\d*,\s*\d*-\d*,\s*\d*-\d*,\s*\d*-\d*,\s*\d*-)`},
		{ID: "CRS-920210", Name: "CRS Multiple/Conflicting Connection", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 50, Action: core.ActionBlock, Description: "CRS: conflicting Connection header values", Targets: []string{"headers.Connection"}, Pattern: `(?i),.*(?:close|keep-alive).*,`},
		{ID: "CRS-920220", Name: "CRS URL Encoding Abuse", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 30, Action: core.ActionBlock, Description: "CRS: invalid URL encoding in URI", Targets: []string{"uri"}, Pattern: `(?i)%(?:[^0-9a-f]|[0-9a-f][^0-9a-f])`},
		{ID: "CRS-920230", Name: "CRS Multiple URL Encoding", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 30, Action: core.ActionBlock, Description: "CRS: multiple URL encodings detected", Targets: []string{"uri"}, Pattern: `%25(?:[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})`},
		{ID: "CRS-920240", Name: "CRS URL Encoding Overlong", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 40, Action: core.ActionBlock, Description: "CRS: UTF-8 overlong encoding", Targets: []string{"uri"}, Pattern: `%[cC][01]%[89abAB][0-9a-fA-F]|%[eE]0%[89abAB][0-9a-fA-F]`},
		{ID: "CRS-920260", Name: "CRS Unicode Abuse", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 40, Action: core.ActionBlock, Description: "CRS: half-width / full-width Unicode abuse", Targets: []string{"uri", "args"}, Pattern: `%u[fF][fF][0-9a-fA-F]{2}`},
		{ID: "CRS-920270", Name: "CRS Invalid Character in Request", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.protocol", Score: 40, Action: core.ActionBlock, Description: "CRS: invalid character in request line", Targets: []string{"uri"}, Pattern: `[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`},
		{ID: "CRS-920280", Name: "CRS Missing Host Header", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 30, Action: core.ActionLog, Description: "CRS: Host header absent", Targets: []string{"headers.Host"}, Pattern: `^$`},
		{ID: "CRS-920290", Name: "CRS Empty Host Header", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 30, Action: core.ActionLog, Description: "CRS: Host header empty", Targets: []string{"headers.Host"}, Pattern: `^\s*$`},
		{ID: "CRS-920300", Name: "CRS Request Missing Accept", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 15, Action: core.ActionLog, Description: "CRS: no Accept header (scanner trait)", Targets: []string{"headers.Accept"}, Pattern: `^$`},
		{ID: "CRS-920320", Name: "CRS Missing User-Agent", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 20, Action: core.ActionLog, Description: "CRS: no User-Agent (automation trait)", Targets: []string{"headers.User-Agent"}, Pattern: `^$`},
		{ID: "CRS-920330", Name: "CRS Empty User-Agent", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 20, Action: core.ActionLog, Description: "CRS: User-Agent present but empty", Targets: []string{"headers.User-Agent"}, Pattern: `^\s*$`},
		// CRS-920340 was removed in 2026-04 — as a pure-regex match on
		// Content-Length alone, it fires on every request with a body.
		// Same structural-join problem as 920180.
		{ID: "CRS-920350", Name: "CRS Host Header is Numeric IP", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.protocol", Score: 20, Action: core.ActionLog, Description: "CRS: Host header is an IP address (automation trait)", Targets: []string{"headers.Host"}, Pattern: `^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$`},
		{ID: "CRS-920370", Name: "CRS Max Num Args Exceeded", Phase: core.PhaseRequestHeaders, Paranoia: 3, Category: "crs.protocol", Score: 25, Action: core.ActionLog, Description: "CRS: abnormal number of query args", Targets: []string{"uri"}, Pattern: `(?:[?&][^=&]+=){50,}`},
		{ID: "CRS-920380", Name: "CRS Arg Name Too Long", Phase: core.PhaseRequestHeaders, Paranoia: 3, Category: "crs.protocol", Score: 20, Action: core.ActionLog, Description: "CRS: query arg name longer than 100 chars", Targets: []string{"uri"}, Pattern: `[?&][^=&]{100,}=`},

		// ============================================================
		// REQUEST-921: Protocol Attack (PL1-PL3)
		// ============================================================
		{ID: "CRS-921110", Name: "CRS HTTP Request Smuggling", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.smuggling", Score: 100, Action: core.ActionBlock, Description: "CRS: HTTP smuggling attempt in body", Targets: []string{"body"}, Pattern: `(?im)(?:\r\n|\n|\r)(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+/`},
		{ID: "CRS-921120", Name: "CRS HTTP Response Splitting", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.smuggling", Score: 100, Action: core.ActionBlock, Description: "CRS: CRLF injection in argument", Targets: []string{"args", "uri"}, Pattern: `(?:\r\n|\n\r?|%0[dD]%0[aA]|%5[cC]r%5[cC]n).*?(?:HTTP/\d|Location:|Set-Cookie:|Content-Type:)`},
		{ID: "CRS-921130", Name: "CRS Response Splitting in Header", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.smuggling", Score: 100, Action: core.ActionBlock, Description: "CRS: CRLF in header value", Targets: []string{"headers"}, Pattern: `[\r\n]|%0[dD]%0[aA]`},
		{ID: "CRS-921140", Name: "CRS Header Injection via payload", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.smuggling", Score: 80, Action: core.ActionBlock, Description: "CRS: injection of HTTP headers via user input", Targets: []string{"args", "body"}, Pattern: `(?i)(?:\r\n|\n|%0a|%0d)+\s*(?:Set-Cookie|Location|Content-Type|Content-Length|Transfer-Encoding)\s*:`},
		// CRS-921150 was removed in 2026-04 — the old regex
		// `(?:[?&]([^=&]+)=[^&]*){2,}` doesn't detect parameter pollution,
		// it just matches any URL with two or more query parameters.
		// Proper HPP detection needs a backreference to the captured name
		// (which RE2 doesn't support) or engine-level logic. Until one of
		// those lands, rely on CRS-921170 (body-side repetition) and
		// application-layer framework protections.
		{ID: "CRS-921160", Name: "CRS Header Injection Body", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.smuggling", Score: 80, Action: core.ActionBlock, Description: "CRS: header injection via request body", Targets: []string{"body"}, Pattern: `(?i)(?:\r\n|\n|%0a|%0d)+\s*(?:Set-Cookie|Location|Transfer-Encoding)\s*:`},
		{ID: "CRS-921170", Name: "CRS HTTP Parameter Pollution", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.smuggling", Score: 30, Action: core.ActionLog, Description: "CRS-adapted: 3+ repeated arg markers in body (HPP heuristic)", Targets: []string{"body"}, Pattern: `(?:(?:^|&)[^=&]+=[^&]*){6,}`},
		{ID: "CRS-921180", Name: "CRS HTTP Parameter Pollution Headers", Phase: core.PhaseRequestHeaders, Paranoia: 3, Category: "crs.smuggling", Score: 20, Action: core.ActionLog, Description: "CRS: duplicate headers attacker could smuggle through", Targets: []string{"headers"}, Pattern: `(?i)(?:content-length|content-type|host|transfer-encoding)[^\n]*\n[^\n]*(?i:content-length|content-type|host|transfer-encoding):`},

		// ============================================================
		// REQUEST-930: LFI (PL1-PL2)
		// ============================================================
		{ID: "CRS-930100", Name: "CRS Path Traversal Unicode", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.lfi", Score: 80, Action: core.ActionBlock, Description: "CRS: Unicode/encoded path traversal", Targets: []string{"uri", "args", "body"}, Pattern: `(?i)(?:%2e|%c0%ae|%c1%9c|\\u002e){2}[/\\]|(?:%2e){2}[/\\]|\.{2}(?:/|%2f|%5c|\\\\)`},
		{ID: "CRS-930110", Name: "CRS Path Traversal (basic)", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.lfi", Score: 80, Action: core.ActionBlock, Description: "CRS: basic ../ path traversal", Targets: []string{"uri", "args", "body"}, Pattern: `(?i)(?:\.\.[/\\])+`},
		{ID: "CRS-930120", Name: "CRS OS File Access", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.lfi", Score: 80, Action: core.ActionBlock, Description: "CRS: direct access to OS sensitive files", Targets: []string{"uri", "args"}, Pattern: `(?i)/(?:etc/(?:passwd|shadow|group|hosts|shells|resolv\.conf)|proc/self/(?:environ|status|maps)|sys/class|boot\.ini|windows/win\.ini|windows/system32/drivers/etc/hosts)\b`},
		{ID: "CRS-930130", Name: "CRS Restricted File Access", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.lfi", Score: 70, Action: core.ActionBlock, Description: "CRS: access to restricted application files", Targets: []string{"uri"}, Pattern: `(?i)\.(?:htaccess|htpasswd|ini|log|pem|key|crt|config|sql|bak|backup|swp|env|DS_Store)\b`},

		// ============================================================
		// REQUEST-931: RFI (PL1-PL2)
		// ============================================================
		{ID: "CRS-931100", Name: "CRS RFI by IP", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rfi", Score: 100, Action: core.ActionBlock, Description: "CRS: RFI attempt with numeric IP", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:https?|ftp|php):\/\/\d{1,3}(?:\.\d{1,3}){3}[:/]`},
		{ID: "CRS-931110", Name: "CRS RFI common parameter", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rfi", Score: 100, Action: core.ActionBlock, Description: "CRS: RFI in classic include params", Targets: []string{"args"}, Pattern: `(?i)(?:^|&|\?)(?:include|require|file|path|url|template|page|view|doc)=(?:https?|ftp|php|data):\/\/`},
		{ID: "CRS-931120", Name: "CRS RFI with ?", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rfi", Score: 60, Action: core.ActionBlock, Description: "CRS: RFI URL with trailing question mark", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:https?|ftp)://[^\s?#]+\?[^\s&]*\?`},
		{ID: "CRS-931130", Name: "CRS Off-Domain RFI", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rfi", Score: 70, Action: core.ActionBlock, Description: "CRS: RFI to known bad TLDs", Targets: []string{"args", "body"}, Pattern: `(?i)\bhttps?://[^/\s]+\.(?:ru|cn|su|xyz|top|bid)/`},

		// ============================================================
		// REQUEST-932: RCE (PL1-PL3)
		// ============================================================
		// CRS-932100 — tightened to require a command + an argument marker
		// (flag, path, redirection, quoting). The upstream CRS rule relies on
		// ModSecurity's @pm + SecLang chaining; ported as pure regex it would
		// false-positive on "who is last?", "please cp this", "find users",
		// etc. Requiring an argument after the command eliminates the vast
		// majority of those FPs without weakening real-attack coverage (a
		// payload like `;cat /etc/passwd` still matches, but a comment
		// containing the word "cat" no longer does).
		{ID: "CRS-932100", Name: "CRS Unix Command Injection", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rce", Score: 100, Action: core.ActionBlock, Description: "CRS-adapted: Unix shell command + argument marker", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:^|[;&|` + "`" + `$(])\s*(?:bash|sh|ksh|csh|zsh|dash|nc|ncat|netcat|wget|curl|telnet|ssh|tftp|nslookup|dig|whoami|uname|cat|awk|sed|grep|find|xargs|killall|sudo|chmod|chown|mkfs|fdisk|umount|lsof|netstat|ifconfig|iptables|nmap|traceroute|useradd|usermod|passwd|mkpasswd)\b\s*(?:-[a-zA-Z]|/[a-z]|\$|\\|<|>|"|'|\||&)`},
		{ID: "CRS-932105", Name: "CRS Unix RCE Command Chain", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rce", Score: 80, Action: core.ActionBlock, Description: "CRS: suspicious shell chain operators", Targets: []string{"args", "body"}, Pattern: `(?i)(?:&&|\|\||;|\|)\s*(?:/bin/|/usr/bin/|/sbin/|/tmp/|/var/|\./)`},
		// Windows command injection — require command + flag/pipe/arg so
		// common English tokens ("net", "reg", "ping") don't false-positive.
		{ID: "CRS-932110", Name: "CRS Windows Command Injection", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rce", Score: 100, Action: core.ActionBlock, Description: "CRS-adapted: Windows shell command + argument marker", Targets: []string{"args", "body"}, Pattern: `(?i)(?:^|[;&|` + "`" + `$(])\s*(?:cmd|powershell|pwsh|tasklist|sc|reg|systeminfo|taskkill|bcdedit|wmic|certutil|mshta|cscript|wscript|vssadmin|fsutil)\b\s*(?:/[a-zA-Z]|-[a-zA-Z]|\$|\\|<|>|"|'|\|)`},
		{ID: "CRS-932115", Name: "CRS Windows cmd /c chain", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rce", Score: 90, Action: core.ActionBlock, Description: "CRS: cmd.exe /c with command", Targets: []string{"args", "body"}, Pattern: `(?i)cmd(?:\.exe)?\s*/[ckr]\s+\S`},
		{ID: "CRS-932120", Name: "CRS PowerShell Command Found", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rce", Score: 100, Action: core.ActionBlock, Description: "CRS: PowerShell cmdlet patterns", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:invoke-(?:expression|command|webrequest|mimikatz|restmethod)|iex|new-object\s+net\.webclient|downloadstring|downloadfile|bypass\s+-ep|encodedcommand)\b`},
		{ID: "CRS-932130", Name: "CRS Unix Shell Expression", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rce", Score: 70, Action: core.ActionBlock, Description: "CRS: shell command substitution operators", Targets: []string{"args", "body"}, Pattern: `\$\([^)]*\)|` + "`" + `[^` + "`" + `]*` + "`" + `|\$\{[^}]*\}`},
		{ID: "CRS-932140", Name: "CRS Windows FOR command", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.rce", Score: 70, Action: core.ActionBlock, Description: "CRS: Windows FOR /F command", Targets: []string{"args", "body"}, Pattern: `(?i)\bfor\s+/[fFdDlLrR]\s`},
		{ID: "CRS-932150", Name: "CRS Bash Shellshock", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rce", Score: 100, Action: core.ActionBlock, Description: "CRS: Shellshock (CVE-2014-6271)", Targets: []string{"headers", "args"}, Pattern: `\(\s*\)\s*\{\s*:\s*;\s*\}\s*;`},
		{ID: "CRS-932160", Name: "CRS Remote Shell Spawn", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.rce", Score: 100, Action: core.ActionBlock, Description: "CRS: reverse/bind shell payload", Targets: []string{"args", "body"}, Pattern: `(?i)(?:bash\s+-i\s*>&|sh\s+-i\s*<&|mkfifo|0<&[12]|\bexec\s+\d+<>/dev/tcp/|nc(?:\.exe)?\s+[^\s]+\s+\d+\s+-e\s)`},
		{ID: "CRS-932170", Name: "CRS RCE by IFS", Phase: core.PhaseRequestHeaders, Paranoia: 3, Category: "crs.rce", Score: 60, Action: core.ActionBlock, Description: "CRS: ${IFS} evasion", Targets: []string{"args", "body"}, Pattern: `(?i)\$\{IFS\}`},

		// ============================================================
		// REQUEST-933: PHP Injection (PL1-PL3)
		// ============================================================
		{ID: "CRS-933100", Name: "CRS PHP Open Tag", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 70, Action: core.ActionBlock, Description: "CRS: PHP open tag in request body", Targets: []string{"args", "body"}, Pattern: `<\?(?:php|=)?`},
		{ID: "CRS-933110", Name: "CRS PHP Script File Upload", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 80, Action: core.ActionBlock, Description: "CRS: PHP file upload by extension", Targets: []string{"body"}, Pattern: `(?i)filename\s*=\s*"[^"]*\.(?:php[3457s]?|phtml|phar|inc|ph[pt]|pl|py|jsp|asp[xh]?|cgi|sh|exe|bat|cmd)"`},
		{ID: "CRS-933120", Name: "CRS PHP Config Directive", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 70, Action: core.ActionBlock, Description: "CRS: PHP ini directive injection", Targets: []string{"args", "body"}, Pattern: `(?i)(?:allow_url_(?:include|fopen)|auto_prepend_file|auto_append_file|disable_functions|open_basedir|safe_mode)\s*=`},
		{ID: "CRS-933130", Name: "CRS PHP Magic Variables", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.php", Score: 60, Action: core.ActionBlock, Description: "CRS: PHP superglobals in user input", Targets: []string{"args", "body"}, Pattern: `(?i)\$(?:GLOBALS|_(?:GET|POST|COOKIE|SESSION|REQUEST|SERVER|ENV|FILES))\b`},
		{ID: "CRS-933140", Name: "CRS PHP IO Stream Wrapper", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 80, Action: core.ActionBlock, Description: "CRS: PHP stream wrappers (php://, data://, expect://)", Targets: []string{"args", "body"}, Pattern: `(?i)(?:php|data|expect|phar|zip|compress\.(?:zlib|bzip2)|ogg|ssh2|rar|zlib):\/{0,2}`},
		{ID: "CRS-933150", Name: "CRS PHP High-Risk Function", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 80, Action: core.ActionBlock, Description: "CRS: dangerous PHP functions", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:eval|assert|create_function|system|exec|passthru|popen|proc_open|shell_exec|pcntl_exec|call_user_func(?:_array)?|include(?:_once)?|require(?:_once)?|preg_replace[^(]*\/e|base64_decode|gzinflate|str_rot13)\s*\(`},
		{ID: "CRS-933160", Name: "CRS PHP Low-Value Function", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.php", Score: 40, Action: core.ActionBlock, Description: "CRS: less-critical PHP functions used in attack chains", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:phpinfo|get_(?:defined_functions|current_user|cfg_var)|ini_(?:get|set|restore)|posix_(?:kill|mkfifo|setuid)|apache_(?:child_terminate|setenv)|error_reporting|parse_str|array_map|array_filter|array_walk|array_walk_recursive|array_reduce|dl)\s*\(`},
		{ID: "CRS-933170", Name: "CRS PHP Object Injection", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.php", Score: 80, Action: core.ActionBlock, Description: "CRS: PHP serialize/unserialize payload", Targets: []string{"args", "body"}, Pattern: `(?i)O:\d+:"\w+":\d+:\{|C:\d+:"\w+":\d+:\{`},
		{ID: "CRS-933180", Name: "CRS PHP Variable Function", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.php", Score: 60, Action: core.ActionBlock, Description: "CRS: $foo() variable function call", Targets: []string{"args", "body"}, Pattern: `\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(`},
		{ID: "CRS-933190", Name: "CRS PHP Closing Tag", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.php", Score: 50, Action: core.ActionBlock, Description: "CRS: PHP closing tag in input", Targets: []string{"args", "body"}, Pattern: `\?>`},

		// ============================================================
		// REQUEST-934: Generic / NodeJS (PL1-PL3)
		// ============================================================
		{ID: "CRS-934100", Name: "CRS NodeJS Injection", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.generic", Score: 80, Action: core.ActionBlock, Description: "CRS: Node.js eval / require / Function", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:require\s*\(|process\.(?:env|exit|mainModule|binding)|child_process|fs\.(?:readFile|writeFile|unlink)|global\.(?:process|require)|Function\s*\(|setTimeout\s*\(\s*["'` + "`" + `]|eval\s*\()`},
		{ID: "CRS-934110", Name: "CRS SSRF Metadata", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.generic", Score: 100, Action: core.ActionBlock, Description: "CRS: cloud metadata IP in argument", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.(?:azure|oracle)\.com)`},
		{ID: "CRS-934120", Name: "CRS SSRF file schemes", Phase: core.PhaseRequestHeaders, Paranoia: 1, Category: "crs.generic", Score: 80, Action: core.ActionBlock, Description: "CRS: file:, gopher:, dict: schemes", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:file|gopher|dict|ldap|ftp|jar|netdoc|tftp|smb):\/\/`},
		{ID: "CRS-934130", Name: "CRS Prototype Pollution", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.generic", Score: 80, Action: core.ActionBlock, Description: "CRS: __proto__ / constructor.prototype injection", Targets: []string{"args", "body"}, Pattern: `(?i)(?:__proto__|constructor\s*\[\s*["']prototype["']|\bprototype\b\s*\[\s*["'])`},

		// ============================================================
		// REQUEST-941: XSS (PL1-PL3)
		// ============================================================
		// Tightened: bare "javascript:" / "data:text/html" fires on prose
		// like "use javascript: it's powerful". Require HTML-tag prefix so
		// we actually need a script tag or attribute context to match.
		{ID: "CRS-941100", Name: "CRS XSS Attack via libinjection", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS-adapted: XSS tag/handler/URL-attribute injection", Targets: []string{"args", "body"}, Pattern: `(?i)(?:<script\b|<iframe\b|<embed\b|<object\b|<svg\b[^>]*on|<img[^>]+onerror\s*=|(?:href|src|action|url|formaction)\s*=\s*["']?\s*(?:javascript|vbscript|data):)`},
		{ID: "CRS-941110", Name: "CRS XSS Filter 1", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS: script tag attack", Targets: []string{"args", "body"}, Pattern: `(?i)<script[^>]*>[\s\S]*?(?:</script>|$)`},
		{ID: "CRS-941120", Name: "CRS XSS Filter 2", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS: event handler attribute", Targets: []string{"args", "body"}, Pattern: `(?i)\bon(?:abort|activate|beforeactivate|beforecopy|beforecut|beforedeactivate|beforeeditfocus|beforepaste|beforeprint|beforeunload|begin|blur|bounce|cellchange|change|click|contextmenu|controlselect|copy|cut|dblclick|deactivate|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|end|error|errorupdate|filterchange|finish|focus|focusin|focusout|help|input|keydown|keypress|keyup|layoutcomplete|load|losecapture|mediacomplete|mediaerror|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|move|moveend|movestart|outofsync|paste|pause|progress|propertychange|readystatechange|repeat|reset|resize|resizeend|resizestart|resume|reverse|rowenter|rowexit|rowsdelete|rowsinserted|scroll|seek|select|selectionchange|selectstart|start|stop|submit|syncrestored|timeerror|trackchange|unload|urlflip)\s*=`},
		// XSS protocol handler — original CRS pattern was too loose, matching
		// any sentence like "javascript: it's powerful". Tightened to require
		// URL-attribute context (href=/src=/url= or quoted context) so
		// "javascript:" has to actually look like a URL, not prose.
		{ID: "CRS-941130", Name: "CRS XSS Filter 3", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS-adapted: javascript:/vbscript:/data: URL in attribute context", Targets: []string{"args", "body"}, Pattern: `(?i)(?:href|src|action|url|formaction|background|poster|xlink:href|data|lowsrc|dynsrc|longdesc)\s*=\s*["']?\s*(?:javascript|vbscript|livescript|mocha|hcp|data):|<\w+[^>]+(?:javascript|vbscript|livescript):[^,]*(?:\(|\)|<|>)`},
		{ID: "CRS-941140", Name: "CRS XSS Filter 4", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS: iframe / frame / object tags", Targets: []string{"args", "body"}, Pattern: `(?i)<(?:iframe|frame|object|embed|applet|frameset|meta)\b`},
		{ID: "CRS-941150", Name: "CRS XSS Filter 5 Base64", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.xss", Score: 60, Action: core.ActionBlock, Description: "CRS: base64 data URI with script", Targets: []string{"args", "body"}, Pattern: `(?i)data:[^,]*;base64,[a-zA-Z0-9+/=]{20,}`},
		{ID: "CRS-941160", Name: "CRS XSS Filter 6 NoScript", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 70, Action: core.ActionBlock, Description: "CRS: NoScript InjectionChecker patterns", Targets: []string{"args", "body"}, Pattern: `(?i)<[^a-z]*(?:s|&#x?0*(?:53|83);?)[^a-z]*(?:c|&#x?0*(?:43|67);?)[^a-z]*(?:r|&#x?0*(?:52|82);?)[^a-z]*(?:i|&#x?0*(?:49|73);?)[^a-z]*(?:p|&#x?0*(?:50|80);?)[^a-z]*(?:t|&#x?0*(?:54|84);?)`},
		{ID: "CRS-941170", Name: "CRS XSS onerror onload", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 80, Action: core.ActionBlock, Description: "CRS: <img onerror> / <body onload> / <svg onload>", Targets: []string{"args", "body"}, Pattern: `(?i)<(?:img|body|svg|video|audio|details|embed|input)[^>]+(?:onerror|onload|onmouseover|onfocus|onclick)\s*=`},
		{ID: "CRS-941180", Name: "CRS XSS Blacklist JS Keywords", Phase: core.PhaseRequestBody, Paranoia: 3, Category: "crs.xss", Score: 40, Action: core.ActionBlock, Description: "CRS: dangerous JS keywords", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:document\.(?:cookie|write|location|URL|referrer|domain|body)|window\.(?:location|open|name)|eval|expression|setInterval|setTimeout|Function|XMLHttpRequest|fetch\s*\(|navigator\.(?:sendBeacon|userAgent))`},
		{ID: "CRS-941190", Name: "CRS XSS using style", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.xss", Score: 50, Action: core.ActionBlock, Description: "CRS: style= with expression/url/behavior", Targets: []string{"args", "body"}, Pattern: `(?i)<[^>]+style\s*=[^>]*(?:expression\s*\(|url\s*\(\s*["']?\s*javascript|behavior\s*:)`},
		{ID: "CRS-941200", Name: "CRS XSS VML 2", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.xss", Score: 50, Action: core.ActionBlock, Description: "CRS: VML namespace with script", Targets: []string{"args", "body"}, Pattern: `(?i)<v:\w+[^>]+xmlns\s*=[^>]+urn:schemas-microsoft-com:vml`},
		{ID: "CRS-941210", Name: "CRS XSS obfuscated", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.xss", Score: 60, Action: core.ActionBlock, Description: "CRS: JS obfuscation pattern", Targets: []string{"args", "body"}, Pattern: `(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}|&#x?0*[0-9a-f]+;?\s*&#x?0*[0-9a-f]+;?\s*&#`},
		{ID: "CRS-941220", Name: "CRS XSS using meta tag", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.xss", Score: 60, Action: core.ActionBlock, Description: "CRS: <meta http-equiv=refresh> injection", Targets: []string{"args", "body"}, Pattern: `(?i)<meta[^>]+http-equiv\s*=\s*["']?\s*refresh`},
		{ID: "CRS-941230", Name: "CRS XSS using link tag", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.xss", Score: 50, Action: core.ActionBlock, Description: "CRS: <link> with remote stylesheet", Targets: []string{"args", "body"}, Pattern: `(?i)<link[^>]+(?:href|rel|onload)\s*=`},
		{ID: "CRS-941240", Name: "CRS Possible XSS charset trick", Phase: core.PhaseRequestHeaders, Paranoia: 3, Category: "crs.xss", Score: 30, Action: core.ActionLog, Description: "CRS: UTF-7 charset in Content-Type", Targets: []string{"headers.Content-Type"}, Pattern: `(?i)charset\s*=\s*["']?utf-?7`},

		// ============================================================
		// REQUEST-942: SQLi (PL1-PL3)
		// ============================================================
		{ID: "CRS-942100", Name: "CRS SQLi Basic via libinjection", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: classic SQL tautology patterns", Targets: []string{"args", "body"}, Pattern: `(?i)(?:'\s*or\s+['"0-9]|\bor\s+1\s*=\s*1\b|\bor\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]|\bunion\s+(?:all\s+)?select\b|--\s|#\s|\/\*|;\s*(?:select|insert|update|delete|drop))`},
		{ID: "CRS-942110", Name: "CRS SQLi Benchmark/Sleep", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: time-based SQLi (benchmark / sleep)", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:benchmark\s*\(|sleep\s*\(\s*\d|pg_sleep\s*\(|waitfor\s+delay\s+["']|dbms_lock\.sleep)`},
		// Tightened: plain "like" / "mod" / "div" are common English words
		// that triggered on any prose ("advice is to like"). Require them
		// adjacent to SQL-ish punctuation so a review comment doesn't fire.
		{ID: "CRS-942120", Name: "CRS SQLi Operator", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 40, Action: core.ActionBlock, Description: "CRS-adapted: SQL operator adjacent to quote / percent-wildcard", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:like|rlike|regexp|not\s+like)\s+["']%|\b(?:bitand|bitor|bitxor)\s*\(`},
		{ID: "CRS-942130", Name: "CRS SQLi Tautology", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: SQL boolean tautology", Targets: []string{"args", "body"}, Pattern: `(?i)(?:["'` + "`" + `]?\w+["'` + "`" + `]?\s*(?:=|like|regexp|is\s+null|is\s+not\s+null)\s*["'` + "`" + `]?\w+["'` + "`" + `]?\s*(?:--|#|\/\*))`},
		{ID: "CRS-942140", Name: "CRS SQLi Database Names", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 60, Action: core.ActionBlock, Description: "CRS: common DB schema names", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:information_schema|mysql\.user|sys\.(?:syscolumns|objects|tables|dm_exec)|pg_catalog|master\.\.sysdatabases|sqlite_master|all_tables|user_tables)\b`},
		{ID: "CRS-942150", Name: "CRS SQLi Functions", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 50, Action: core.ActionBlock, Description: "CRS: SQL functions used for fingerprinting", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:concat|concat_ws|group_concat|char|ascii|hex|unhex|ord|database|user|current_user|version|@@version|connection_id|last_insert_id|load_file|into\s+outfile|into\s+dumpfile|extractvalue|updatexml)\s*\(`},
		{ID: "CRS-942160", Name: "CRS SQLi Sleep/Benchmark Expressions", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: time-based in conditional", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:and|or|\bif\s*\(|\bcase\s+when)\b[^;]*(?:benchmark|sleep|pg_sleep|waitfor|dbms_lock)`},
		{ID: "CRS-942170", Name: "CRS SQLi Column Enum", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 50, Action: core.ActionBlock, Description: "CRS: UNION SELECT column enumeration", Targets: []string{"args", "body"}, Pattern: `(?i)\bunion\b(?:\s+all)?\s+select\b[\s\S]{0,200}\b(?:from|where|limit)\b`},
		{ID: "CRS-942180", Name: "CRS Basic SQLi Auth Bypass", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: auth bypass patterns", Targets: []string{"args", "body"}, Pattern: `(?i)'\s*or\s+'[^']*'\s*=\s*'|"\s*or\s+"[^"]*"\s*=\s*"|admin['"]\s*(?:--|#|/\*)`},
		{ID: "CRS-942190", Name: "CRS SQLi Comment Evasion", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 50, Action: core.ActionBlock, Description: "CRS: SQL comment-based evasion", Targets: []string{"args", "body"}, Pattern: `(?i)\/\*![0-9]*\s*[a-z]`},
		{ID: "CRS-942200", Name: "CRS SQLi MySQL Comment", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 40, Action: core.ActionBlock, Description: "CRS: MySQL inline comment /*! */", Targets: []string{"args", "body"}, Pattern: `\/\*!.*?\*\/`},
		{ID: "CRS-942210", Name: "CRS SQLi Chained Statements", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 60, Action: core.ActionBlock, Description: "CRS: stacked SQL query", Targets: []string{"args", "body"}, Pattern: `(?i);\s*(?:select|insert|update|delete|drop|create|alter|rename|exec|execute|xp_\w+)\b`},
		{ID: "CRS-942220", Name: "CRS SQLi MS-SQL xp_cmdshell", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 100, Action: core.ActionBlock, Description: "CRS: xp_cmdshell / sp_OACreate", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:xp_cmdshell|xp_regread|xp_execresultset|sp_OACreate|sp_OAMethod|sp_OAGetProperty|sp_OASetProperty)\b`},
		{ID: "CRS-942230", Name: "CRS SQLi MySQL UDF", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.sqli", Score: 80, Action: core.ActionBlock, Description: "CRS: MySQL UDF exploitation", Targets: []string{"args", "body"}, Pattern: `(?i)\b(?:sys_eval|sys_exec|do_system)\s*\(`},
		{ID: "CRS-942240", Name: "CRS SQLi MySQL Charset", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.sqli", Score: 50, Action: core.ActionBlock, Description: "CRS: MySQL charset manipulation", Targets: []string{"args", "body"}, Pattern: `(?i)(?:convert_tz|@@character_set|alter\s+database.+charset)`},

		// ============================================================
		// REQUEST-943: Session Fixation (PL1-PL2)
		// ============================================================
		{ID: "CRS-943100", Name: "CRS Session Fixation", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.session", Score: 40, Action: core.ActionBlock, Description: "CRS: cookie/session-id value in POST body", Targets: []string{"args", "body"}, Pattern: `(?i)(?:sessionid|phpsessid|jsessionid|aspsessionid|sid|session_id)\s*=\s*\w{8,}`},
		{ID: "CRS-943110", Name: "CRS Session Fix Referer", Phase: core.PhaseRequestHeaders, Paranoia: 2, Category: "crs.session", Score: 30, Action: core.ActionLog, Description: "CRS: Referer with session id", Targets: []string{"headers.Referer"}, Pattern: `(?i)[?&](?:phpsessid|jsessionid|aspsessionid|sid)=`},

		// ============================================================
		// REQUEST-944: Java (PL1-PL2)
		// ============================================================
		{ID: "CRS-944100", Name: "CRS Java Method Call", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.java", Score: 80, Action: core.ActionBlock, Description: "CRS: Java Runtime.getRuntime.exec / ProcessBuilder", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)\b(?:java\.lang\.(?:Runtime|ProcessBuilder|System)|Runtime\.getRuntime\s*\(\s*\)\.exec|new\s+ProcessBuilder|Class\.forName|javax\.script|ScriptEngineManager)\b`},
		{ID: "CRS-944110", Name: "CRS Java Serialization", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.java", Score: 80, Action: core.ActionBlock, Description: "CRS: Java serialized object marker", Targets: []string{"args", "body", "headers"}, Pattern: `(?:aced0005|rO0[A-Z]|H4sIA)`},
		{ID: "CRS-944120", Name: "CRS Java OGNL Injection", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.java", Score: 100, Action: core.ActionBlock, Description: "CRS: OGNL / Struts expression", Targets: []string{"args", "body", "headers"}, Pattern: `(?i)(?:%\{[^}]*(?:#_memberAccess|#context|#request|#response|@java\.)|\$\{[^}]*(?:@java\.lang|T\())`},
		{ID: "CRS-944130", Name: "CRS Log4Shell JNDI", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.java", Score: 100, Action: core.ActionBlock, Description: "CRS: Log4j JNDI lookup", Targets: []string{"args", "body", "headers", "uri"}, Pattern: `(?i)\$\{(?:jndi|\$\{::-j\}\$\{::-n\}\$\{::-d\}\$\{::-i\})[\s:]`},
		{ID: "CRS-944140", Name: "CRS Spring4Shell", Phase: core.PhaseRequestBody, Paranoia: 1, Category: "crs.java", Score: 100, Action: core.ActionBlock, Description: "CRS: Spring4Shell ClassLoader", Targets: []string{"args", "body"}, Pattern: `(?i)class\.(?:module\.classLoader|classLoader\.(?:resources\.context|DefaultAssertionStatus))`},
		{ID: "CRS-944150", Name: "CRS Java Class Import", Phase: core.PhaseRequestBody, Paranoia: 2, Category: "crs.java", Score: 50, Action: core.ActionBlock, Description: "CRS: Java class import in input", Targets: []string{"args", "body"}, Pattern: `(?i)\bimport\s+java\.(?:io|lang|net|util|script|beans)\.`},

		// ============================================================
		// RESPONSE-950+: Data Leakage (runs on response body)
		// ============================================================
		{ID: "CRS-950100", Name: "CRS Response PHP Error", Phase: core.PhaseResponseBody, Paranoia: 1, Category: "crs.leak", Score: 30, Action: core.ActionLog, Description: "CRS: PHP error in response leaks path", Targets: []string{"response_body"}, Pattern: `(?i)(?:<b>(?:Warning|Notice|Fatal error|Parse error)</b>|Call\s+to\s+undefined\s+function|Stack trace:\s*\n|/home/[^/]+/public_html/)`},
		{ID: "CRS-950110", Name: "CRS Response SQL Error", Phase: core.PhaseResponseBody, Paranoia: 1, Category: "crs.leak", Score: 50, Action: core.ActionLog, Description: "CRS: SQL engine error leaked in response", Targets: []string{"response_body"}, Pattern: `(?i)(?:you have an error in your sql syntax|warning:\s*mysqli?_|ORA-\d{4,5}|PG::\w+Error|unclosed quotation mark|Microsoft SQL Server|SQLServer JDBC Driver|Warning:\s*pg_|ODBC SQL Server Driver)`},
		{ID: "CRS-950120", Name: "CRS Response Java Stack", Phase: core.PhaseResponseBody, Paranoia: 1, Category: "crs.leak", Score: 30, Action: core.ActionLog, Description: "CRS: Java stack trace leaked", Targets: []string{"response_body"}, Pattern: `(?i)(?:java\.lang\.\w+Exception|at\s+[a-z]+(?:\.[a-z]+)+\([A-Za-z]+\.java:\d+\)|Caused by:\s*[a-z]+(?:\.[a-z]+)+)`},
		{ID: "CRS-950130", Name: "CRS Response Node Stack", Phase: core.PhaseResponseBody, Paranoia: 1, Category: "crs.leak", Score: 30, Action: core.ActionLog, Description: "CRS: Node.js / .NET stack trace leak", Targets: []string{"response_body"}, Pattern: `(?i)(?:Error:\s+[A-Z][^\n]{0,80}\s+at\s+[^\s]+\s+\(|System\.(?:Exception|NullReferenceException|InvalidOperationException)|at System\.|Microsoft\.\w+\.Exception)`},
		{ID: "CRS-950140", Name: "CRS Response Private Key", Phase: core.PhaseResponseBody, Paranoia: 1, Category: "crs.leak", Score: 100, Action: core.ActionBlock, Description: "CRS: PEM private key in response", Targets: []string{"response_body"}, Pattern: `-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----`},
		{ID: "CRS-950150", Name: "CRS Response Credit Card", Phase: core.PhaseResponseBody, Paranoia: 2, Category: "crs.leak", Score: 60, Action: core.ActionLog, Description: "CRS: credit card-like number in response", Targets: []string{"response_body"}, Pattern: `\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|3(?:0[0-5]|[68]\d)\d{11})\b`},
	}
}

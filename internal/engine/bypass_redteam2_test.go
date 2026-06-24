package engine

import "testing"

// TestBypassVerify_TwigFilterGadget covers SSTI-TWIG-002: the Twig
// filter/map/reduce/sort callback RCE gadget that evaded every existing SSTI
// rule (which key on _self.env / config / __class__ tokens the gadget lacks).
// These are real, DB/host-exploitable Twig PHP-callback RCE primitives.
func TestBypassVerify_TwigFilterGadget(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := map[string]string{
		"filter-system": "{{['id']|filter('system')}}",
		"map-system":    "{{['id',1]|map('system')|join}}",
		"reduce-exec":   "{{[1,2]|reduce('shell_exec')}}",
		"sort-passthru": "{{['whoami']|sort('passthru')}}",
		"map-dq":        `{{['id']|map("system")}}`,
	}
	for name, pl := range mustBlock {
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("Twig gadget %q PASSED unblocked (arg): %s", name, pl)
		}
		if !fireBlocked(eng, probe{payload: pl, target: "body"}) {
			t.Errorf("Twig gadget %q PASSED unblocked (body): %s", name, pl)
		}
	}
	// Legitimate Twig/template filters and ordinary text must NOT be blocked.
	benign := map[string]string{
		"twig-upper":   "{{ user.name|upper }}",
		"twig-number":  "{{ price|number_format(2, '.', ',') }}",
		"twig-default": "{{ title|default('Home') }}",
		"js-map-arrow": "{{ items|map(i => i.id) }}",
		"plain-text":   "filter the list and map the results from the system log",
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("FALSE POSITIVE: benign %q blocked: %s", name, pl)
		}
	}
}

// TestBypassVerify_ProtoBracket covers PROTO-003: bracket-notation prototype
// pollution (__proto__[…] / unquoted constructor[prototype]) which PROTO-001
// only LOGGED while the sibling __proto__/JSON forms were blocked — an
// exploitable inconsistency against prototype-chain-walking set/merge helpers.
func TestBypassVerify_ProtoBracket(t *testing.T) {
	eng := probeEngine(t)
	// Both the param-NAME form (the natural wire encoding) and the value form.
	for _, pl := range []string{
		"constructor[prototype][isAdmin]",
		"__proto__[isAdmin]",
		`constructor["prototype"]["isAdmin"]`,
	} {
		if !fireBlocked(eng, probe{payload: pl, target: "argname"}) {
			t.Errorf("proto-pollution %q PASSED unblocked (argname)", pl)
		}
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("proto-pollution %q PASSED unblocked (arg)", pl)
		}
	}
	// Dot-access and ordinary identifiers must NOT be blocked.
	benign := map[string]string{
		"dot-access":     "constructor.prototype.foo",
		"array-index":    "items[index]",
		"english":        "the constructor builds the object from a blueprint",
		"ctor-bracket-x": "myConstructors[0]",
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("FALSE POSITIVE: benign %q blocked: %s", name, pl)
		}
	}
}

// TestBypassVerify_ClauseSubquery covers SQLI-036: a parenthesised SELECT…FROM
// subquery in an ORDER BY / GROUP BY clause — the keyword-anchoring blind spot
// in SQLI-032 (which requires a leading AND/OR). Low-FP hardening of the same
// subquery class SQLI-031..033 target.
func TestBypassVerify_ClauseSubquery(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := map[string]string{
		"orderby-subq":   "1 ORDER BY (SELECT 1 FROM users)",
		"orderby-exfil":  "1 ORDER BY (SELECT substr(password,1,1) FROM users LIMIT 1)",
		"groupby-subq":   "1 GROUP BY (SELECT a FROM secrets)",
		"orderby-spaced": "1 order  by  ( select name from admins )",
	}
	for name, pl := range mustBlock {
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("clause subquery %q PASSED unblocked: %s", name, pl)
		}
	}
	// Ordinary sort/group parameters must NOT be blocked.
	benign := map[string]string{
		"order-by-date":  "order by date",
		"order-by-price": "sort=price&order by name ascending",
		"group-category": "group by category",
		"select-prompt":  "please select from the dropdown",
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("FALSE POSITIVE: benign %q blocked: %s", name, pl)
		}
	}
}

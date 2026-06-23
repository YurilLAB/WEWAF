package engine

import "testing"

// TestBypassVerify_SciNotJsonb covers SQLI-034 (scientific-notation keyword
// glue) and SQLI-035 (Postgres jsonb tautology) — two verified, DB-exploitable
// evasions that avoided UNION SELECT / OR 1=1. Benign floats/casts must not FP.
func TestBypassVerify_SciNotJsonb(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := map[string]string{
		"scinot-union":   "1e0UNION1e0SELECT1e0username,password1e0FROM1e0users",
		"scinot-from":    "0e0/**/UNION/**/SELECT1e0table_name1e0FROM1e0information_schema.tables",
		"jsonb-contain":  "1 OR '{\"a\":1,\"b\":2}'::jsonb @> '{\"b\":2}'::jsonb",
		"jsonb-contain2": "1 OR '{\"b\":2}'::jsonb <@ '{\"a\":1,\"b\":2}'::jsonb",
	}
	for name, pl := range mustBlock {
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("%q still PASSES (bypass): %s", name, pl)
		}
	}
	benign := map[string]string{
		"float-price":  "price=1e3&qty=2",      // scientific-notation number, no keyword
		"float-word":   "value is 2e5 dollars", // float then ordinary words
		"json-payload": `{"score":1.5e2,"ok":true}`,
		"cast-text":    "convert this to text format",
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("FALSE POSITIVE: benign %q blocked: %s", name, pl)
		}
	}
}

// TestBypassVerify_Whitespace proves WEWAF's whitespace normalization is solid
// for EXPLOITABLE evasion: every char a real SQL tokenizer (MySQL/Postgres)
// treats as whitespace must still be caught in `' OR '1'='1`. (A lone 0xa0 byte
// evades but is NOT SQL whitespace, so it isn't a real bypass — excluded.)
func TestBypassVerify_Whitespace(t *testing.T) {
	eng := probeEngine(t)
	// %09 tab, %0a LF, %0b VT, %0c FF, %0d CR, %20 space, %c2%a0 NBSP(UTF-8),
	// %e2%80%83 EM SPACE, /**/ inline comment — all valid SQL whitespace/comment.
	wsVariants := map[string]string{
		"tab":       "1'%09OR%09'1'='1",
		"lf":        "1'%0aOR%0a'1'='1",
		"vtab":      "1'%0bOR%0b'1'='1",
		"ff":        "1'%0cOR%0c'1'='1",
		"cr":        "1'%0dOR%0d'1'='1",
		"space":     "1'%20OR%20'1'='1",
		"nbsp-utf8": "1'%c2%a0OR%c2%a0'1'='1",
		"emspace":   "1'%e2%80%83OR%e2%80%83'1'='1",
		"comment":   "1'/**/OR/**/'1'='1",
	}
	for name, pl := range wsVariants {
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("EXPLOITABLE whitespace evasion: %s variant of ' OR '1'='1 PASSED unblocked: %s", name, pl)
		}
	}
}

// TestBypassVerify_Subquery is the regression test for the SQLi subquery/function
// gap (SQLI-031/032/033): these genuinely-exploitable injections that avoid
// UNION SELECT / OR 1=1 must now block, while benign free text containing the
// same English words must NOT (false-positive guard).
func TestBypassVerify_Subquery(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := map[string]string{
		"pipe-concat-subquery": "1'||(SELECT password FROM users LIMIT 1)||'",
		"and-subquery":         "1' AND (SELECT 1 FROM users WHERE name='admin')='1",
		"or-subquery":          "1' OR (SELECT count(*) FROM information_schema.tables)>0-- -",
		"json-extract-bool":    "1' AND JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
		"updatexml":            "1' AND updatexml(1,concat(0x7e,(SELECT pass FROM users)),1)-- -",
	}
	for name, pl := range mustBlock {
		if !fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("subquery SQLi %q still PASSES (bypass): %s", name, pl)
		}
	}
	// Benign English / app text that mentions select/from/and/or/json but is NOT
	// SQL injection must still pass (no false positives).
	benign := map[string]string{
		"english-1":    "search for shoes and shirts from our new collection",
		"english-2":    "pick a color or size from the dropdown and submit",
		"english-3":    "select your country from the list",
		"json-field":   `{"name":"select","origin":"from the catalog"}`,
		"and-or-words": "this and that or the other from yesterday",
		"select-param": "select=name&from=2024",
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "arg"}) {
			t.Errorf("FALSE POSITIVE: benign %q was blocked: %s", name, pl)
		}
	}
}

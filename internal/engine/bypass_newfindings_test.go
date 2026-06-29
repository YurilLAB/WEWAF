package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// blockedInJSONBody runs the payload as a JSON request body through the body
// phase, exactly as the proxy would for an application/json request.
func blockedInJSONBody(eng *Engine, jsonBody string) bool {
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	tx := core.NewTransaction(nil, req, nil)
	tx.SetMetadata("body", []byte(jsonBody))
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// blockedInHeader runs the payload as the value of an arbitrary request header
// through both phases (header-phase rules + the body-phase header-sink rules).
func blockedInHeader(eng *Engine, name, payload string) bool {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(name, payload)
	tx := core.NewTransaction(nil, req, nil)
	if eng.ProcessRequestHeaders(tx) != nil {
		return true
	}
	return eng.ProcessRequestBody(tx) != nil
}

// TestBypassFix_UnionDistinct closes the confirmed UNION DISTINCT evasion: the
// UNION signatures recognised "UNION SELECT" and "UNION ALL SELECT" but not
// "UNION DISTINCT SELECT" — valid standard SQL on MySQL/MariaDB/Postgres/MSSQL/
// Oracle (the explicit form of the default de-duplicating UNION). Found by the
// bypass-hunt workflow, verified against every compiled rule.
func TestBypassFix_UnionDistinct(t *testing.T) {
	eng := newFuzzEngine(t)

	// Control: the plain forms must (still) block.
	for _, plain := range []string{
		"1' UNION SELECT password FROM admin-- -",
		"1' UNION ALL SELECT password FROM admin-- -",
	} {
		if !blockedInFormBody(eng, plain) {
			t.Fatalf("control regression: plain %q must block in form body", plain)
		}
	}

	// The evasion: UNION DISTINCT SELECT must block in every body view.
	evasion := "1' UNION DISTINCT SELECT password FROM admin-- -"
	if !blockedInFormBody(eng, evasion) {
		t.Errorf("UNION DISTINCT not blocked in form body: %q", evasion)
	}
	if !blockedInJSONBody(eng, `{"id":"`+evasion+`"}`) {
		t.Errorf("UNION DISTINCT not blocked in JSON body")
	}
	if !blockedInArg(eng, evasion) {
		t.Errorf("UNION DISTINCT not blocked in query arg")
	}
	// Comment-glued and extra-whitespace variants of the same evasion.
	if !blockedInFormBody(eng, "1' UNION/**/DISTINCT/**/SELECT a FROM b") {
		t.Errorf("UNION/**/DISTINCT/**/SELECT not blocked")
	}
	if !blockedInFormBody(eng, "1' union   distinct   select a from b") {
		t.Errorf("lowercase union distinct select not blocked")
	}
}

// TestBypassFix_UnionDistinctNoFalsePositive guards the fix doesn't over-match
// benign SQL/text that contains the words but is not a UNION injection.
func TestBypassFix_UnionDistinctNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, benign := range []string{
		"SELECT DISTINCT name FROM users",      // DISTINCT without UNION
		"the credit union will select a board", // English prose
		"distinct union members",               // wrong order, no select
	} {
		if blockedInFormBody(eng, benign) {
			t.Errorf("false positive: benign %q must not block", benign)
		}
	}
}

// TestBypassFix_JsProtocolEncodedSeparator closes the XSS-002 evasion: the
// javascript:-protocol rule allowed only %09/%0a/%0d (and space/entities) as the
// inter-token separator between "java" and "script", so a null byte (%00) — and
// any other percent-encoded C0 control a null-stripping backend/browser ignores
// — slipped through. Header values are normalised without URL-decoding (to keep
// base64 tokens intact), so the encoded form survives there in particular.
func TestBypassFix_JsProtocolEncodedSeparator(t *testing.T) {
	eng := newFuzzEngine(t)

	// Control: the plain javascript: protocol blocks in a custom header and arg.
	if !blockedInHeader(eng, "X-Custom", "javascript:alert(1)") {
		t.Fatalf("control regression: plain javascript: must block in a header")
	}
	if !blockedInArg(eng, "javascript:alert(1)") {
		t.Fatalf("control regression: plain javascript: must block in an arg")
	}

	// The evasion: an encoded-control separator must block in a header (the
	// header path does not URL-decode, so the rule itself must cover it).
	for _, sep := range []string{"%00", "%01", "%08", "%0b", "%0c", "%1f", "%7f"} {
		payload := "java" + sep + "script:alert(1)"
		if !blockedInHeader(eng, "X-Custom", payload) {
			t.Errorf("encoded-separator js-protocol not blocked in header: %q", payload)
		}
	}
}

// TestBypassFix_JsProtocolNoFalsePositive guards the broadened separator class
// doesn't start matching benign header values.
func TestBypassFix_JsProtocolNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	for _, benign := range []string{
		"java is a programming language",
		"the script ran",
		"application/javascript", // a real MIME type, no colon-protocol form
	} {
		if blockedInHeader(eng, "X-Custom", benign) {
			t.Errorf("false positive: benign header %q must not block", benign)
		}
	}
}

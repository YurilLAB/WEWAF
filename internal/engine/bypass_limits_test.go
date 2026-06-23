package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

// TestBypassVerify_InspectionLimits is the regression test for the inspection-
// LIMIT evasion class (the Azure App Gateway 2024 padding bypass): padding a
// request with junk to push a malicious value past a per-value size cap or a
// target-count cap must NOT let it reach the backend uninspected. Verified: the
// body is inspected in full and the payload is still caught past the 64KB arg
// cap, so none of these evade.
func TestBypassVerify_InspectionLimits(t *testing.T) {
	eng := probeEngine(t)

	fireGet := func(rawQuery string) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.RawQuery = rawQuery
		tx := core.NewTransaction(nil, req, nil)
		return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
	}
	firePost := func(body string) bool {
		req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tx := core.NewTransaction(nil, req, nil)
		tx.SetMetadata("body", []byte(body))
		return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
	}

	const xss = "q=<script>alert(1)</script>"

	// (1) Many query args: 150 junk params, payload in the last.
	var q strings.Builder
	for i := 0; i < 150; i++ {
		q.WriteString("p")
		q.WriteString(itoa(i))
		q.WriteString("=x&")
	}
	if !fireGet(q.String() + xss) {
		t.Error("many-args padding (payload in last of 150) evaded inspection")
	}

	// (2) Huge single arg: payload pushed past the 64KB per-value cap.
	for _, padKB := range []int{65, 80, 200} {
		if !fireGet("q=" + strings.Repeat("A", padKB*1024) + "<script>alert(1)</script>") {
			t.Errorf("huge-arg padding (%dKB) pushed the payload past inspection", padKB)
		}
	}

	// (3) Many form-body fields: payload in the last of 150.
	var f strings.Builder
	for i := 0; i < 150; i++ {
		f.WriteString("f")
		f.WriteString(itoa(i))
		f.WriteString("=x&")
	}
	if !firePost(f.String() + xss) {
		t.Error("many-form-fields padding (payload in last of 150) evaded inspection")
	}

	// (4) Huge body: 80KB junk then the payload (body is inspected in full).
	if !firePost(strings.Repeat("A", 80*1024) + "<script>alert(1)</script>") {
		t.Error("huge-body padding (80KB) pushed the payload past inspection")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

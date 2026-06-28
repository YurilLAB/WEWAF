package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wewaf/internal/history"
)

func TestThreatOffendersFiltersAndCaps(t *testing.T) {
	ips := []history.IPActivity{
		{IP: "1.1.1.1", BlockCount: 10, RequestCount: 100},
		{IP: "2.2.2.2", BlockCount: 1, RequestCount: 50}, // below minBlocks
		{IP: "3.3.3.3", BlockCount: 5, RequestCount: 20},
		{IP: "4.4.4.4", BlockCount: 4, RequestCount: 9},
	}
	banned := map[string]bool{"1.1.1.1": true}
	got := threatOffenders(ips, func(ip string) bool { return banned[ip] }, 3, 2)
	if len(got) != 2 {
		t.Fatalf("want 2 offenders (topN cap, minBlocks filter), got %d: %+v", len(got), got)
	}
	if got[0].IP != "1.1.1.1" || !got[0].Banned {
		t.Fatalf("first offender should be 1.1.1.1 banned=true, got %+v", got[0])
	}
	if got[1].IP != "3.3.3.3" || got[1].Banned {
		t.Fatalf("second offender should be 3.3.3.3 banned=false, got %+v", got[1])
	}
	// 2.2.2.2 (1 block) must be excluded.
	for _, o := range got {
		if o.IP == "2.2.2.2" {
			t.Fatal("2.2.2.2 is below minBlocks and must be excluded")
		}
	}
}

func TestThreatOffendersNilBanFunc(t *testing.T) {
	ips := []history.IPActivity{{IP: "9.9.9.9", BlockCount: 3}}
	got := threatOffenders(ips, nil, 3, 10)
	if len(got) != 1 || got[0].Banned {
		t.Fatalf("nil isBanned should yield banned=false, got %+v", got)
	}
}

// TestHandleThreatsNilDeps verifies the endpoint is nil-safe (no proxy/history/
// banList wired) and returns the documented shape.
func TestHandleThreatsNilDeps(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/threats", nil)
	rec := httptest.NewRecorder()
	s.handleThreats(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var body struct {
		UnderAttack bool             `json:"under_attack"`
		Offenders   []ThreatOffender `json:"offenders"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.UnderAttack {
		t.Fatal("under_attack should be false with no proxy")
	}
	if body.Offenders == nil {
		t.Fatal("offenders should be an empty array, not null")
	}
}

func TestHandleThreatsRejectsNonGet(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/threats", nil)
	rec := httptest.NewRecorder()
	s.handleThreats(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

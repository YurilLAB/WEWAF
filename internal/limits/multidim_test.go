package limits

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestMultiLimiterIPBudgetTrips(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 5})
	r := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < 5; i++ {
		if k, b, _ := m.CheckRequest(r, "203.0.113.5", ""); b {
			t.Fatalf("blocked too early at i=%d kind=%v", i, k)
		}
	}
	if k, b, _ := m.CheckRequest(r, "203.0.113.5", ""); !b || k != DimIP {
		t.Fatalf("expected IP block at request 6; got kind=%v blocked=%v", k, b)
	}
}

func TestMultiLimiterPerIPIsolated(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 3})
	r := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < 3; i++ {
		m.CheckRequest(r, "203.0.113.1", "")
	}
	if _, b, _ := m.CheckRequest(r, "203.0.113.2", ""); b {
		t.Fatal("second IP must not be blocked by first IP's count")
	}
}

func TestMultiLimiterJA4Dimension(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, JA4Budget: 3})
	r := httptest.NewRequest("GET", "/", nil)
	ja := "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	for i := 0; i < 3; i++ {
		m.CheckRequest(r, "203.0.113.5", ja)
	}
	// Different IP, same JA4 — should still trip JA4 budget.
	if k, b, _ := m.CheckRequest(r, "203.0.113.99", ja); !b || k != DimJA4 {
		t.Fatalf("JA4 dim should trip on rotated IP: kind=%v blocked=%v", k, b)
	}
}

func TestMultiLimiterCookieDimension(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, CookieBudget: 3, CookieName: "sid"})
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
		m.CheckRequest(r, "203.0.113.5", "")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	if k, b, _ := m.CheckRequest(r, "203.0.113.99", ""); !b || k != DimCookie {
		t.Fatalf("cookie dim should trip: kind=%v blocked=%v", k, b)
	}
}

func TestMultiLimiterQueryKeySignatureRotatesValues(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, QueryKeysBudget: 3})
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/api/items?id="+string(rune('A'+i)), nil)
		m.CheckRequest(r, "203.0.113.5", "")
	}
	// Same key shape, different value, different IP — should trip the
	// query-keys dimension.
	r := httptest.NewRequest("GET", "/api/items?id=Z", nil)
	if k, b, _ := m.CheckRequest(r, "203.0.113.99", ""); !b || k != DimQueryKeys {
		t.Fatalf("query-keys dim should trip on value rotation: kind=%v blocked=%v", k, b)
	}
}

func TestMultiLimiterIgnoresEmptyKeys(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 1, JA4Budget: 1, CookieBudget: 1, QueryKeysBudget: 1})
	r := httptest.NewRequest("GET", "/", nil)
	// Empty IP, empty JA4, no cookie, no query — must not block.
	if _, b, _ := m.CheckRequest(r, "", ""); b {
		t.Fatal("empty inputs must never block")
	}
}

func TestMultiLimiterDisabledDimDoesntBlock(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 0})
	r := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < 100; i++ {
		if _, b, _ := m.CheckRequest(r, "203.0.113.5", ""); b {
			t.Fatal("disabled IP dim should not block")
		}
	}
}

func TestQueryKeySignatureIsStable(t *testing.T) {
	u1, _ := url.Parse("/x?b=1&a=2&c=3")
	u2, _ := url.Parse("/x?c=99&a=foo&b=bar")
	if QueryKeySignature(u1) != QueryKeySignature(u2) {
		t.Fatalf("signature must depend only on key set: %q vs %q", QueryKeySignature(u1), QueryKeySignature(u2))
	}
	if QueryKeySignature(u1) != "a,b,c" {
		t.Fatalf("expected a,b,c got %q", QueryKeySignature(u1))
	}
}

func TestMultiLimiterCapEvicts(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 1, MaxEntries: 8})
	for i := 0; i < 1000; i++ {
		ip := "10.0." + string(rune('A'+(i%26))) + "." + string(rune('a'+(i%26)))
		r := httptest.NewRequest("GET", "/", nil)
		m.CheckRequest(r, ip, "")
	}
	st := m.Stats()
	// Cap is a soft limit (we evict 64 at a time when overflowing) so
	// the assert tolerates a small overshoot.
	if st.Tracked > 100 {
		t.Fatalf("tracked entries grew unbounded: %d (cap=%d)", st.Tracked, st.Cap)
	}
	if st.Dropped == 0 {
		t.Fatal("evictions should have been recorded")
	}
}

func TestMultiLimiterStatsIncrement(t *testing.T) {
	m := NewMultiLimiter(MultiConfig{Window: time.Second, IPBudget: 1})
	r := httptest.NewRequest("GET", "/", nil)
	m.CheckRequest(r, "203.0.113.5", "")
	m.CheckRequest(r, "203.0.113.5", "") // blocked
	st := m.Stats()
	if st.Checks != 2 || st.Allowed != 1 || st.Blocked != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if st.BlockedByDim["ip"] == 0 {
		t.Fatal("blocked-by-ip counter should increment")
	}
}

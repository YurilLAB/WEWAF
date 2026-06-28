package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"wewaf/internal/clientip"
	"wewaf/internal/config"
)

// signCookieIP reproduces internal/web/handlers_session.go:signPowCookie with
// the client-IP key folded into the MAC (the POW-AMORTIZE-001 binding).
func signCookieIP(secret, sessID, ipKey string, ts int64) string {
	body := sessID + "." + strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	if ipKey != "" {
		mac.Write([]byte("|"))
		mac.Write([]byte(ipKey))
	}
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig
}

// TestPoWCookieBoundToClientIP is the regression for POW-AMORTIZE-001: a pass
// cookie minted for one client IP must not validate from a different IP, so a
// botnet cannot copy a single solved cookie fleet-wide to skip the gate for the
// cookie's lifetime.
func TestPoWCookieBoundToClientIP(t *testing.T) {
	ipx, err := clientip.New(false, nil) // trust no XFF → key off RemoteAddr
	if err != nil {
		t.Fatalf("clientip.New: %v", err)
	}
	wp := &WAFProxy{
		cfg: &config.Config{
			PoWEnabled:      true,
			PoWSecret:       "test-secret",
			PoWCookieTTLSec: 3600,
		},
		ipExtractor: ipx,
	}

	rA := httptest.NewRequest("GET", "/", nil)
	rA.RemoteAddr = "1.1.1.1:5555"
	keyA := wp.ipExtractor.ClientIP(rA)
	cookie := signCookieIP("test-secret", "sess-1", keyA, time.Now().Unix())
	rA.AddCookie(&http.Cookie{Name: powCookieName, Value: cookie})

	// Same IP the cookie was minted for: accepted.
	if !wp.hasValidPoWCookie(rA, "sess-1") {
		t.Fatal("cookie should be valid from the IP it was minted for")
	}

	// Different IP, same cookie + session: rejected — no fleet-wide amortization.
	rB := httptest.NewRequest("GET", "/", nil)
	rB.RemoteAddr = "2.2.2.2:5555"
	rB.AddCookie(&http.Cookie{Name: powCookieName, Value: cookie})
	if wp.hasValidPoWCookie(rB, "sess-1") {
		t.Fatal("cookie minted for 1.1.1.1 must not validate from 2.2.2.2 (POW-AMORTIZE-001)")
	}
}

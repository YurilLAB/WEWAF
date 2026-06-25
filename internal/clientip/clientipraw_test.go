package clientip

import (
	"net/http/httptest"
	"testing"
)

// TestClientIPRawFullPrecisionIPv6 is the regression for the zero-trust IPv6
// fail-open: ClientIP masks IPv6 to /64 (correct for abuse keying), but
// ClientIPRaw must return the full /128 so an access-control gate can honour a
// /128 CIDR. IPv4 is identical for both.
func TestClientIPRawFullPrecisionIPv6(t *testing.T) {
	e, err := New(false, nil) // no XFF trust -> uses the TCP peer
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::dead:beef:0:1]:443"

	if raw := e.ClientIPRaw(r); raw != "2001:db8::dead:beef:0:1" {
		t.Errorf("ClientIPRaw = %q, want full /128 2001:db8::dead:beef:0:1", raw)
	}
	if masked := e.ClientIP(r); masked != "2001:db8::" {
		t.Errorf("ClientIP = %q, want /64-masked 2001:db8::", masked)
	}

	// IPv4: raw and masked agree (full /32).
	r4 := httptest.NewRequest("GET", "/", nil)
	r4.RemoteAddr = "203.0.113.7:5555"
	if raw, masked := e.ClientIPRaw(r4), e.ClientIP(r4); raw != "203.0.113.7" || masked != "203.0.113.7" {
		t.Errorf("IPv4 raw=%q masked=%q, want both 203.0.113.7", raw, masked)
	}
}

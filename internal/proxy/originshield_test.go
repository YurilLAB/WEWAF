package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyOriginSecret(t *testing.T) {
	const cur, prev = "current-secret-value-32-bytes-long!", "previous-secret-value-rotation-old"
	cases := []struct {
		name           string
		provided, c, p string
		want           bool
	}{
		{"matches current", cur, cur, prev, true},
		{"matches previous (rotation)", prev, cur, prev, true},
		{"wrong value", "nope", cur, prev, false},
		{"empty provided vs set secret", "", cur, prev, false},
		{"empty current, empty provided -> never match", "", "", "", false},
		{"empty current, non-empty provided", "x", "", "", false},
		{"no previous configured, provided==prev-shaped", "anything", cur, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyOriginSecret(tc.provided, tc.c, tc.p); got != tc.want {
				t.Fatalf("VerifyOriginSecret(%q,%q,%q)=%v want %v", tc.provided, tc.c, tc.p, got, tc.want)
			}
		})
	}
}

func TestOriginShieldDirectorOverwritesClientValue(t *testing.T) {
	shield := newOriginShield("X-WEWAF-Origin-Verify", "the-real-secret", "")
	baseCalled := false
	director := shield.wrapDirector(func(*http.Request) { baseCalled = true })

	req := httptest.NewRequest(http.MethodGet, "http://backend/path", nil)
	// A hostile client tries to forge the verify header.
	req.Header.Set("X-WEWAF-Origin-Verify", "attacker-guess")
	director(req)

	if !baseCalled {
		t.Fatal("wrapped director must still call the base director")
	}
	if got := req.Header.Get("X-WEWAF-Origin-Verify"); got != "the-real-secret" {
		t.Fatalf("director must overwrite client value, got %q", got)
	}
}

func TestOriginShieldDefaultHeader(t *testing.T) {
	shield := newOriginShield("", "s", "")
	if shield.header != "X-WEWAF-Origin-Verify" {
		t.Fatalf("expected default header, got %q", shield.header)
	}
}

func FuzzVerifyOriginSecret(f *testing.F) {
	f.Add("a", "a", "")
	f.Add("", "", "")
	f.Add("secret", "secret", "old")
	f.Add("old", "secret", "old")
	f.Add("x\x00y", "x", "y")
	f.Fuzz(func(t *testing.T, provided, current, previous string) {
		got := VerifyOriginSecret(provided, current, previous)
		// Reconstruct the ground truth: a match is true iff provided exactly
		// equals a NON-EMPTY configured secret.
		want := (current != "" && provided == current) || (previous != "" && provided == previous)
		if got != want {
			t.Fatalf("VerifyOriginSecret(%q,%q,%q)=%v want %v", provided, current, previous, got, want)
		}
	})
}

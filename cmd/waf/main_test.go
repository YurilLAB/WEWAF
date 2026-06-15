package main

import "testing"

// TestIsLoopbackListenAddr guards the gate for the WAF_ALLOW_NO_AUTH escape
// hatch: disabling admin auth is only permitted on a loopback bind.
func TestIsLoopbackListenAddr(t *testing.T) {
	loopback := []string{"127.0.0.1:8443", "[::1]:8443", "localhost:8443", "127.5.5.5:80"}
	notLoopback := []string{":8443", "0.0.0.0:8443", "[::]:8443", "10.0.0.1:8443", "192.168.1.1:8443", "", "example.com:8443"}
	for _, a := range loopback {
		if !isLoopbackListenAddr(a) {
			t.Errorf("%q should be loopback", a)
		}
	}
	for _, a := range notLoopback {
		if isLoopbackListenAddr(a) {
			t.Errorf("%q should NOT be loopback", a)
		}
	}
}

func TestIsWildcardListenAddr(t *testing.T) {
	wildcard := []string{":8443", "0.0.0.0:8443", "[::]:8443", ""}
	notWildcard := []string{"127.0.0.1:8443", "10.0.0.1:8443", "localhost:8443"}
	for _, a := range wildcard {
		if !isWildcardListenAddr(a) {
			t.Errorf("%q should be wildcard", a)
		}
	}
	for _, a := range notWildcard {
		if isWildcardListenAddr(a) {
			t.Errorf("%q should NOT be wildcard", a)
		}
	}
}

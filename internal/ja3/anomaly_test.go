package ja3

import (
	"testing"
)

// TestAnomalyDetectsUATLSMismatch covers the UA↔TLS cross-signal check that the
// proxy now runs on the live path: a UA claiming a browser while the TLS
// fingerprint is a known CLI tool is flagged; a matching pair is not.
func TestAnomalyDetectsUATLSMismatch(t *testing.T) {
	a := NewAnomalyDetector()
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

	// curl's well-known JA3 hash + a Chrome UA → mismatch flagged.
	curlFP := Fingerprint{Hash: "6fa3244afc6bb6f9fad207b6b52af26b"}
	if res := a.Check(chromeUA, curlFP); res.ScoreBump <= 0 {
		t.Fatalf("Chrome UA + curl JA3 must flag a mismatch, got bump=%d", res.ScoreBump)
	}

	// Honest curl (matching UA + fingerprint) → no flag.
	if res := a.Check("curl/7.88.1", curlFP); res.ScoreBump != 0 {
		t.Fatalf("curl UA + curl JA3 must not flag: bump=%d tags=%v", res.ScoreBump, res.Tags)
	}

	// Modern-browser UA with an old-TLS JA4 → flagged.
	oldTLS := Fingerprint{JA4: "t10d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}
	if res := a.Check(chromeUA, oldTLS); res.ScoreBump <= 0 {
		t.Fatalf("modern-browser UA with t10 JA4 must flag, got %d", res.ScoreBump)
	}

	// Empty UA / empty fingerprint → never flags (not enough signal).
	if res := a.Check("", curlFP); res.ScoreBump != 0 {
		t.Fatalf("empty UA must not flag")
	}
	if res := a.Check(chromeUA, Fingerprint{}); res.ScoreBump != 0 {
		t.Fatalf("empty fingerprint must not flag")
	}

	// Bump is capped at 25.
	if res := a.Check(chromeUA, curlFP); res.ScoreBump > 25 {
		t.Fatalf("bump must be capped at 25, got %d", res.ScoreBump)
	}
}

package proxy

import (
	"strings"
	"testing"
)

func TestExfilDetectsValidCreditCard(t *testing.T) {
	body := []byte(`{"card":"4111 1111 1111 1111","name":"jack"}`)
	// Strip spaces so the digit run matches.
	body = []byte(strings.ReplaceAll(string(body), " ", ""))
	findings := inspectEgressResponseBody(body)
	if len(findings) == 0 {
		t.Fatalf("expected a credit_card finding; got none")
	}
	var kinds []string
	for _, f := range findings {
		kinds = append(kinds, f.Kind)
	}
	if !contains(kinds, "credit_card") {
		t.Fatalf("expected credit_card in %v", kinds)
	}
}

func TestExfilIgnoresNonLuhnDigitRun(t *testing.T) {
	// Phone-number style 10-digit run shouldn't trigger.
	body := []byte(`{"phone":"5551234567"}`)
	findings := inspectEgressResponseBody(body)
	for _, f := range findings {
		if f.Kind == "credit_card" {
			t.Fatalf("phone number falsely flagged as credit card")
		}
	}
}

func TestExfilDetectsAWSKey(t *testing.T) {
	// Construct the AWS-style key at runtime so GitHub secret-scanning
	// doesn't flag the literal source line as a leaked credential.
	// The regex under test is `\bAKIA[0-9A-Z]{16}\b`, so we need the
	// prefix followed by 16 uppercase alphanumerics. This is not a real
	// key — it's the canonical documentation placeholder split apart.
	key := "AKIA" + strings.Repeat("A", 13) + "BCD" // "AKIA" + 16 chars
	body := []byte("Authorization: AWS4-HMAC-SHA256 Credential=" + key)
	findings := inspectEgressResponseBody(body)
	if !anyKind(findings, "aws_access_key") {
		t.Fatalf("expected aws_access_key finding; got %v", findings)
	}
}

func TestExfilMasksSecrets(t *testing.T) {
	// Build a Stripe-style key from its prefix + 24 alphanumerics so the
	// literal string never appears in source (secret-scanner friendly).
	// The regex is `\bsk_live_[0-9A-Za-z]{20,}\b`.
	stripe := "sk_" + "live_" + strings.Repeat("A", 24)
	body := []byte(stripe)
	findings := inspectEgressResponseBody(body)
	if len(findings) == 0 {
		t.Fatalf("stripe key should have matched")
	}
	// The mask function keeps only the first 8 chars + "***".
	if strings.Contains(findings[0].Sample, strings.Repeat("A", 20)) {
		t.Fatalf("sample leaked full secret: %q", findings[0].Sample)
	}
}

func TestLuhnKnownCards(t *testing.T) {
	cases := map[string]bool{
		"4111111111111111": true,  // Visa test
		"5500000000000004": true,  // MasterCard test
		"340000000000009":  true,  // Amex test (15 digits)
		"4111111111111112": false, // one-off checksum
		"123456":           false, // too short
	}
	for num, want := range cases {
		got := luhnValid([]byte(num))
		if got != want {
			t.Errorf("luhn(%s) = %v, want %v", num, got, want)
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func anyKind(findings []exfilFinding, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

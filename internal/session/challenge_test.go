package session

import (
	"net/url"
	"testing"
)

// TestVerifyChallengeSignals_NegativeIntsTreatedAsAbsent — closes
// the bypass where strconv.Atoi("-1") returned -1 (no error), so a
// hostile client sending "hc=-1" defeated the `if hwc == 0` check
// while still being implausible. The new nonNegInt helper treats
// negatives as zero so the suspicion bump fires.
func TestVerifyChallengeSignals_NegativeIntsTreatedAsAbsent(t *testing.T) {
	form := url.Values{
		"wd": {"false"},
		"pl": {"-1"},  // negative plugins — must be treated as zero
		"ch": {"-1"},  // ditto for window.chrome
		"lg": {"-1"},
		"hc": {"-1"},
		"sw": {"-1"},
		"sh": {"-1"},
		"tn": {"-1"},
		"ua": {"-1"},
	}
	score, _, _ := VerifyChallengeSignals(form, "Mozilla/5.0 (Chromium) Chrome/120.0")
	// All of: zero plugins (chromium), missing window.chrome, empty
	// languages, hwc=0, zero screen dims, ua-too-short. Score should
	// land ≥ the failure threshold (50).
	if score < 50 {
		t.Fatalf("negative-int payload should fail challenge; got %d", score)
	}
}

// TestVerifyChallengeSignals_AbsurdlyLargeIntsClamped — the inverse
// failure mode: Atoi happily parses "999999999" as a screen height,
// which a bot could use to look "configured" while reporting a
// physically-impossible dimension. nonNegInt clamps at the soft
// ceiling so the implausible value still tells us nothing useful
// past the cap.
func TestVerifyChallengeSignals_AbsurdlyLargeIntsClamped(t *testing.T) {
	form := url.Values{
		"wd": {"false"},
		"pl": {"3"},
		"ch": {"1"},
		"lg": {"2"},
		"hc": {"4"},
		"sw": {"99999999999"}, // way past the 16384 cap
		"sh": {"99999999999"},
		"tn": {"500"},
		"ua": {"120"},
	}
	score, passed, _ := VerifyChallengeSignals(form, "Mozilla/5.0 (Chromium) Chrome/120.0")
	if !passed {
		t.Fatalf("clamped large dims should still pass when other signals are clean; score=%d", score)
	}
}

// TestNonNegInt covers the helper directly so a future change can't
// silently regress its contract.
func TestNonNegInt(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want int
	}{
		{"", 100, 0},
		{"5", 100, 5},
		{"-1", 100, 0},
		{"-99999", 100, 0},
		{"abc", 100, 0},
		// strconv.Atoi DOES accept a leading "+", per Go's docs. We
		// treat the parsed value as legitimate — a bot that bothers
		// to send "+5" instead of "5" is implausibly polite.
		{"+5", 100, 5},
		{" 5", 100, 0}, // leading whitespace not tolerated by Atoi
		{"100", 100, 100},
		{"101", 100, 100},
		{"99999999999", 100, 100},
	}
	for _, tc := range cases {
		if got := nonNegInt(tc.in, tc.max); got != tc.want {
			t.Errorf("nonNegInt(%q, %d) = %d, want %d", tc.in, tc.max, got, tc.want)
		}
	}
}

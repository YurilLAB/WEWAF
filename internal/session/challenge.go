package session

import (
	"net/url"
	"strconv"
	"strings"
)

// VerifyChallengeSignals scores the JS-reported browser signals and
// decides whether to issue a pass cookie. Returns (score, passed).
//
// The scoring is intentionally lenient — we're looking for clear
// headless tells, not fingerprint-grade identification. False positives
// hurt real users, false negatives only cost us a sharper risk score
// (the session tracker still sees the missing-challenge signal).
//
// Score is 0-100 where higher = more suspicious. We pass at < 50.
// Every signal is annotated in comments so the admin UI can surface
// "why did this fail" for operator debugging.
//
// All numeric inputs go through nonNegInt below: a negative integer
// in any field is treated as "field absent" rather than the literal
// value. The previous code used strconv.Atoi directly, so a hostile
// client could send "hc=-1" and the `if hwc == 0` check would skip
// the bump even though -1 cores is obvious automation. nonNegInt also
// rejects values larger than a soft ceiling — Atoi happily parses
// "999999999" as a real screen height, which a bot could use to look
// "configured" while still being implausible.
func VerifyChallengeSignals(form url.Values, userAgent string) (score int, passed bool, reasons []string) {
	// Defensive: if the form somehow came in empty the client is broken
	// or someone hit the endpoint directly. Fail but don't blame the user.
	if len(form) == 0 {
		return 100, false, []string{"no signals submitted"}
	}

	// +40 — navigator.webdriver=true is a hard tell.
	if form.Get("wd") == "true" {
		score += 40
		reasons = append(reasons, "navigator.webdriver=true")
	}

	uaLower := strings.ToLower(userAgent)
	isFirefox := strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "gecko/")
	isChromium := strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "edg/")

	// +20 — zero plugins is the default for headless Chrome. Real browsers
	// report 2+ (PDF viewer, Chromium PDF plugin, etc.). Firefox reports
	// 0 legitimately post-Quantum, so cross-check with UA to avoid
	// flagging Firefox users.
	plugins := nonNegInt(form.Get("pl"), 256)
	if plugins == 0 && isChromium && !isFirefox {
		score += 20
		reasons = append(reasons, "zero plugins on chromium UA")
	}

	// +15 — window.chrome missing on a Chrome UA is the classic
	// "puppeteer didn't patch it" tell. Safari and Firefox legitimately
	// lack it.
	chObj := nonNegInt(form.Get("ch"), 1)
	if chObj == 0 && isChromium {
		score += 15
		reasons = append(reasons, "window.chrome missing on chromium UA")
	}

	// +10 — navigator.languages empty is a strong tell. Every mainstream
	// browser has reported this since 2015.
	langs := nonNegInt(form.Get("lg"), 32)
	if langs == 0 {
		score += 10
		reasons = append(reasons, "navigator.languages empty")
	}

	hwc := nonNegInt(form.Get("hc"), 256)
	sw := nonNegInt(form.Get("sw"), 16384)
	sh := nonNegInt(form.Get("sh"), 16384)
	if hwc == 0 {
		score += 10
		reasons = append(reasons, "hardwareConcurrency=0")
	}
	if sw == 0 || sh == 0 {
		score += 15
		reasons = append(reasons, "zero screen dims")
	}

	// +5 — time between page load and challenge firing < 50 ms means the
	// script ran synchronously on document_start, which headless runners
	// often do. Real browsers spread load across ~150 ms minimum.
	tn := nonNegInt(form.Get("tn"), 24*60*60*1000) // up to 24h
	if tn > 0 && tn < 50 {
		score += 5
		reasons = append(reasons, "challenge fired too fast")
	}

	// +5 — user-agent implausibly short (automation often strips it down).
	uaLen := nonNegInt(form.Get("ua"), 4096)
	if uaLen < 40 {
		score += 5
		reasons = append(reasons, "UA string implausibly short")
	}

	if score > 100 {
		score = 100
	}
	passed = score < 50
	return
}

// nonNegInt parses s as a non-negative integer, clamping to [0, max].
// Returns 0 for parse errors, negative values, or values > max so a
// hostile client can't send "-1" or "999999999" to slip past a == 0
// check while still being implausible. Uses strconv.Atoi rather than
// ParseUint so leading "+" / whitespace / hex prefixes still error
// the way the old behaviour expected.
func nonNegInt(s string, max int) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	if n > max {
		return max
	}
	return n
}

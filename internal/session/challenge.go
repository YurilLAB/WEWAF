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

	// +20 — zero plugins is the default for headless Chrome. Real browsers
	// report 2+ (PDF viewer, Chromium PDF plugin, etc.). Firefox reports
	// 0 legitimately post-Quantum, so we have to be careful here:
	// cross-check with UA to avoid flagging Firefox users.
	plugins, _ := strconv.Atoi(form.Get("pl"))
	uaLower := strings.ToLower(userAgent)
	isFirefox := strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "gecko/")
	isChromium := strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "edg/")
	if plugins == 0 && isChromium && !isFirefox {
		score += 20
		reasons = append(reasons, "zero plugins on chromium UA")
	}

	// +15 — window.chrome missing on a Chrome UA is the classic "puppeteer
	// didn't patch it" tell. Safari and Firefox legitimately lack it.
	chObj, _ := strconv.Atoi(form.Get("ch"))
	if chObj == 0 && isChromium {
		score += 15
		reasons = append(reasons, "window.chrome missing on chromium UA")
	}

	// +10 — navigator.languages empty is a strong tell. Every mainstream
	// browser has reported this since 2015.
	langs, _ := strconv.Atoi(form.Get("lg"))
	if langs == 0 {
		score += 10
		reasons = append(reasons, "navigator.languages empty")
	}

	// +15 — 0x0 or 1920x1080 exactly + 0 hardware concurrency is the
	// Playwright/Puppeteer default viewport and worker config. Real
	// devices have non-zero hardwareConcurrency.
	hwc, _ := strconv.Atoi(form.Get("hc"))
	sw, _ := strconv.Atoi(form.Get("sw"))
	sh, _ := strconv.Atoi(form.Get("sh"))
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
	tn, _ := strconv.Atoi(form.Get("tn"))
	if tn > 0 && tn < 50 {
		score += 5
		reasons = append(reasons, "challenge fired too fast")
	}

	// +5 — user-agent implausibly short (automation often strips it down).
	uaLen, _ := strconv.Atoi(form.Get("ua"))
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

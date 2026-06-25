package engine

import "testing"

// TestUploadRFC2231ExtendedFilename covers UPLOAD-005: the RFC2231/5987
// extended-value filename (filename*=…, filename*0=…) carrying a dangerous
// extension — including the percent-encoded-dot form (shell%2Ephp) — which the
// contiguous `filename="…"` rules miss. Several upload stacks reassemble it.
func TestUploadRFC2231ExtendedFilename(t *testing.T) {
	eng := probeEngine(t)
	mustBlock := map[string]string{
		"extvalue-pct-dot": `Content-Disposition: form-data; name="f"; filename*=UTF-8''shell%2Ephp`,
		"extvalue-dot":     `Content-Disposition: form-data; name="f"; filename*=UTF-8''webshell.phtml`,
		"star0-jsp":        `Content-Disposition: form-data; name="f"; filename*0=backdoor.jsp`,
		"extvalue-aspx":    `Content-Disposition: form-data; name="f"; filename*=UTF-8''x%2easpx`,
	}
	for name, pl := range mustBlock {
		if !fireBlocked(eng, probe{payload: pl, target: "body"}) {
			t.Errorf("RFC2231 upload evasion %q PASSED unblocked: %s", name, pl)
		}
	}
	// Legitimate extended-value filenames (Unicode names, safe extensions) must
	// NOT be blocked.
	benign := map[string]string{
		"unicode-pdf": `Content-Disposition: form-data; name="f"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`,
		"png":         `Content-Disposition: form-data; name="f"; filename*=UTF-8''holiday%20photo.png`,
		"docx":        `Content-Disposition: form-data; name="f"; filename*0=quarterly.; filename*1=docx`,
	}
	for name, pl := range benign {
		if fireBlocked(eng, probe{payload: pl, target: "body"}) {
			t.Errorf("FALSE POSITIVE: benign upload %q blocked: %s", name, pl)
		}
	}
}

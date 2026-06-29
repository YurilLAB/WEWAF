package engine

import "testing"

// TestRedteamFP probes the new (and FP-prone) rules with BENIGN inputs that
// could plausibly trip them. blocked=true here is a false positive to fix.
func TestRedteamFP(t *testing.T) {
	eng := newFuzzEngine(t)
	benign := []string{
		// SQLI-037 (set operators) — English prose with the keywords.
		"everything except select items from the menu",
		"the intersection of two sets from the diagram",
		"10 minus 5 equals 5 from basic math",
		"you can select anything except the locked items",
		// SQLI-038 (CTE / WITH) — "with X as ..." prose.
		"with john as a witness we proceed to the next step",
		"starts with abc as the standard prefix from the docs",
		"begin with caution as the road from here is narrow",
		// SQLI-039 (JSON path operators) — arrows / pointers in prose & data.
		"click here -> next page",
		"flow: a -> b -> c -> done",
		"navigate to 'home' -> 'settings'",
		"the value a->b in our notation",
		// SSTI-007 (statement dunders) — benign Jinja with no dunder.
		"{% if user.is_admin %}hello{% endif %}",
		"{% for item in cart %}{{ item.name }}{% endfor %}",
		"my python class __init__ explained in the tutorial",
		// XSS-015 (modern handlers) — benign text and harmless tags.
		"please monitor the toggle switch state",
		"<button type=\"submit\">Save</button>",
		"the ontoggle event fires when a details element opens",
		"<p>pointer events are useful</p>",
	}
	for _, b := range benign {
		if blockedInFormBody(eng, b) {
			t.Errorf("FALSE POSITIVE (form body): %q", b)
		}
		if evasionBlocked(eng, b) {
			t.Errorf("FALSE POSITIVE (query arg): %q", b)
		}
	}
}

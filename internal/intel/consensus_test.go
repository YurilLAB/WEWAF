package intel

import "testing"

// TestConsensusMediumRequiresTwoSources is the regression for
// INTEL-CONSENSUS-001: a medium-confidence value must only enforce once >=2
// DISTINCT sources report it — a single (or self-repeating) medium feed must
// not auto-ban.
func TestConsensusMediumRequiresTwoSources(t *testing.T) {
	c := NewConsensus(2)
	if c.Enforce("1.2.3.4", "firehol-level1", ConfMedium) {
		t.Fatal("single medium source must NOT enforce")
	}
	if c.Enforce("1.2.3.4", "firehol-level1", ConfMedium) {
		t.Fatal("one source repeating a value must not manufacture consensus")
	}
	if !c.Enforce("1.2.3.4", "et-compromised", ConfMedium) {
		t.Fatal("two distinct medium sources should reach consensus")
	}
}

func TestConsensusHighEnforcesAlone(t *testing.T) {
	c := NewConsensus(2)
	if !c.Enforce("9.9.9.9", "spamhaus-drop", ConfHigh) {
		t.Fatal("a single high-confidence source must enforce immediately")
	}
}

func TestConsensusLowNeverEnforces(t *testing.T) {
	c := NewConsensus(2)
	if c.Enforce("8.8.8.8", "blocklist-de", ConfLow) {
		t.Fatal("low confidence must never auto-enforce")
	}
	if c.Enforce("8.8.8.8", "another-low", ConfLow) {
		t.Fatal("low confidence must never auto-enforce regardless of source count")
	}
}

// TestConsensusBoundedCap proves the tracker fails toward NOT banning once its
// memory cap is reached (so a feed flooding unique values can't exhaust memory
// or force enforcement), while values already tracked can still reach consensus.
func TestConsensusBoundedCap(t *testing.T) {
	c := NewConsensus(2)
	c.cap = 2
	c.Enforce("a", "s1", ConfMedium)
	c.Enforce("b", "s1", ConfMedium)
	if c.Enforce("c", "s1", ConfMedium) {
		t.Fatal("a new value beyond the cap must not be recorded/enforced")
	}
	if c.Enforce("c", "s2", ConfMedium) {
		t.Fatal("a capped-out value must stay non-enforcing even with a 2nd source")
	}
	if !c.Enforce("a", "s2", ConfMedium) {
		t.Fatal("an already-tracked value should still reach consensus from a 2nd source")
	}
}

package cluster

import "testing"

func self() NodeInfo {
	return NodeInfo{ID: "n1", Name: "edge-1", Cluster: "prod", Addr: "10.0.0.1:8443", Version: "test"}
}

func TestSnapshotSelfOnly(t *testing.T) {
	m := NewManager(self())
	v := m.Snapshot(NodeSummary{}, 1000, 120)
	if v.NodeCount != 1 {
		t.Fatalf("self-only cluster should have NodeCount 1, got %d", v.NodeCount)
	}
	if v.Self.ID != "n1" || len(v.Peers) != 0 {
		t.Fatalf("unexpected view: %+v", v)
	}
}

func TestRecordReachablePeer(t *testing.T) {
	m := NewManager(self())
	peer := NodeInfo{ID: "n2", Name: "edge-2", Cluster: "prod"}
	m.RecordPeerResult("https://p2/", true, 12, peer, NodeSummary{UnderAttack: true, BanCount: 5}, 1000)
	v := m.Snapshot(NodeSummary{}, 1000, 120)
	if v.NodeCount != 2 {
		t.Fatalf("self + 1 reachable peer => NodeCount 2, got %d", v.NodeCount)
	}
	if v.UnderAttack != 1 {
		t.Fatalf("peer under attack should count: UnderAttack=%d", v.UnderAttack)
	}
	if len(v.Peers) != 1 || v.Peers[0].Node.ID != "n2" || v.Peers[0].Summary.BanCount != 5 {
		t.Fatalf("peer summary not carried: %+v", v.Peers)
	}
}

func TestUnreachablePeerNotCounted(t *testing.T) {
	m := NewManager(self())
	m.RecordPeerResult("https://p2/", true, 5, NodeInfo{ID: "n2"}, NodeSummary{}, 1000)
	m.RecordPeerResult("https://p2/", false, 0, NodeInfo{}, NodeSummary{}, 1005)
	v := m.Snapshot(NodeSummary{}, 1005, 120)
	if v.NodeCount != 1 {
		t.Fatalf("unreachable peer must not count: NodeCount=%d", v.NodeCount)
	}
	if len(v.Peers) != 1 || v.Peers[0].Reachable {
		t.Fatalf("peer should be present but unreachable: %+v", v.Peers)
	}
	// Last-known identity is preserved for display even when unreachable.
	if v.Peers[0].Node.ID != "n2" {
		t.Fatalf("last-known identity should be preserved: %+v", v.Peers[0])
	}
}

func TestStalePeerMarkedUnreachable(t *testing.T) {
	m := NewManager(self())
	m.RecordPeerResult("https://p2/", true, 5, NodeInfo{ID: "n2"}, NodeSummary{UnderAttack: true}, 1000)
	// 300s later with a 120s staleness window -> stale -> unreachable, and its
	// under-attack no longer inflates the live count.
	v := m.Snapshot(NodeSummary{}, 1300, 120)
	if v.NodeCount != 1 {
		t.Fatalf("stale peer should drop out of NodeCount, got %d", v.NodeCount)
	}
	if v.UnderAttack != 0 {
		t.Fatalf("stale peer's under-attack must not count, got %d", v.UnderAttack)
	}
	if !(!v.Peers[0].Reachable) {
		t.Fatalf("stale peer should be reported unreachable: %+v", v.Peers[0])
	}
}

func TestSelfUnderAttackCounts(t *testing.T) {
	m := NewManager(self())
	v := m.Snapshot(NodeSummary{UnderAttack: true}, 1000, 120)
	if v.UnderAttack != 1 {
		t.Fatalf("self under attack should count: %d", v.UnderAttack)
	}
}

func TestNilManagerSafe(t *testing.T) {
	var m *Manager
	_ = m.Self()
	m.RecordPeerResult("x", true, 1, NodeInfo{}, NodeSummary{}, 1)
	v := m.Snapshot(NodeSummary{UnderAttack: true}, 1, 1)
	if v.NodeCount != 1 || v.UnderAttack != 1 {
		t.Fatalf("nil manager should still yield a self view: %+v", v)
	}
}

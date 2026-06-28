// Package cluster tracks WEWAF's native node clustering. WEWAF nodes coordinate
// directly via the built-in mesh (internal/web mesh-sync gossip) — there is no
// external control plane. This package holds this node's identity plus the
// membership + health of its peers (updated by the gossip loop), and serves a
// snapshot to the admin API / wafctl / ypanel so an operator can see and manage
// every machine running WEWAF in one view.
package cluster

import (
	"sync"
)

// NodeInfo is the stable identity of a WEWAF node.
type NodeInfo struct {
	ID      string `json:"id"`      // stable id for the node
	Name    string `json:"name"`    // operator label (defaults to hostname)
	Cluster string `json:"cluster"` // cluster grouping name
	Addr    string `json:"addr"`    // address peers reach it at
	Version string `json:"version"`
}

// NodeSummary is the live, gossiped operational state of a node.
type NodeSummary struct {
	UnderAttack     bool   `json:"under_attack"`
	TotalRequests   uint64 `json:"total_requests"`
	BlockedRequests uint64 `json:"blocked_requests"`
	BanCount        int    `json:"ban_count"`
}

// PeerStatus is a peer node's membership + health as seen from this node.
type PeerStatus struct {
	Node         NodeInfo    `json:"node"`
	URL          string      `json:"url"`
	Reachable    bool        `json:"reachable"`
	LastSeenUnix int64       `json:"last_seen_unix"`
	RTTms        int64       `json:"rtt_ms"`
	Summary      NodeSummary `json:"summary"`
}

// View is the cluster snapshot served to the API / CLI / UI.
type View struct {
	Self        NodeInfo     `json:"self"`
	SelfSummary NodeSummary  `json:"self_summary"`
	Peers       []PeerStatus `json:"peers"`
	NodeCount   int          `json:"node_count"`   // self + reachable peers
	UnderAttack int          `json:"under_attack"` // nodes currently under attack
	GeneratedAt int64        `json:"generated_at"`
}

// Manager tracks this node's identity and its peers' membership/health.
type Manager struct {
	mu    sync.RWMutex
	self  NodeInfo
	peers map[string]*PeerStatus // keyed by peer URL
}

// NewManager returns a cluster manager for the given local node identity.
func NewManager(self NodeInfo) *Manager {
	return &Manager{self: self, peers: make(map[string]*PeerStatus)}
}

// Self returns this node's identity.
func (m *Manager) Self() NodeInfo {
	if m == nil {
		return NodeInfo{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.self
}

// RecordPeerResult updates a peer from one gossip round. On a reachable result
// it refreshes last-seen, RTT, the peer's advertised identity (if provided), and
// its summary; on an unreachable result it only flips reachability (preserving
// the last-known identity/summary for display).
func (m *Manager) RecordPeerResult(url string, reachable bool, rttMs int64, node NodeInfo, summary NodeSummary, nowUnix int64) {
	if m == nil || url == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ps := m.peers[url]
	if ps == nil {
		ps = &PeerStatus{URL: url}
		m.peers[url] = ps
	}
	ps.Reachable = reachable
	ps.RTTms = rttMs
	if reachable {
		ps.LastSeenUnix = nowUnix
		if node.ID != "" {
			ps.Node = node
		}
		ps.Summary = summary
	}
}

// Snapshot builds the cluster view. selfSummary is supplied by the caller (the
// web layer reads live local stats). A peer last seen longer ago than
// staleAfterSec is reported unreachable even if its last gossip succeeded.
func (m *Manager) Snapshot(selfSummary NodeSummary, nowUnix, staleAfterSec int64) View {
	v := View{SelfSummary: selfSummary, GeneratedAt: nowUnix, NodeCount: 1}
	if selfSummary.UnderAttack {
		v.UnderAttack = 1
	}
	if m == nil {
		return v
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	v.Self = m.self
	v.Peers = make([]PeerStatus, 0, len(m.peers))
	for _, ps := range m.peers {
		p := *ps
		if p.Reachable && staleAfterSec > 0 && nowUnix-p.LastSeenUnix > staleAfterSec {
			p.Reachable = false
		}
		if p.Reachable {
			v.NodeCount++
			if p.Summary.UnderAttack {
				v.UnderAttack++
			}
		}
		v.Peers = append(v.Peers, p)
	}
	return v
}

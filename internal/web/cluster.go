package web

import (
	"net/http"
	"time"

	"wewaf/internal/cluster"
)

// clusterPeerStaleSec marks a peer unreachable in the cluster view if it hasn't
// gossiped successfully within this many seconds (≈3 gossip intervals).
const clusterPeerStaleSec = 180

// AttachCluster wires the native cluster manager so /api/cluster can serve the
// membership/health view of every WEWAF node in the mesh.
func (s *Server) AttachCluster(m *cluster.Manager) {
	if s == nil {
		return
	}
	s.cluster = m
}

// selfSummary builds this node's live operational summary (under-attack +
// request/block totals + ban count) from the proxy/metrics/ban subsystems. It
// feeds both /api/cluster and the mesh gossip so peers learn this node's state.
func (s *Server) selfSummary() cluster.NodeSummary {
	sum := cluster.NodeSummary{}
	if s == nil {
		return sum
	}
	if s.proxy != nil {
		if v, ok := s.proxy.DDoSStats()["under_attack"].(bool); ok {
			sum.UnderAttack = v
		}
	}
	if s.metrics != nil {
		snap := s.metrics.Snapshot()
		sum.TotalRequests = toUint64(snap["total_requests"])
		sum.BlockedRequests = toUint64(snap["blocked_requests"])
	}
	if s.banList != nil {
		sum.BanCount = s.banList.Count()
	}
	return sum
}

// handleCluster returns the cluster membership + health view. When clustering
// isn't configured it still reports this single node so the UI/CLI render one.
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cluster == nil {
		self := cluster.NodeInfo{}
		if s.cfg != nil {
			self.Name = s.cfg.NodeName
			self.Cluster = s.cfg.ClusterName
		}
		writeJSON(w, cluster.View{
			Self:        self,
			SelfSummary: s.selfSummary(),
			Peers:       []cluster.PeerStatus{},
			NodeCount:   1,
			GeneratedAt: time.Now().Unix(),
		})
		return
	}
	view := s.cluster.Snapshot(s.selfSummary(), time.Now().Unix(), clusterPeerStaleSec)
	writeJSON(w, view)
}

// toUint64 coerces a metrics-snapshot value (which may be uint64/int/int64/
// float64 depending on the source) to uint64, clamping negatives to 0.
func toUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n > 0 {
			return uint64(n)
		}
	case int:
		if n > 0 {
			return uint64(n)
		}
	case float64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

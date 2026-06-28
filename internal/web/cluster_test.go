package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wewaf/internal/cluster"
	"wewaf/internal/config"
)

func TestHandleClusterNilManagerReportsSelf(t *testing.T) {
	s := &Server{cfg: &config.Config{NodeName: "edge-1", ClusterName: "prod"}}
	req := httptest.NewRequest(http.MethodGet, "/api/cluster", nil)
	rec := httptest.NewRecorder()
	s.handleCluster(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var v cluster.View
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.NodeCount != 1 || v.Self.Name != "edge-1" || v.Self.Cluster != "prod" {
		t.Fatalf("unexpected self view: %+v", v)
	}
	if v.Peers == nil {
		t.Fatal("peers should be an empty array, not null")
	}
}

func TestHandleClusterWithPeers(t *testing.T) {
	m := cluster.NewManager(cluster.NodeInfo{ID: "n1", Name: "edge-1", Cluster: "prod"})
	m.RecordPeerResult("https://p2/", true, 7,
		cluster.NodeInfo{ID: "n2", Name: "edge-2", Cluster: "prod"},
		cluster.NodeSummary{UnderAttack: true, BanCount: 3}, time.Now().Unix())
	s := &Server{cfg: &config.Config{}}
	s.AttachCluster(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster", nil)
	rec := httptest.NewRecorder()
	s.handleCluster(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var v cluster.View
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.NodeCount != 2 {
		t.Fatalf("self + reachable peer => NodeCount 2, got %d", v.NodeCount)
	}
	if v.UnderAttack != 1 {
		t.Fatalf("peer under attack should count: %d", v.UnderAttack)
	}
	if len(v.Peers) != 1 || v.Peers[0].Node.ID != "n2" {
		t.Fatalf("peer not surfaced: %+v", v.Peers)
	}
}

func TestHandleClusterRejectsNonGet(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/cluster", nil)
	rec := httptest.NewRecorder()
	s.handleCluster(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

func TestToUint64(t *testing.T) {
	cases := []struct {
		in   interface{}
		want uint64
	}{
		{uint64(5), 5}, {int(7), 7}, {int64(9), 9}, {float64(11), 11},
		{int(-3), 0}, {float64(-2), 0}, {"x", 0}, {nil, 0},
	}
	for _, c := range cases {
		if got := toUint64(c.in); got != c.want {
			t.Errorf("toUint64(%v)=%d, want %d", c.in, got, c.want)
		}
	}
}

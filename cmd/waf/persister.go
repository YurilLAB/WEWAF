package main

import (
	"wewaf/internal/history"
	"wewaf/internal/telemetry"
)

// historyPersister adapts a *history.Store to the telemetry.Persister interface.
// It lives here (and not in either package) so history doesn't depend on
// telemetry's struct types and telemetry doesn't depend on history.
type historyPersister struct {
	store *history.Store
}

func newHistoryPersister(s *history.Store) *historyPersister {
	return &historyPersister{store: s}
}

func (h *historyPersister) EnqueueBlock(e telemetry.BlockEvent) {
	if h == nil || h.store == nil {
		return
	}
	h.store.EnqueueBlock(history.BlockEvent{
		Timestamp:    e.Timestamp,
		IP:           e.IP,
		Method:       e.Method,
		Path:         e.Path,
		RuleID:       e.RuleID,
		RuleCategory: e.RuleCategory,
		Score:        e.Score,
		Message:      e.Message,
	})
}

func (h *historyPersister) EnqueueRequest(ip string, blocked bool) {
	if h == nil || h.store == nil {
		return
	}
	h.store.EnqueueRequest(ip, blocked)
}

func (h *historyPersister) EnqueueTrafficPoint(p telemetry.BlockTrafficPoint) {
	if h == nil || h.store == nil {
		return
	}
	h.store.EnqueueTrafficPoint(history.TrafficPoint{
		Timestamp: p.Timestamp,
		Requests:  p.Requests,
		Blocked:   p.Blocked,
		BytesIn:   p.BytesIn,
		BytesOut:  p.BytesOut,
	})
}

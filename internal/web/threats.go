package web

import (
	"net/http"
	"time"

	"wewaf/internal/history"
)

// Threat-signal emission (cluster hub-and-spoke alerting). A node exposes its
// current threat posture so the ypanel-agent can include it in the snapshot and
// the worker can correlate it across cluster peers. The worker treats each
// node's offender list as ONE source: only when >=2 distinct peers report the
// same IP does it reach consensus and fan out a pre-emptive ban — and every such
// ban still passes the never-ban allowlist. That keeps a single compromised node
// from weaponizing the cluster into a self-ban DoS.

// ThreatOffender is one IP this node has recently flagged.
type ThreatOffender struct {
	IP       string `json:"ip"`
	Blocks   int64  `json:"blocks"`
	Requests int64  `json:"requests"`
	Banned   bool   `json:"banned"`
}

const (
	threatWindow    = 15 * time.Minute
	threatMinBlocks = 3
	threatTopN      = 50
)

// threatOffenders filters recent IP activity down to high-confidence offenders
// (>= minBlocks blocks within the window), preserving the input order (the
// history query returns most-active first) up to topN. Pure for testability.
func threatOffenders(ips []history.IPActivity, isBanned func(string) bool, minBlocks int64, topN int) []ThreatOffender {
	out := make([]ThreatOffender, 0, topN)
	for _, a := range ips {
		if a.BlockCount < minBlocks {
			continue
		}
		banned := false
		if isBanned != nil {
			banned = isBanned(a.IP)
		}
		out = append(out, ThreatOffender{
			IP:       a.IP,
			Blocks:   a.BlockCount,
			Requests: a.RequestCount,
			Banned:   banned,
		})
		if len(out) >= topN {
			break
		}
	}
	return out
}

// handleThreats reports this node's threat posture: an under-attack flag plus
// recent high-confidence offender IPs. Read-only, bounded. Behind the admin
// auth like every other /api/* route.
func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	underAttack := false
	if s.proxy != nil {
		if v, ok := s.proxy.DDoSStats()["under_attack"].(bool); ok {
			underAttack = v
		}
	}
	offenders := []ThreatOffender{}
	if s.history != nil {
		to := time.Now()
		from := to.Add(-threatWindow)
		// Over-fetch then filter by block count so the cap applies to genuine
		// offenders, not merely the busiest IPs.
		if ips, err := s.history.QueryIPs(from, to, threatTopN*4); err == nil {
			var isBanned func(string) bool
			if s.banList != nil {
				isBanned = s.banList.IsBanned
			}
			offenders = threatOffenders(ips, isBanned, threatMinBlocks, threatTopN)
		}
	}
	writeJSON(w, map[string]interface{}{
		"under_attack": underAttack,
		"generated_at": time.Now().UTC(),
		"offenders":    offenders,
	})
}

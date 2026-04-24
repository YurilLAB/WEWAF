package telemetry

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// WritePrometheus writes all current metrics in Prometheus text exposition
// format 0.0.4 (the format every Prometheus server and vmagent can scrape).
// We hand-roll the output to avoid pulling the ~1 MB prometheus/client_golang
// dependency — the schema is small and stable.
//
// https://prometheus.io/docs/instrumenting/exposition_formats/
func (m *Metrics) WritePrometheus(w io.Writer) error {
	if m == nil || w == nil {
		return nil
	}
	m.mu.RLock()
	total := m.TotalRequests
	blocked := m.BlockedRequests
	passed := m.PassedRequests
	bytesIn := m.TotalBytesIn
	bytesOut := m.TotalBytesOut
	errs := m.ErrorCount
	egressB := m.EgressBlocked
	egressA := m.EgressAllowed
	bots := m.BotsDetected
	uniqueIPs := len(m.UniqueIPs)
	bytesInPS := m.CurrentBytesInPS
	bytesOutPS := m.CurrentBytesOutPS
	statusCopy := make(map[int]uint64, len(m.StatusCounts))
	for k, v := range m.StatusCounts {
		statusCopy[k] = v
	}
	ruleCopy := make(map[string]uint64, len(m.RuleCounters))
	for k, v := range m.RuleCounters {
		ruleCopy[k] = v
	}
	m.mu.RUnlock()

	// Core counters.
	writeCounter(w, "wewaf_requests_total", "All requests seen by the proxy.", total)
	writeCounter(w, "wewaf_blocked_total", "Requests the WAF blocked.", blocked)
	writeCounter(w, "wewaf_passed_total", "Requests forwarded to the backend.", passed)
	writeCounter(w, "wewaf_errors_total", "Proxy errors (backend failures, etc).", errs)
	writeCounter(w, "wewaf_egress_blocked_total", "Egress requests blocked.", egressB)
	writeCounter(w, "wewaf_egress_allowed_total", "Egress requests allowed.", egressA)
	writeCounter(w, "wewaf_bots_detected_total", "Requests matched a bot/scanner signature.", bots)
	writeGauge(w, "wewaf_unique_ips", "Distinct source IPs since last history rotation.", uint64(uniqueIPs))
	writeGauge(w, "wewaf_bytes_in_per_second", "Ingress bytes per second (last 10 s window).", bytesInPS)
	writeGauge(w, "wewaf_bytes_out_per_second", "Egress bytes per second (last 10 s window).", bytesOutPS)
	writeCounter(w, "wewaf_bytes_in_total", "Cumulative ingress bytes.", bytesIn)
	writeCounter(w, "wewaf_bytes_out_total", "Cumulative egress bytes.", bytesOut)

	// Response status distribution as a labeled counter.
	if len(statusCopy) > 0 {
		fmt.Fprintln(w, "# HELP wewaf_response_status Response status distribution (bucketed by hundreds).")
		fmt.Fprintln(w, "# TYPE wewaf_response_status counter")
		keys := make([]int, 0, len(statusCopy))
		for k := range statusCopy {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "wewaf_response_status{bucket=\"%d\"} %d\n", k, statusCopy[k])
		}
	}

	// Per-rule counters — the key feature for tuning noisy rules.
	if len(ruleCopy) > 0 {
		fmt.Fprintln(w, "# HELP wewaf_rule_matches_total Matches per rule ID.")
		fmt.Fprintln(w, "# TYPE wewaf_rule_matches_total counter")
		ids := make([]string, 0, len(ruleCopy))
		for k := range ruleCopy {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(w, "wewaf_rule_matches_total{rule_id=\"%s\"} %d\n", escapeLabel(id), ruleCopy[id])
		}
	}

	return nil
}

func writeCounter(w io.Writer, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, value)
}

func writeGauge(w io.Writer, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %d\n", name, value)
}

// escapeLabel quotes the characters Prometheus's label syntax treats as
// special (backslash, double-quote, newline).
func escapeLabel(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(s)
}

// strconvItoaU64 keeps callers free of strconv imports.
func strconvItoaU64(n uint64) string { return strconv.FormatUint(n, 10) }

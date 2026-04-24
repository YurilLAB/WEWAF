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
// The exposition is written to an in-memory buffer first, then flushed to w
// in one call. That keeps a slow-scraping client from seeing a half-written
// exposition (which Prometheus treats as a scrape failure) and avoids
// holding the metrics read lock across network I/O.
//
// https://prometheus.io/docs/instrumenting/exposition_formats/
func (m *Metrics) WritePrometheus(w io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("prometheus: panic during exposition: %v", r)
		}
	}()
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

	var buf strings.Builder
	buf.Grow(4096 + len(ruleCopy)*64)

	// Core counters.
	writeCounter(&buf, "wewaf_requests_total", "All requests seen by the proxy.", total)
	writeCounter(&buf, "wewaf_blocked_total", "Requests the WAF blocked.", blocked)
	writeCounter(&buf, "wewaf_passed_total", "Requests forwarded to the backend.", passed)
	writeCounter(&buf, "wewaf_errors_total", "Proxy errors (backend failures, etc).", errs)
	writeCounter(&buf, "wewaf_egress_blocked_total", "Egress requests blocked.", egressB)
	writeCounter(&buf, "wewaf_egress_allowed_total", "Egress requests allowed.", egressA)
	writeCounter(&buf, "wewaf_bots_detected_total", "Requests matched a bot/scanner signature.", bots)
	writeGauge(&buf, "wewaf_unique_ips", "Distinct source IPs since last history rotation.", uint64(uniqueIPs))
	writeGauge(&buf, "wewaf_bytes_in_per_second", "Ingress bytes per second (last 10 s window).", bytesInPS)
	writeGauge(&buf, "wewaf_bytes_out_per_second", "Egress bytes per second (last 10 s window).", bytesOutPS)
	writeCounter(&buf, "wewaf_bytes_in_total", "Cumulative ingress bytes.", bytesIn)
	writeCounter(&buf, "wewaf_bytes_out_total", "Cumulative egress bytes.", bytesOut)

	// Response status distribution as a labeled counter.
	if len(statusCopy) > 0 {
		buf.WriteString("# HELP wewaf_response_status Response status distribution (bucketed by hundreds).\n")
		buf.WriteString("# TYPE wewaf_response_status counter\n")
		keys := make([]int, 0, len(statusCopy))
		for k := range statusCopy {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			fmt.Fprintf(&buf, "wewaf_response_status{bucket=\"%d\"} %d\n", k, statusCopy[k])
		}
	}

	// Per-rule counters — the key feature for tuning noisy rules. Capped
	// output so a scrape can't stall on 10k+ labels (Prometheus best
	// practice: keep per-metric cardinality in the low thousands).
	if len(ruleCopy) > 0 {
		buf.WriteString("# HELP wewaf_rule_matches_total Matches per rule ID.\n")
		buf.WriteString("# TYPE wewaf_rule_matches_total counter\n")
		ids := make([]string, 0, len(ruleCopy))
		for k := range ruleCopy {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		const maxRuleCardinality = 2048
		if len(ids) > maxRuleCardinality {
			ids = ids[:maxRuleCardinality]
		}
		for _, id := range ids {
			fmt.Fprintf(&buf, "wewaf_rule_matches_total{rule_id=\"%s\"} %d\n", escapeLabel(id), ruleCopy[id])
		}
	}

	_, err = w.Write([]byte(buf.String()))
	return err
}

func writeCounter(w *strings.Builder, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, value)
}

func writeGauge(w *strings.Builder, name, help string, value uint64) {
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

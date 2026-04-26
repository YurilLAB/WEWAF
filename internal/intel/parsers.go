package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ParseLinePerIP handles the most common feed format: one IP or CIDR
// per line, possibly with `# comment` lines and blank lines. Used by
// FireHOL Level 1, blocklist.de, CINS Score, ET compromised, and
// Spamhaus DROP txt.
//
// Lines containing semicolons are accepted because Spamhaus DROP uses
// the format `1.2.3.0/24 ; SBL12345` — we keep only the CIDR portion.
func ParseLinePerIP(body []byte, source string) ([]Entry, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	out := make([]Entry, 0, 4096)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// Some feeds publish very long comment lines; raise the buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Strip comments. # at start; ; mid-line for Spamhaus.
		if strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, ";#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		entry, ok := classifyIP(line)
		if !ok {
			continue
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if len(out) == 0 {
		return nil, errors.New("no records parsed")
	}
	return out, nil
}

// dangerousFeedRanges are CIDRs we MUST refuse to ingest from a
// third-party feed regardless of source. A compromised or buggy feed
// publishing 0.0.0.0/0 would otherwise ban every IPv4 address; the
// link-local / loopback / RFC1918 ranges should never appear in a
// reputation feed and including them would sever localhost / health
// checks / internal traffic.
var dangerousFeedRanges = func() []*net.IPNet {
	in := []string{
		"0.0.0.0/0", "::/0",
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fc00::/7", "fe80::/10",
	}
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isDangerousRange reports whether ipnet equals or is broader than any
// of the always-refused ranges. The "broader-than" check uses prefix
// length: a /0 from a feed should be rejected even if it's labelled
// "1.2.3.4/0" (technically valid CIDR notation that still covers the
// whole Internet).
func isDangerousRange(ipnet *net.IPNet) bool {
	feedOnes, _ := ipnet.Mask.Size()
	for _, bad := range dangerousFeedRanges {
		badOnes, _ := bad.Mask.Size()
		// Reject if the feed's prefix is at least as broad as a
		// dangerous range AND covers the same address family.
		if (bad.IP.To4() != nil) != (ipnet.IP.To4() != nil) {
			continue
		}
		if feedOnes <= badOnes && bad.Contains(ipnet.IP) {
			return true
		}
		if feedOnes <= badOnes && ipnet.Contains(bad.IP) {
			return true
		}
	}
	return false
}

func classifyIP(s string) (Entry, bool) {
	// Accept either a bare IP or a CIDR. Reject anything else so a
	// random word in a comment doesn't get treated as an entry.
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return Entry{}, false
		}
		if isDangerousRange(ipnet) {
			return Entry{}, false
		}
		k := KindIPv4
		if ipnet.IP.To4() == nil {
			k = KindIPv6
		}
		return Entry{Kind: k, Value: ipnet.String(), Reason: "feed"}, true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return Entry{}, false
	}
	// Reject loopback / link-local / unspecified bare IPs from feeds —
	// these should never come from a reputation list and including
	// them in the ban set breaks local probes / health checks.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return Entry{}, false
	}
	k := KindIPv4
	suffix := "/32"
	if ip.To4() == nil {
		k = KindIPv6
		suffix = "/128"
	}
	return Entry{Kind: k, Value: ip.String() + suffix, Reason: "feed"}, true
}

// ParseSSLBLJA3 reads the abuse.ch JA3 fingerprint CSV. Format
// (after a # comment header):
//
//	ja3_md5,Listingreason
//
// We accept either a 32-char hex hash (current format) or the older
// listing where the first column was a description and the second
// was the hash — robust against a publisher format swap.
func ParseSSLBLJA3(body []byte, source string) ([]Entry, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	r := csv.NewReader(bytes.NewReader(body))
	r.Comment = '#'
	r.FieldsPerRecord = -1

	out := make([]Entry, 0, 256)
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		var hash, reason string
		switch len(rec) {
		case 0, 1:
			continue
		case 2, 3, 4, 5:
			// Try column 0 first; fall back to column 1.
			c0 := strings.TrimSpace(rec[0])
			if isHex32(c0) {
				hash = c0
				if len(rec) > 1 {
					reason = strings.TrimSpace(rec[1])
				}
				break
			}
			if len(rec) > 1 {
				c1 := strings.TrimSpace(rec[1])
				if isHex32(c1) {
					hash = c1
					reason = strings.TrimSpace(rec[0])
				}
			}
		}
		if hash == "" {
			continue
		}
		out = append(out, Entry{
			Kind:   KindJA3,
			Value:  strings.ToLower(hash),
			Reason: reason,
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no JA3 records parsed")
	}
	return out, nil
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ParseLinePerUA reads a flat list of bad-bot UA substrings (the
// mitchellkrogza format). Empty lines and # comments ignored. Each
// line becomes a single Entry whose Value is the substring to match
// against User-Agent (case-insensitive at use time).
//
// We deliberately cap entry length at 512 bytes — a feed entry
// longer than that is almost certainly a parser misalignment, not a
// legitimate UA pattern.
func ParseLinePerUA(body []byte, source string) ([]Entry, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 32*1024), 256*1024)
	out := make([]Entry, 0, 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 512 {
			continue
		}
		// nginx-format files sometimes wrap entries in `~*"..."` regex
		// markers, sometimes followed by `;`. Strip the trailing `;`
		// FIRST so the surrounding-quote trim that follows can do its
		// job; otherwise `Trim` only sees the `;` at the right edge.
		line = strings.TrimRight(line, "; \t")
		line = strings.Trim(line, "\"~*")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, Entry{Kind: KindUA, Value: line})
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if len(out) == 0 {
		return nil, errors.New("no UA records parsed")
	}
	return out, nil
}

// ParseCISAKEV reads the CISA Known Exploited Vulnerabilities feed.
// Each entry is { cveID, vendorProject, product, vulnerabilityName, ...}.
// We emit one KindCVE entry per record so the downstream sink can
// attach virtual-patch metadata.
func ParseCISAKEV(body []byte, source string) ([]Entry, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	var doc struct {
		Vulnerabilities []struct {
			CveID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			DueDate           string `json:"dueDate"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	out := make([]Entry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		out = append(out, Entry{
			Kind:   KindCVE,
			Value:  v.CveID,
			Reason: fmt.Sprintf("%s/%s: %s (added %s)", v.VendorProject, v.Product, v.VulnerabilityName, v.DateAdded),
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no KEV records parsed")
	}
	return out, nil
}

// ParseSpamhausDropJSON reads the JSON variant of Spamhaus DROP /
// EDROP. Each line is a JSON object: {"cidr":"1.2.3.0/24","sblid":"SBL...",...}.
// Note: this is *NDJSON* — newline-delimited, not a JSON array — so
// we scan line by line.
func ParseSpamhausDropJSON(body []byte, source string) ([]Entry, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 32*1024), 256*1024)
	out := make([]Entry, 0, 1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec struct {
			CIDR  string `json:"cidr"`
			SBLID string `json:"sblid"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.CIDR == "" {
			continue
		}
		entry, ok := classifyIP(rec.CIDR)
		if !ok {
			continue
		}
		entry.Reason = rec.SBLID
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if len(out) == 0 {
		return nil, errors.New("no Spamhaus records parsed")
	}
	return out, nil
}

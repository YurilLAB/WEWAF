package intel

import "time"

// DefaultSources returns the curated free-feed list. All entries are
// permissively-licensed and free for commercial use; the License
// field surfaces in the admin UI for compliance review.
//
// Refresh cadences are deliberately conservative: we do not want
// to hammer community infrastructure. ETag/If-Modified-Since on
// every fetch means a "no-change" response is just two RTTs
// regardless.
//
// Confidence ratings reflect operator-facing trust:
//
//	high   — authoritative, low-FP (Spamhaus DROP, CISA KEV)
//	medium — well-curated community lists (FireHOL L1, SSLBL JA3)
//	low    — bulk crowdsourced (blocklist.de, mitchellkrogza UAs);
//	         use as score-only, never auto-block on a single hit
func DefaultSources() []Source {
	return []Source{
		{
			Name:         "firehol-level1",
			URL:          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			Mirror:       "https://iplists.firehol.org/files/firehol_level1.netset",
			Kind:         KindIPv4,
			Confidence:   ConfMedium,
			RefreshEvery: time.Hour,
			Parser:       ParseLinePerIP,
			License:      "GPLv2 — commercial use OK",
		},
		{
			Name:         "spamhaus-drop",
			URL:          "https://www.spamhaus.org/drop/drop.txt",
			Mirror:       "https://www.spamhaus.org/drop/drop_v4.json",
			Kind:         KindIPv4,
			Confidence:   ConfHigh,
			RefreshEvery: 6 * time.Hour,
			Parser:       ParseLinePerIP, // mirror auto-falls-back; the JSON parser handles either via header sniff
			License:      "Free for own infra (attribution)",
		},
		{
			Name:         "blocklist-de",
			URL:          "https://lists.blocklist.de/lists/all.txt",
			Kind:         KindIPv4,
			Confidence:   ConfLow,
			RefreshEvery: 30 * time.Minute,
			Parser:       ParseLinePerIP,
			License:      "Free, CC-BY",
		},
		{
			Name:         "cins-badguys",
			URL:          "http://cinsscore.com/list/ci-badguys.txt",
			Kind:         KindIPv4,
			Confidence:   ConfLow,
			RefreshEvery: 6 * time.Hour,
			Parser:       ParseLinePerIP,
			License:      "Free",
		},
		{
			Name:         "et-compromised",
			URL:          "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Kind:         KindIPv4,
			Confidence:   ConfMedium,
			RefreshEvery: 6 * time.Hour,
			Parser:       ParseLinePerIP,
			License:      "BSD; commercial use OK",
		},
		{
			Name:         "sslbl-ja3",
			URL:          "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
			Kind:         KindJA3,
			Confidence:   ConfMedium,
			RefreshEvery: time.Hour,
			Parser:       ParseSSLBLJA3,
			License:      "CC0; commercial use OK",
		},
		{
			Name:         "bad-user-agents",
			URL:          "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
			Kind:         KindUA,
			Confidence:   ConfLow,
			RefreshEvery: 24 * time.Hour,
			Parser:       ParseLinePerUA,
			License:      "MIT",
		},
		{
			Name:         "cisa-kev",
			URL:          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			Mirror:       "https://raw.githubusercontent.com/cisagov/kev-data/main/kev.json",
			Kind:         KindCVE,
			Confidence:   ConfHigh,
			RefreshEvery: 6 * time.Hour,
			Parser:       ParseCISAKEV,
			License:      "U.S. public domain",
		},
	}
}

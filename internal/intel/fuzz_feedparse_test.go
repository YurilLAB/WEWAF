package intel

import (
	"net"
	"strings"
	"testing"
)

// The feed parsers ingest untrusted, remotely-fetched blocklist bodies (FireHOL,
// blocklist.de, Spamhaus DROP, abuse.ch, …). A compromised, hijacked, or simply
// buggy feed is fully attacker-influenced input. A panic is a DoS of the intel
// updater; far worse, an emitted ban entry for a NON-PUBLIC or OVER-BROAD range
// would sever localhost / RFC1918 / health-check traffic or ban a huge slice of
// the internet — so the parser's refusal of those is a security invariant, not a
// nicety. These fuzzers assert no-panic AND that invariant on every emitted
// entry.
//
// Run:  go test ./internal/intel -run x -fuzz FuzzParseLinePerIP -fuzztime 30s
func FuzzParseLinePerIP(f *testing.F) {
	for _, s := range []string{
		"1.2.3.4\n5.6.7.8/24\n# comment\n",
		"1.2.3.0/24 ; SBL12345\n",
		"0.0.0.0/0\n10.0.0.1\n127.0.0.1\n169.254.169.254\n", // all must be refused
		"::ffff:0:0/96\n",                                   // disguised 0.0.0.0/0
		"::/0\n192.168.1.1/32\nfe80::1\n",
		"not an ip\n\n\n;;;\n0x7f000001\n2130706433\n",
		"255.255.255.255\n224.0.0.1\n100.64.0.1\n",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseLinePerIP(body, "fuzz")
		if err != nil {
			return // "empty"/"no records" are the normal non-result paths
		}
		for _, e := range entries {
			// The parser always emits a CIDR value (bare IPs get /32 or /128).
			ip, ipnet, perr := net.ParseCIDR(e.Value)
			if perr != nil {
				t.Fatalf("emitted unparseable entry value %q", e.Value)
			}
			// SAFETY INVARIANT 1: never a non-public destination.
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				t.Fatalf("feed parser emitted a NON-PUBLIC ban entry %q (would sever internal traffic)", e.Value)
			}
			// SAFETY INVARIANT 2: never over-broad (ban-most-of-the-internet).
			ones, bits := ipnet.Mask.Size()
			if (bits == 32 && ones < 8) || (bits == 128 && ones < 20) {
				t.Fatalf("feed parser emitted an OVER-BROAD ban entry %q (mask /%d)", e.Value, ones)
			}
		}
	})
}

// FuzzParseSpamhausDropJSON fuzzes the NDJSON DROP/EDROP variant. It routes
// every record through classifyIP, so it must satisfy the SAME safety invariant
// as ParseLinePerIP: no emitted ban entry may be non-public or over-broad. A
// hostile feed that swaps the txt format for JSON must not get a second,
// weaker path to smuggle a dangerous ban entry in.
func FuzzParseSpamhausDropJSON(f *testing.F) {
	for _, s := range []string{
		"{\"cidr\":\"1.2.3.0/24\",\"sblid\":\"SBL1\"}\n",
		"{\"cidr\":\"0.0.0.0/0\"}\n{\"cidr\":\"10.0.0.0/8\"}\n", // must be refused
		"{\"cidr\":\"::ffff:0:0/96\"}\n",                       // disguised /0
		"not json\n{}\n{\"cidr\":\"\"}\n{\"cidr\":\"0.0.0.0/9\"}\n",
		"{\"cidr\":\"224.0.0.0/4\"}\n{\"cidr\":\"240.0.0.0/4\"}\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseSpamhausDropJSON(body, "fuzz")
		if err != nil {
			return
		}
		for _, e := range entries {
			ip, ipnet, perr := net.ParseCIDR(e.Value)
			if perr != nil {
				t.Fatalf("emitted unparseable entry value %q", e.Value)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				t.Fatalf("DROP-JSON parser emitted a NON-PUBLIC ban entry %q", e.Value)
			}
			ones, bits := ipnet.Mask.Size()
			if (bits == 32 && ones < 8) || (bits == 128 && ones < 20) {
				t.Fatalf("DROP-JSON parser emitted an OVER-BROAD ban entry %q (mask /%d)", e.Value, ones)
			}
		}
	})
}

// FuzzParseSSLBLJA3 asserts the abuse.ch JA3 CSV parser never panics and only
// ever emits a well-formed fingerprint: a 32-char lowercase-hex MD5 tagged
// KindJA3. A malformed value here would silently corrupt the JA3 match set.
func FuzzParseSSLBLJA3(f *testing.F) {
	for _, s := range []string{
		"# ja3_md5,reason\n" + "0123456789abcdef0123456789abcdef,Malware\n",
		"Trojan,0123456789ABCDEF0123456789ABCDEF\n", // swapped columns, upper-hex
		"notahash,alsonot\n\n,,\n",
		"deadbeef,short\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseSSLBLJA3(body, "fuzz")
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Kind != KindJA3 {
				t.Fatalf("JA3 parser emitted non-JA3 kind %v", e.Kind)
			}
			if len(e.Value) != 32 || !isHex32(e.Value) || e.Value != strings.ToLower(e.Value) {
				t.Fatalf("JA3 parser emitted a malformed fingerprint %q", e.Value)
			}
		}
	})
}

// FuzzParseCISAKEV asserts the CISA KEV JSON parser never panics on arbitrary
// JSON and only emits non-empty CVE-kind entries (no blank virtual-patch keys).
func FuzzParseCISAKEV(f *testing.F) {
	for _, s := range []string{
		`{"vulnerabilities":[{"cveID":"CVE-2024-1234","vendorProject":"Acme","product":"X"}]}`,
		`{"vulnerabilities":[{"cveID":""},{"cveID":"CVE-2025-0001"}]}`,
		`{}`, `[]`, `null`, `{"vulnerabilities":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseCISAKEV(body, "fuzz")
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Kind != KindCVE {
				t.Fatalf("KEV parser emitted non-CVE kind %v", e.Kind)
			}
			if e.Value == "" {
				t.Fatalf("KEV parser emitted an empty CVE id")
			}
		}
	})
}

// FuzzParseLinePerUA asserts the UA-blocklist parser never panics and respects
// its own bounds (no empty entry; the 512-char per-line cap holds), so a hostile
// feed can't smuggle a pathological entry into the UA match set.
func FuzzParseLinePerUA(f *testing.F) {
	for _, s := range []string{
		"sqlmap\nnikto\n# header\n",
		"~*\"BadBot\";\n",
		"\n\n   \n\";~*\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseLinePerUA(body, "fuzz")
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Value == "" {
				t.Fatalf("UA parser emitted an empty entry")
			}
			if len(e.Value) > 512 {
				t.Fatalf("UA parser emitted an over-long entry (%d bytes)", len(e.Value))
			}
		}
	})
}

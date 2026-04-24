package zerotrust

// Templates returns ready-made policy examples so operators aren't staring at
// a blank editor. Each template is a complete, sensible starting point for a
// common protected-path shape; the UI exposes these via
// /api/zerotrust/templates so they can be applied and then tweaked.
//
// Every template ships in Simulate mode so a hasty click doesn't lock the
// operator out of their own admin panel. Switching Simulate off is one field
// change in the editor.
func Templates() []*Policy {
	return []*Policy{
		{
			ID:                "tmpl-admin-panel",
			Description:       "Admin panel — require mTLS and allow only office CIDR; deny-by-default for safety",
			PathPrefix:        "/admin",
			RequireMTLS:       true,
			AllowedCIDRs:      []string{"10.0.0.0/8", "192.168.0.0/16"},
			DenyByDefault:     true,
			FallbackAllow:     false,
			Simulate:          true,
		},
		{
			ID:          "tmpl-public-api-ratelimit",
			Description: "Public API — require bearer token, block known-bad countries",
			PathPrefix:  "/api/v1",
			Methods:     []string{"POST", "PUT", "PATCH", "DELETE"},
			RequireAuthHeader: "Authorization",
			BlockedCountries:  []string{"RU", "KP", "IR", "SY"},
			FallbackAllow:     true,
			Simulate:          true,
		},
		{
			ID:          "tmpl-banking-business-hours",
			Description: "Banking flows — only reachable during business hours (09:00-17:00 UTC)",
			PathPrefix:  "/bank",
			RequireAuthHeader: "Authorization",
			AllowedCountries:  []string{"US", "CA", "GB", "DE", "FR"},
			TimeStart:         "09:00",
			TimeEnd:           "17:00",
			FallbackAllow:     false,
			Simulate:          true,
		},
		{
			ID:          "tmpl-block-datacenters",
			Description: "Block common datacenter CIDRs for user-facing paths",
			PathPrefix:  "/",
			BlockedCIDRs: []string{
				// AWS us-east-1 public ranges (subset)
				"3.208.0.0/12", "52.0.0.0/11",
				// Azure public cloud (subset)
				"13.64.0.0/11", "20.0.0.0/11",
				// DigitalOcean
				"104.131.0.0/16", "138.197.0.0/16",
			},
			Simulate: true,
		},
		{
			ID:                "tmpl-internal-only",
			Description:       "Internal tools — only reachable from RFC1918 with an auth header",
			PathPrefix:        "/internal",
			AllowedCIDRs:      []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			RequireAuthHeader: "X-Internal-Token",
			DenyByDefault:     true,
			Simulate:          true,
		},
	}
}

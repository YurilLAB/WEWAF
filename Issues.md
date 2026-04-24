## What's Actually Strong

### 1. Session Tracker (`internal/session/tracker.go`)
- **HMAC-SHA256 cookie signing** with 12-byte truncated signatures — fast verification on the hot path
- **Bounded random-drop eviction** (1% budget, 64 min) — same pattern as ddos/limits, consistent across codebase
- **Auto-generated secret on first start** — deliberate non-persistence across restarts for incident response
- **Per-request touchSession is cheap** — map lookup + update under write lock, no allocation on cache hits
- **Defensive caps on beacon deltas** (mouse <=100K, keys <=10K, time <=5min) — prevents counter overflow from hostile clients

### 2. Browser Challenge (`internal/session/challenge.go`)
- **Six high-signal checks, no canvas/audio/webgl** — avoids GPU driver false positives, exactly right
- **Cross-UA logic** — distinguishes Chromium (plugins=0 is suspicious) from Firefox (plugins=0 is normal post-Quantum)
- **Score < 50 passes** — lenient threshold, false negatives only cost sharper risk scoring
- **Zero-activity beacon detection** — catches Puppeteer scripts that carry cookies but don't drive input

### 3. DDoS Detector (`internal/ddos/detector.go`)
- **EMA baseline with alpha=0.02** — slow smoothing, ~34 sample half-life, attack traffic doesn't pollute baseline
- **Spike streak + cooldown** — 3 consecutive windows (~30s) before declaring under_attack, 60s cooldown
- **Per-IP conn-rate with opportunistic random-drop** — O(1) eviction vs previous O(n) scan under mutex
- **Botnet detection on sensitive paths** — 200 unique IPs/60s on /login-style paths, not /static
- **Slow-read measures full request age minus sema wait** — corrects for WAF's own queue congestion

### 4. Proxy (`internal/proxy/proxy.go`)
- **Request ID correlation** — reuses client X-Request-ID or generates `req-{nano}-{counter}`
- **multiReadCloser with atomic.Bool closed flag** — prevents double-close when handler goroutine != reader goroutine
- **Edge-triggered shaper Tighten/Relax** — CompareAndSwap avoids mutex storm during sustained attack
- **Session scoring before phase-2** — risk threshold enforcement without touching rule engine
- **GraphQL validation before general body rules** — prevents false-positive XSS/SQLi matches on field names
- **Backend transport with explicit timeouts** — dial 5s, TLS 10s, response header 30s, expect-continue 1s
- **Egress CONNECT tunnel with bidirectional pipe + done channel** — force-closes both sides on first return, no goroutine leak

### 5. GraphQL Validator (`internal/graphql/validator.go`)
- **Schema-aware @requires(role)** — walks AST against parsed SDL, checks field-level authorization
- **Structural limits** — depth, aliases, fields with configurable caps
- **Tolerant of parse failures** — malformed queries forwarded to backend, WAF doesn't become stricter than origin
- **Atomic config pointer swap** — safe hot-reload while requests in flight

### 6. Canonicalization (`internal/engine/canonicalize.go`)
- **3-pass URL decode + NFKC + homoglyph fold** — kills encoding bypasses that slip past ModSecurity
- **Path segment resolution** — `..//foo/./bar` -> `/foo/bar`, preserves traversal attempts for SECURITY rules
- **Control char stripping** — removes `\r`, `\n`, `\x7f` used for header splitting and smuggling
- **Obfuscated Transfer-Encoding detection** — tab/vtab/form-feed padding, duplicate chunked, unknown+chunked combos

---

## What Needs Ironing Out (Code-Level Issues)

### Security / Correctness

| Issue | Location | Impact | Fix |
|-------|----------|--------|-----|
| **Session cookie `HttpOnly: true` but challenge cookie `HttpOnly: false`** | `tracker.go:IssueChallengeCookie` | Challenge cookie readable by JS (intentional for beacon), but if XSS exists on site, attacker can steal `__wewaf_bc` and impersonate challenge-pass status | Consider `Secure` flag requirement, or split into two cookies: one HttpOnly for server verification, one JS-readable for beacon optimization |
| **`clientIPFromRequest` trusts X-Forwarded-For blindly** | `tracker.go:clientIPFromRequest` | If `TrustXFF` is true but no trusted proxy list exists, attacker can spoof any IP in XFF, bypassing per-IP rate limits and session IP drift detection | Add `TrustedProxies []string` config, only parse XFF when RemoteAddr matches a trusted proxy CIDR |
| **GraphQL validator doesn't check subscription abuse** | `validator.go:walkSelectionSet` | No detection of WebSocket frame flooding or subscription amplification attacks | Add subscription operation counting, frame rate limiting |
| **Egress proxy `dangerReason` resolves DNS on every request for cache misses** | `proxy.go:dangerReason` | DNS cache only helps on hits; first request to a new host still blocks on `resolver.LookupIP` with 5s timeout | Pre-resolve allowlist hosts at startup, add async background resolution for cache misses |
| **No HSTS header injection** | `proxy.go:modifyResponse` | Security headers include X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, but no `Strict-Transport-Security` | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` when backend is HTTPS |
| **Prometheus endpoint unauthenticated** | `embed.go:RegisterRoutes` | `/metrics` bypasses `withAuth` — intentional for Prometheus scraping, but no network-level protection mentioned | Document this in README security section, suggest firewall rules or mTLS for admin port |

### Performance / Scalability

| Issue | Location | Impact | Fix |
|-------|----------|--------|-----|
| **`Session.List()` does O(n^2) bubble sort** | `tracker.go:List()` | Sorting 200K sessions with nested loops is catastrophic | Replace with `sort.Slice` or maintain a separate `[]*Session` slice ordered by LastSeen with insertion sort on touch |
| **DDoS detector `checkBotnet` does O(n) scan over all IPs in a path map** | `detector.go:checkBotnet` | When botnet map grows large, the "count fresh IPs" loop scans all entries | Maintain a running fresh count updated during pruning, or use a secondary ring buffer of recent arrivals |
| **GraphQL `recordSample` takes mutex on every request** | `validator.go:recordSample` | Recent sample ring buffer under mutex on every validated request | Use a pre-allocated circular buffer with atomic index (lock-free) |
| **Config POST handler does 40+ individual `if` checks** | `embed.go:handleConfig` | 300+ lines of sequential field validation, hard to maintain | Generate from struct tags with reflection, or use a validation library like `go-playground/validator` |

### Operational / Maintainability

| Issue | Location | Impact | Fix |
|-------|----------|--------|-----|
| **No structured logging (JSON)** | Throughout | All logs are `log.Printf` text format, hard to parse in ELK/Loki | Add `slog` or `zap` with JSON formatter, configurable level |
| **No distributed tracing** | Throughout | Can't trace a request through WAF -> backend -> egress | Add OpenTelemetry/Jaeger spans at proxy entry, rule evaluation, backend call |
| **Rule engine uses regex for everything** | `rules/signatures.go` | 349 regexes compiled at startup, every request runs ~100+ regex matches | Consider Aho-Corasick or hyperscan for literal patterns, reserve regex for complex patterns |
| **No query cost analysis for GraphQL** | `validator.go` | Depth limits don't catch `allUsers { friends { friends { friends } } }` — this is O(n^3) backend cost | Add field cost weights from schema directives (`@cost`), reject queries exceeding total cost budget |
| **Session fixation protection missing** | `tracker.go` | Session ID never rotates after challenge pass or privilege escalation | Rotate `__wewaf_sid` on challenge pass, bind new session to old state |
| **No cross-session correlation** | `tracker.go` | Same attacker rotating cookies via IP/UA fingerprint not detected | Add IP+UA hash tracking across sessions, flag rapid cookie rotation |
| **Tests are `.gitignore`'d** | `.gitignore` | `*_test.go` and `tests/` ignored — contributors can't see or run tests | Remove from `.gitignore`, use build tags (`//go:build test`) to exclude from release builds |
| **No CI/CD pipeline** | Repo root | 12 commits in 72 hours with no automated validation | Add GitHub Actions: `go test -race ./...`, `go vet`, UI build, integration test |

---

## Missing Security Features (That Would Elevate This Further)

| Feature | Why It Matters | Implementation Approach |
|---------|---------------|------------------------|
| **TLS fingerprinting (JA3/JA4)** | Identify tools by TLS handshake characteristics, block known bad fingerprints | Parse `ClientHello` via `utls` or `ja3` library, maintain blocklist of known scanner JA3s |
| **Proof-of-work challenge** | For high-risk sessions (score > 50), add lightweight JS computation that costs 50-100ms for real browsers but 5-10s for headless automation | Serve JS challenge with adjustable difficulty, verify server-side with nonce + timestamp |
| **Response body exfiltration detection** | Current egress proxy only inspects requests, not responses | Add egress response inspection: detect large JSON arrays, base64 blobs, credit card regexes in outbound responses |
| **Tamper-evident logging** | HMAC-sign log entries so audit trails can't be altered | HMAC each SQLite write batch with key derived from config secret, verify on read |
| **Automatic TLS (Let's Encrypt)** | ACME integration for cert management | Add `autocert` or `lego` integration, store certs in SQLite or filesystem |
| **gRPC/WebSocket deep inspection** | Binary protocol analysis for modern APIs | Add protobuf deserialization for gRPC, WebSocket frame analysis for injection in message payloads |
| **IP reputation feeds** | Integrate with AbuseIPDB, VirusTotal for known-malicious IPs | Background goroutine polls feeds, caches results with TTL, integrates into zero-trust policies |

---
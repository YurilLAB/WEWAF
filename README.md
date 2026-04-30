# WEWAF

<p align="center">
  <img src="internal/web/dist/eagle-logo-icon.png" alt="WEWAF Eagle Logo" width="120">
</p>

A self-hosted Web Application Firewall written in Go, paired with a React
admin dashboard. WEWAF sits in front of your backend as a reverse proxy,
inspects every transaction against a compiled rule set, and persists
telemetry to a rotating set of SQLite databases so historical data survives
restarts and stays searchable by time range.

### Feature matrix

| Area              | Feature                                                   | Default  |
|-------------------|-----------------------------------------------------------|----------|
| Rule engine       | Native signatures + OWASP CRS (paranoia 1–4)              | enabled  |
| Rule engine       | Request canonicalisation (3-pass URL decode, NFKC, dotseg)| enabled  |
| Rule engine       | Homoglyph folding (Cyrillic/Greek/fullwidth → ASCII)      | enabled  |
| Rule engine       | Fail-closed panic recovery per phase                      | enabled  |
| Traffic           | Per-IP rate limit + global semaphore                      | enabled  |
| Traffic           | Pre-WAF token-bucket shaper with auto-tighten on attack   | opt-in   |
| Traffic           | Gzip/Brotli decompression with ratio cap                  | enabled  |
| Resilience        | Hardened reverse-proxy transport (timeouts + pool caps)   | enabled  |
| Resilience        | Circuit breaker with half-open probe gating               | enabled  |
| Resilience        | Adaptive DDoS detector (volumetric + botnet + Slowloris)  | enabled  |
| Resilience        | Exponential-backoff bans (doubling duration, capped)      | enabled  |
| Observability     | Prometheus `/metrics` exposition                          | enabled  |
| Observability     | Per-rule match counters (JSON + Prometheus)               | enabled  |
| Observability     | Server-Sent Events stream of blocks / egress / bots       | enabled  |
| Operational       | Config hot-reload (mtime watcher, recompiles rules)       | enabled  |
| Operational       | Rotating SQLite history store (time-sliced, WAL)          | enabled  |
| Operational       | Egress proxy with DNS cache, allowlist, SSRF guards       | opt-in   |
| Operational       | Zero-trust per-path policies (CIDR, country, mTLS, time)  | opt-in   |
| App integrity     | Signed-cookie session tracker + risk scoring              | opt-in   |
| App integrity     | Browser integrity JS challenge (no CAPTCHA)               | opt-in   |
| App integrity     | GraphQL schema-aware validator + depth/alias/field caps   | opt-in   |
| Response headers  | HSTS (Strict-Transport-Security) on HTTPS backends        | opt-in   |
| Egress            | Outbound response exfil detection (CC + token patterns)   | opt-in   |
| App integrity     | Deep packet inspection: gRPC frames + WebSocket           | opt-in   |
| Operational       | Tamper-evident audit log (HMAC-SHA256 chain)              | opt-in   |

## What makes WEWAF different

Most open-source WAFs fall into two camps: heavyweight rule engines glued to
nginx/Apache (ModSecurity, Coraza), or cloud-managed blackboxes you rent.
WEWAF is neither — it's a single static Go binary with the dashboard, rule
engine, rotating history store, egress filter, DDoS detector, and
zero-trust policy engine all inside the same process. One `go build`, one
binary to deploy, no sidecars, no external database.

That compactness is the point. Every subsystem can talk to every other
subsystem directly, without RPC hops or brittle log-scraping integrations,
which is what lets WEWAF do things that multi-process WAFs charge extra
for or can't do at all:

**Request canonicalization before rule matching.** Before any signature
runs, request URIs, paths, and query arguments go through a dedicated
canonicalizer: recursive URL decoding (up to three passes, so `%2525..%2f`
becomes `../`), backslash → forward slash, null-byte stripping, NFKC
Unicode normalization (fullwidth and ligature tricks collapse to ASCII),
slash coalescing, and resolution of `./` and `../` segments. Pattern rules
only need to match one representation; every common encoding bypass gets
peeled off first.

**A real DDoS detector tuned to not cry wolf.** The naive approach —
"flag anything above baseline × 4" — false-positives on every Black Friday
surge and every viral tweet. WEWAF's detector refuses to declare "under
attack" unless three characteristics line up: the 10-second smoothed RPS
exceeds an adaptive baseline (exponentially weighted over a 5-minute
warmup, never polluted by attack traffic itself), it crosses an absolute
configurable floor so a 20 RPS site isn't over-sensitive, AND the condition
holds for multiple consecutive spike windows (default 3, roughly 30 seconds
of sustained abnormality). Once tripped, it stays tripped for a cool-down
period so a brief dip doesn't prematurely release the floodgates. That
combination gives it a false-positive rate approaching zero on legitimate
bursts while catching real sustained floods early.

The detector also watches three independent signals that individual rule
matches miss:

- **Per-IP connection rate** — 10-second window, default 300 hits (30 qps
  per client). CDN-friendly out of the box; office NAT and shared hosting
  don't trigger.
- **Slowloris / slow-read** — if a request reads its body below the
  bytes/sec floor for more than the configured min age, it's terminated
  before it ties up a worker.
- **Botnet / distributed** — unique source IPs converging on the same
  sensitive path (login, admin, api, wp-login, oauth, signup) within a
  60-second window. Many distinct IPs each individually below the per-IP
  rate is the classic botnet shape, and this is the signal that catches
  it. Threshold defaults to 200 unique IPs in 60s on a sensitive path.

**Pre-WAF admission shaper.** When the detector flips "under attack", the
WAF's own resources become the bottleneck. WEWAF runs a global
token-bucket admission controller at the very front of the request path,
before any body buffering, rule matching, or telemetry work. In normal
operation the bucket is set well above peak traffic so it's a no-op. When
the DDoS detector fires, the shaper auto-tightens to 20% of the base rate;
excess requests get a fast `429` with no inspection cost, so the WAF has
enough CPU left to keep serving the requests it does admit. Without this,
a sufficiently large flood wins by drowning the WAF in work even while
every single request gets correctly classified as malicious.

**Circuit breaker on the backend.** The proxy counts consecutive backend
failures (including 5xx responses and connection errors). When the threshold
trips, it flips to `open` and short-circuits every subsequent request to
503 with a `Retry-After` header for a cool-down period. After the timeout
one probe is allowed through (`half-open`); success closes the breaker,
another failure reopens it. This protects your origin from retry storms
while your site is already struggling — nothing slows recovery like a
stampede.

**Failsafe mode is explicit.** Every production WAF eventually panics on
some malformed input. WEWAF's top-level deferred panic handler checks
`failsafe_mode` — `closed` (default) returns 503 + `Retry-After: 5` so
the request can retry against a healthy instance; `open` forwards the
request unfiltered, with `X-WAF-Failsafe: open-pass` set on the response
so you know it happened. Which behaviour is safer is your call, but it's
your call now, not a silent default.

**Egress filtering that actually holds up.** The egress proxy matches
allowlists with exact host or dot-bounded subdomain rules (so
`google.com` doesn't accidentally permit `googlecompromise.evil.com`).
Hostnames are resolved through a TTL-bounded DNS cache and every returned
IP is classified against private, loopback, link-local, multicast, and
cloud metadata ranges. A dedicated blocklist catches AWS/GCP/Azure
`169.254.169.254`, Alibaba `100.100.100.200`, and IPv6 IMDSv2 even if the
hostname is attacker-controlled and aliased. Each destination host gets
its own token-bucket rate limit so a single noisy dependency can't flood
a third party. CONNECT tunnels half-close on either direction's copy
ending so an idle peer cannot leak the other goroutine.

**Per-session anomaly scoring.** A dedicated tracker issues an
HMAC-signed `__wewaf_sid` cookie on first contact and accumulates
per-session signals over the life of the conversation: request rate
against a ceiling, distinct-path count, user-agent and source-IP drift,
block ratio, and whether the session has cleared the browser integrity
challenge. Weights are explainable additive values — no opaque ML — so
every score bump is debuggable in the admin UI during an incident.
Scoring is observe-only by default; flipping `session_block_threshold`
to a non-zero value turns it into a real enforcement knob without
changing a single rule. The tracker honours the same `trust_xff` flag
as the proxy so hostile clients can't spoof source IPs past the drift
detector. Sessions live in-memory with an LRU cap and idle TTL; the
HMAC secret auto-generates per-restart so a stolen ID stops working the
moment you bounce the daemon.

**Browser integrity challenge, no CAPTCHA.** A sub-2 KB JS probe served
at `/api/browser-challenge.js` checks a handful of high-signal browser
properties — `navigator.webdriver`, plugin count against the reported
UA family, `window.chrome` on Chromium, languages array, hardware
concurrency, screen geometry, touch support, fire-time delta — and
reports them via `navigator.sendBeacon`. The server scores the signals
and, on pass, issues a signed `__wewaf_bc` cookie **and rotates the
session ID** (classic fixation defence — any pre-challenge ID an
attacker may have planted becomes invalid). Canvas/audio/WebGL
fingerprints were deliberately left out because they false-positive
across GPU drivers and ad blockers; six boring checks plus beacon-based
activity detection is enough to separate real browsers from headless
automation without CAPTCHA UX friction.

**GraphQL schema-aware validation.** Beyond the signature rules that
catch obvious introspection probes, WEWAF can parse every incoming
GraphQL query against a loaded SDL schema and reject operations whose
AST exceeds the configured depth / alias / field caps — the DoS shape
that depth-only limits miss when you stack 500 aliases at depth 3.
When a schema is loaded, the validator also enforces field-level
`@requires(role: "...")` directives: requests hitting an admin-only
field without the matching role header are blocked before the resolver
ever runs. Subscription operations can be rejected outright (WebSocket
frames bypass most HTTP WAFs anyway), and malformed queries are
forwarded unchanged so the WAF never becomes a stricter syntax checker
than the origin. Observe-only by default.

**Deep packet inspection for gRPC and WebSocket.** Classic HTTP-body
WAFs see gRPC as opaque binary and WebSocket as a tunnel. WEWAF has
native inspectors for both. The gRPC inspector parses length-prefixed
Protobuf frames, bounds per-frame and per-body resource use, and
extracts UTF-8 string runs so the existing XSS/SQLi/RCE signatures
match against protobuf string fields without needing a `.proto`
descriptor. The WebSocket inspector rejects handshakes whose Origin,
subprotocol, or extensions header is off-policy before the upgrade
completes, and includes an RFC 6455 frame parser (masking handled, 64-
bit length cap enforced, reserved opcodes rejected, control-frame size
limit) that callers can wrap around a hijacked connection for full
frame-by-frame inspection. Both are observe-only by default — block
flags are separate so operators can tune first, enforce later.

**Tamper-evident audit log.** Every block, WebSocket rejection, and
operator config change writes an HMAC-SHA256-chained entry to an
append-only file. Each record's MAC covers the previous record's MAC,
so an attacker who gains write access can't silently delete, reorder,
or edit a historical entry: the `/api/audit/verify` endpoint walks the
chain from seq 1 and surfaces the first bad index. A truncated trailing
line (power-loss during write) is tolerated — the chain resumes cleanly
from the last good entry on restart. Secrets in memory are the
trust-root; operators supplying a fixed `audit_secret` get verifiable
cross-restart audit trails, otherwise the key auto-rotates per restart
(good for defence-in-depth during active incidents).

**Zero-trust policies on paths, before the rule engine.** The rule engine
answers "does this request look malicious?" — zero-trust answers "should
this request be anywhere near this endpoint in the first place?". Path
policies can require a specific auth header, require mTLS (checked via
`X-WEWAF-Client-Cert-Verified`, set by a correctly configured TLS
terminator), restrict source to CIDR allow/blocklists, or geofence by
ISO country code. Policies run first, so requests that fail the basic
"who are you" test never consume rule-engine CPU.

**Live operator visibility.** The dashboard holds a Server-Sent Events
stream at `/api/events/stream` that pushes every block, egress decision,
and bot detection to connected operators in real time, with auto-reconnect
and 25-second keepalives. The IP Intelligence page lets you drill into any
IP's 24-hour activity, attack-category mix, and ban status — and run
one-click auto-mitigation that bans every IP exceeding a configurable
block threshold in the last hour.

**Memory bounds are explicit.** Every ring buffer has a declared cap.
Every map has an eviction policy. Nothing grows unbounded under attack:
recent blocks 500, egress decisions 200, bot detections 200, traffic
samples 288, unique IPs 100 000, connection pings 100, brute-force
attempts-per-key 10 000. SQLite writes happen on a dedicated goroutine
off a buffered channel; when the channel fills during a burst, events
are dropped with a counter increment rather than back-pressuring the
request path.

## How it fits together

```
┌──────────────┐       ┌────────────────────────────────────────┐
│  Client      │──────▶│  :8080  WAF Proxy                      │
└──────────────┘       │  1. Pre-WAF shaper (admission control) │
                       │  2. Concurrency semaphore              │
                       │  3. DDoS detector (vol / conn / botnet)│
                       │  4. Per-IP token-bucket rate limit     │
                       │  5. Zero-trust policy evaluation       │
                       │  6. Circuit breaker gate               │
                       │  7. Canonicalize → rule evaluation     │
                       │  8. Forward to backend                 │
                       │  9. Response inspection + leak redact  │
                       └───────────────┬────────────────────────┘
                                       ▼
                       ┌────────────────────────┐     ┌───────────────┐
                       │  Rule Engine (phases)  │────▶│  Telemetry    │
                       │  196+ signatures,      │     │  counters +   │
                       │  canonicalized input   │     │  ring buffers │
                       └────────────────────────┘     └──────┬────────┘
                                                             ▼
                                                     ┌───────────────┐
                                                     │  History      │
                                                     │  SQLite       │
                                                     │  (rotating)   │
                                                     └───────────────┘

┌──────────────┐       ┌────────────────────────────────────────┐
│  Operator    │──────▶│  :8443  Admin (embedded React SPA)     │
└──────────────┘       │         + JSON API + SSE /events       │
                       └────────────────────────────────────────┘

┌──────────────┐       ┌────────────────────────────────────────┐
│  Backend     │◀──────│  :8081  Egress Proxy (optional)        │
│  outbound    │       │  allowlist + DNS cache + per-dest RL + │
│              │       │  metadata blocks + CONNECT half-close  │
└──────────────┘       └────────────────────────────────────────┘
```

Every subsystem has a `Stop()` or `Close()` method; `SIGINT`/`SIGTERM`
triggers an orderly shutdown that flushes outstanding history events
before exiting.

## The rule engine

WEWAF ships with **349 compiled signatures** across two layered rule packs:
the native WEWAF pack (~243 rules focused on high-value exploit classes and
recent CVEs), and a curated port of the **OWASP Core Rule Set** v4
(~106 rules across protocol enforcement, LFI, RFI, RCE, PHP injection, XSS,
SQLi, Java, and data-leakage categories).

**Every rule change is regression-locked against a false-positive test
suite.** `internal/rules/falsepositive_test.go` runs the full compiled rule
pack at PL4 (widest set) against 25 inputs representing realistic traffic
that past WAFs have historically false-positive'd on — search queries
containing shell-command words, comments mentioning `javascript:`, form
posts with ampersands, URLs with dotfile-lookalikes, blog prose about
SQL-adjacent topics — and asserts no rule fires. Another 16 malicious
cases cover the major CVEs and confirm detection still works. New rules
that break the FP suite don't land.

Every rule has a **paranoia level** (1–4) matching the CRS convention —
PL1 rules are the base set with the lowest false-positive risk, PL4 adds
the most aggressive matches. The engine filters rules by the configured
`paranoia_level` at evaluation time so operators can start at PL1 in
detection mode, observe, and ratchet up gradually. OWASP CRS can be
toggled off entirely via `crs_enabled=false` for operators who want only
the native WEWAF signatures.

The native WEWAF pack covers XSS, SQL injection, RCE, SSRF, XXE, path
traversal, CRLF, NoSQLi, LDAP, JNDI, prototype pollution, file upload,
open redirect, HTTP smuggling, and scanner/bot fingerprints.
Beyond those classics, WEWAF ships with signatures for specific high-value
exploits and modern attack classes:

- **2024 / 2025 / 2026 CVEs**: Next.js middleware bypass (CVE-2025-29927),
  PHP-CGI argv injection (CVE-2024-4577), PAN-OS GlobalProtect
  (CVE-2024-3400), Ivanti Connect Secure (CVE-2024-21887), FortiOS SSL-VPN
  (CVE-2024-21762), TeamCity auth bypass (CVE-2024-27198), GitLab
  password-reset takeover (CVE-2023-7028), CitrixBleed (CVE-2023-4966),
  Confluence template RCE (CVE-2023-22527), XWiki SolrSearch
  (CVE-2025-24893), ScreenConnect (CVE-2024-1709), Veeam Backup
  (CVE-2024-40711), GeoServer OGC (CVE-2024-36401), CUPS IPP
  (CVE-2024-47176), **React2Shell / React Server Components
  prototype-pollution RCE (CVE-2025-55182, CVE-2025-66478)**,
  **Langflow unauthenticated Python RCE (CVE-2025-3248)**, **Marimo
  pre-auth WebSocket RCE (CVE-2026-39987)**, **n8n form-trigger file read
  (CVE-2026-21858)**, **FortiClient EMS Site-header SQLi
  (CVE-2026-21643)**, **Cisco Catalyst SD-WAN vManage (CVE-2026-20122)**,
  **Livewire v3 hydration RCE (CVE-2025-54068)**, **CrushFTP S3 auth
  bypass (CVE-2025-31161)**, **Check Point Quantum Gateway file read
  (CVE-2024-24919)**, **Cleo Harmony/VLTrader/LexiCom RCE
  (CVE-2024-50623 / CVE-2024-55956)**.
- **Log4Shell** (CVE-2021-44228) with obfuscation-aware patterns that
  unfold `${lower:j}${::-ndi}` style tricks.
- **Spring4Shell** (CVE-2022-22965), **Confluence OGNL** (CVE-2022-26134),
  **Struts S2**, **Exchange ProxyShell**, **MOVEit Transfer**
  (CVE-2023-34362), **F5 iControl RCE**, **GitLab ExifTool**
  (CVE-2021-22205), and **Shellshock**.
- **SSTI** for Jinja2, Twig, ERB, Velocity, Freemarker, and Smarty.
- **GraphQL abuse**: introspection, field duplication, mutation injection,
  deep-nesting DoS.
- **Insecure deserialization** for Java (aced0005/rO0), PHP, Node
  `_$$ND_FUNC$$_`, Python pickle, Ruby Marshal, YAML tag injection.
- **Server-Side Includes** and **Edge-Side Includes**.
- **React SSR / Next.js** payload injection through
  `dangerouslySetInnerHTML`, React Server Component gadget chains.
- **Prompt injection + LangChain tool abuse**: classic "ignore all previous
  instructions" markers, `PythonREPL` / `ShellTool` exploit patterns.
- **Mass-assignment**: suspicious `is_admin` / `role` / `permissions`
  fields in request bodies.
- **Advanced scanner fingerprints**: Nuclei, Nikto, masscan, zmap,
  Acunetix, Netsparker, Qualys, Nessus, and known webshell filenames
  (c99, r57, wso, adminer, filesman, weevely).
- **Request-shape anomalies**: GET/DELETE with bodies, URLs over 2000
  chars, null bytes anywhere in the URL.
- **Credential-stuffing**: combo-list `user:pass` payloads, OpenBullet /
  BlackBullet / Sentry MBA tool signatures.

Every rule is evaluated against the canonicalized request so double-
encoded, fullwidth, or mixed-slash payloads no longer bypass anything.

## Operating modes

`active` mode blocks requests whose cumulative score reaches
`block_threshold`; `detection` mode evaluates rules and logs matches but
forwards traffic unchanged (useful for soft rollout); `learning` mode
logs every match with its score so you can author rule tweaks and
whitelists before switching to active. Mode is hot-swappable at runtime
via `POST /api/config`:

```bash
curl -X POST -d '{"mode":"detection"}' http://localhost:8443/api/config
```

## History subsystem

The history store writes every block, IP activity update, and traffic
sample (including per-interval bytes in/out) to a SQLite database inside
`history/`. A fresh database is created on startup, and again each time
the rotation window (default 168 h / 1 week) elapses.

The hot path is non-blocking. The proxy enqueues events to a buffered
channel. A single background writer drains the channel every two seconds
(or when a batch of 256 accumulates) and applies them inside one
transaction. If the buffer is ever full — e.g., during a burst that
outpaces disk — the event is dropped and `history.dropped_events` is
incremented. The request itself is never affected.

At the rotation boundary the writer sets `metadata.ended_at` on the
current database, closes it, and opens a new one named
`history/waf-<rfc3339-timestamp>.sqlite`. Registered listeners (the
telemetry layer) reset their in-memory aggregates so unique-IP counts
align with the fresh window. Schema changes ship as additive
`ALTER TABLE ... ADD COLUMN` migrations applied on reopen, so upgrading
WEWAF never requires data migration.

Query endpoints under `/api/history/*` scan only the databases whose
`[started_at, ended_at]` range intersects the requested window, aggregate
results, and return them sorted. Databases outside the window are never
opened.

## Quick start

```bash
# Clone, then build the UI (requires Node 18+).
cd ui
npm install
npm run build           # emits ../internal/web/dist/

# Build and run the Go daemon from the repo root.
cd ..
go build -o waf.exe ./cmd/waf
./waf.exe -config config.json
```

After startup the proxy listens on `:8080` and the admin dashboard on
`:8443`. Point your application traffic at `http://<host>:8080` and open
`http://<host>:8443` in a browser.

## Configuration

Defaults are applied for every missing field in `config.json`, so only
the ones you want to override need to be listed. The tables below cover
the fields most operators touch; every field also has a JSON-tag comment
in `internal/config/config.go` for reference.

### Core proxy and limits

| Field                 | Default           | Purpose                                         |
|-----------------------|-------------------|-------------------------------------------------|
| `listen_addr`         | `":8080"`         | Where inbound traffic hits the WAF.             |
| `admin_addr`          | `":8443"`         | Dashboard + API port. Put behind auth in prod.  |
| `backend_url`         | required          | Origin the proxy forwards to.                   |
| `trust_xff`           | `false`           | Trust `X-Forwarded-For` (only behind a CDN).    |
| `trusted_proxies`     | `[]`              | CIDR allowlist of upstream proxies whose `X-Forwarded-For` we honour. Empty = legacy left-most behaviour with a startup warning; production behind a CDN should populate this so an attacker who reaches the WAF directly cannot spoof the source IP. Bare IPs are accepted and promoted to `/32` or `/128`. |
| `max_concurrent_req`  | `10000`           | Global semaphore on in-flight requests.         |
| `max_body_bytes`      | `10 MiB`          | Cap on request/response body inspection.        |
| `block_threshold`     | `100`             | Aggregate score at which a request is blocked.  |
| `rate_limit_rps`      | `100`             | Per-IP token bucket rate.                       |
| `rate_limit_burst`    | `150`             | Per-IP token bucket burst size.                 |
| `paranoia_level`      | `1`               | OWASP CRS paranoia 1–4. Raise after tuning.     |

### Resilience features

| Field                                  | Default  | Purpose                                                        |
|----------------------------------------|----------|----------------------------------------------------------------|
| `backend_dial_timeout_ms`              | `5000`   | TCP dial timeout on the origin transport.                      |
| `backend_response_header_timeout_ms`   | `30000`  | Max time the origin can take to send response headers.         |
| `backend_tls_handshake_timeout_ms`     | `10000`  | TLS handshake cap on upstream connections.                     |
| `backend_max_idle_conns`               | `200`    | Connection-pool cap across all origins.                        |
| `backend_max_conns_per_host`           | `64`     | Per-host connection cap (prevents single-origin exhaustion).   |
| `decompress_inspect`                   | `true`   | gzip / brotli bodies are decompressed into a ratio-capped buffer before engine eval (zip-bomb defence). |
| `decompress_ratio_cap`                 | `100`    | Max allowed (decompressed ÷ compressed) ratio.                 |
| `max_decompress_bytes`                 | `64 MiB` | Absolute decompressed-size cap.                                |
| `failsafe_mode`                        | `closed` | `closed` = 503 on engine panic, `open` = forward unfiltered.   |
| `breaker_consecutive_failures`         | `10`     | Origin failures in a row before the breaker opens.             |
| `breaker_open_timeout_sec`             | `30`     | Cool-down before a half-open probe is allowed.                 |

### Bans, DDoS, and admission control

| Field                              | Default  | Purpose                                                          |
|------------------------------------|----------|------------------------------------------------------------------|
| `ddos_spike_windows_required`      | `3`      | Consecutive 10-second spike windows before declaring attack.     |
| `ddos_cooldown_seconds`            | `60`     | Quiet period before releasing attack state.                      |
| `ddos_conn_rate_threshold`         | `300`    | Per-IP connections in a 10 s window (CDN-friendly default).      |
| `ddos_botnet_unique_ip_threshold`  | `200`    | Unique IPs converging on a sensitive path in 60 s.               |
| `shaper_enabled`                   | `false`  | Pre-WAF token-bucket admission. Tightens under attack.           |
| `shaper_max_rps` / `shaper_burst`  | `2000 / 4000` | Base budget and burst for the shaper.                       |
| `ban_backoff_enabled`              | `true`   | Repeat bans on the same IP inside the window get longer.         |
| `ban_backoff_multiplier`           | `2`      | Duration multiplier per repeat offence.                          |
| `ban_backoff_window_sec`           | `86400`  | Window inside which repeats count as the same offender.          |
| `max_ban_duration_sec`             | `604800` | Upper cap so backoff doesn't grow without bound.                 |

### Session tracking, browser challenge, GraphQL

| Field                              | Default         | Purpose                                                              |
|------------------------------------|-----------------|----------------------------------------------------------------------|
| `session_tracking_enabled`         | `false`         | Issue `__wewaf_sid` cookie and accumulate per-session signals.       |
| `session_max_sessions`             | `200000`        | LRU cap on live sessions (random-drop eviction at the cap).          |
| `session_idle_ttl_sec`             | `1800`          | Evict sessions idle longer than this.                                |
| `session_request_rate_ceiling`     | `600`           | Requests/minute above which scoring starts penalising.               |
| `session_path_count_ceiling`       | `40`            | Distinct paths per session above which scoring starts penalising.    |
| `session_block_threshold`          | `0` (off)       | Score at which requests for that session are blocked. `0` = observe. |
| `session_cookie_secret`            | auto-generated  | HMAC key for cookie signing. Auto if blank (rotates on restart).     |
| `browser_challenge_enabled`        | `false`         | Serve the JS integrity probe and accept verify POSTs.                |
| `browser_challenge_block`          | `false`         | If on, a failed challenge blocks the request outright.               |
| `graphql_enabled`                  | `false`         | Parse GraphQL requests and enforce structural limits.                |
| `graphql_block_on_error`           | `false`         | If off, violations are counted but the request still proxies.        |
| `graphql_max_depth`                | `7`             | Max AST depth. Typical SPAs sit at 4–5.                              |
| `graphql_max_aliases`              | `10`            | Max aliased fields per operation (amplification defence).            |
| `graphql_max_fields`               | `200`           | Max total fields per operation (resource exhaustion defence).        |
| `graphql_schema_file`              | `""`            | Path to SDL file. Enables `@requires(role:"…")` enforcement.         |
| `graphql_role_header`              | `X-User-Role`   | Header the validator reads for the requester's role claim.           |
| `graphql_block_subscriptions`      | `false`         | Reject `subscription` operations outright (useful if unused).        |

### Deep packet inspection

| Field                            | Default | Purpose                                                                                                 |
|----------------------------------|---------|---------------------------------------------------------------------------------------------------------|
| `grpc_inspect`                   | `false` | Parse length-prefixed Protobuf frames on `application/grpc*` requests.                                 |
| `grpc_block_on_error`            | `false` | Block when frame count / size caps are exceeded. Default is observe + extract scan targets.            |
| `grpc_max_frames`                | `1024`  | Hard cap on frames per body.                                                                           |
| `grpc_max_frame_bytes`           | `1 MiB` | Per-frame payload cap.                                                                                 |
| `websocket_inspect`              | `false` | Run the upgrade-gate on WebSocket handshakes.                                                          |
| `websocket_require_subprotocol`  | `false` | Reject upgrades that don't advertise any `Sec-WebSocket-Protocol`.                                     |
| `websocket_origin_allowlist`     | `[]`    | Permitted `Origin` values. Supports `*.example.com` subdomain wildcards.                               |
| `websocket_subprotocol_allowlist`| `[]`    | Permitted `Sec-WebSocket-Protocol` values. Match is case-insensitive.                                 |

### Tamper-evident audit log

| Field              | Default       | Purpose                                                                                          |
|--------------------|---------------|--------------------------------------------------------------------------------------------------|
| `audit_enabled`    | `false`       | Turn on the HMAC-chained append-only log.                                                        |
| `audit_file_path`  | `audit.log`   | Where the chain persists on disk. Empty string means in-memory ring only.                        |
| `audit_secret`     | auto-gen      | HMAC key. Leave empty and you get a fresh per-restart key — which invalidates the chain on reboot. Production deployments should mount a fixed secret. |
| `audit_ring_size`  | `256`         | In-memory tail available at `/api/audit/tail?n=…`.                                              |

Admin endpoints:

- `GET /api/audit/verify` — walks the whole chain and returns
  `{ok, bad_seq, total, appends, verify_fails}`. Run this periodically
  (or on demand during an incident) to confirm the log hasn't been
  altered.
- `GET /api/audit/tail?n=100` — newest entries from the in-memory ring.
- `GET /api/dpi/stats` — `grpc_requests`, `grpc_blocked`,
  `ws_upgrades`, `ws_rejected` counters plus the live DPI config.

### Egress response inspection

| Field                      | Default  | Purpose                                                                                                                                |
|----------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------|
| `egress_exfil_inspect`     | `false`  | Scan the first 256 KiB of each outbound response for credit-card numbers (Luhn-verified) and cloud-provider secret prefixes.           |
| `egress_exfil_block`       | `false`  | Block when a pattern matches. Default is observe-only: log + increment `exfil_detected` so operators can tune before enforcing.        |

Allowlist hostnames are pre-resolved into the DNS cache at startup so
the first real egress request doesn't block five seconds on LookupIP.
Resolution happens on a background goroutine — startup never stalls on
DNS even if the network is flaky.

### Response headers

| Field                       | Default     | Purpose                                                                                                                                           |
|-----------------------------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `security_headers_enabled`  | `true`      | Inject `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; strip `Server` and `X-Powered-By`.                   |
| `hsts_enabled`              | `false`     | Emit `Strict-Transport-Security`. Only injected when the backend is HTTPS — setting HSTS on plain HTTP is spec-non-compliant and browsers ignore it. |
| `hsts_max_age_sec`          | `15552000`  | 180 days. Safe starting value before ratcheting up to two years and `preload`.                                                                    |
| `hsts_include_subdomains`   | `true`      | Append `; includeSubDomains` to the HSTS header.                                                                                                  |
| `hsts_preload`              | `false`     | Append `; preload`. Only tick once you are ready to submit to `hstspreload.org` — removal is manual and slow.                                     |

### JA3 TLS fingerprinting

JA3 catches automation that passes the JS browser-integrity check by
fingerprinting the TLS ClientHello. WEWAF supports two capture paths:

- **Native** — when WEWAF terminates TLS itself, the proxy installs a
  `GetConfigForClient` hook and computes the fingerprint per handshake.
  Cached by remote address with a short TTL.
- **Edge-fed** — when WEWAF runs behind a TLS terminator that exports
  the JA3 hash via header (Cloudflare's `Cf-Ja3-Hash`, AWS, custom
  edges), the value is honoured **only when the source IP is in
  `ja3_trusted_sources`**. Any other client setting that header is
  silently ignored — there is no spoofing path.

Detection is layered: a curated list of well-known automation
fingerprints (curl, Go's net/http, Python urllib3, headless Chrome)
adds **+15 to the session risk score** by default. Operators can flip
`ja3_hard_block` to refuse the request outright. A "good" list of
real-browser hashes suppresses the bump in the rare case of a curated
collision.

| Field                  | Default | Purpose                                                                                          |
|------------------------|---------|--------------------------------------------------------------------------------------------------|
| `ja3_enabled`          | `false` | Master switch.                                                                                   |
| `ja3_hard_block`       | `false` | If true, "bad" verdicts return 403 directly. Default just bumps the session score.               |
| `ja3_header`           | `""`    | Header that carries the JA3 hash from a trusted edge. Empty = native-only mode.                  |
| `ja3_trusted_sources`  | `[]`    | CIDRs allowed to set `ja3_header`. Bare IPs are widened to /32 (IPv4) or /128 (IPv6).            |
| `ja3_cache_capacity`   | `4096`  | Bounded entries in the per-handshake fingerprint cache.                                          |
| `ja3_cache_ttl_sec`    | `30`    | TTL for cached fingerprints. Long enough to cover a Keep-Alive connection, short enough to bound memory. |

GREASE values (RFC 8701) are stripped before hashing so real Chrome
produces a stable fingerprint across handshakes.

### Proof-of-work for high-risk sessions

When a session's risk score crosses `pow_trigger_score`, WEWAF returns
a small HTML page that runs a hashcash-style PoW solver in JavaScript.
The browser hashes `SHA-256(salt || nonce)` until the prefix has the
configured number of leading zero bits, then POSTs the nonce to
`/api/pow/verify`. On pass the WAF sets a signed cookie (HMAC-SHA256
truncated to 12 bytes), records the pass on the session, and caps the
visible score at 49 for one hour so the user isn't immediately
re-challenged.

| Field                | Default | Purpose                                                                                                        |
|----------------------|---------|----------------------------------------------------------------------------------------------------------------|
| `pow_enabled`        | `false` | Master switch.                                                                                                 |
| `pow_trigger_score`  | `60`    | Session risk-score threshold above which the PoW gate fires.                                                   |
| `pow_min_difficulty` | `18`    | Bits at the trigger score. ~250 ms–1 s on a modern phone.                                                      |
| `pow_max_difficulty` | `24`    | Hard ceiling. ~5–15 s on desktop.                                                                              |
| `pow_token_ttl_sec`  | `120`   | Server-issued challenge validity. Plenty for a slow client; bounds replay window if cookies leak.              |
| `pow_cookie_ttl_sec` | `3600`  | Pass-cookie lifetime once verified.                                                                            |
| `pow_secret`         | auto    | HMAC key. Auto-generated per restart unless explicitly set — restart invalidates outstanding solves, by design. |

Token verification is constant-time (HMAC compare via
`crypto/subtle`), replay-protected via a TTL'd seen-set, and
panic-recovered. If a client lacks `crypto.subtle` (very old browser,
locked-down enterprise mode), the page falls through to the existing
JS browser challenge — high-risk sessions still get gated, just by
the lighter mechanism.

### Other sections

Egress proxy, history rotation, rule engine mode, paranoia level, SSL
manager, mesh gossip keep the same JSON tags as before — see
`internal/config/config.go` for the full list.

Set `WAF_API_KEY` in the environment to require an API key on every
`/api/*` request. Clients present it via `X-API-Key` header or
`api_key` query parameter. Leave it unset only for development.

## Notable endpoints

The full set of endpoints is larger than reasonable to table here; the
important ones to know about beyond the obvious `/api/health`,
`/api/metrics`, `/api/config`:

- `/api/events/stream` — Server-Sent Events. Event types: `hello`,
  `block`, `egress`, `bot`, `ping`.
- `/api/network/summary` — live bandwidth rates, byte totals, status-code
  distribution, recent egress decisions, backend latency.
- `/api/network/top-paths` / `/api/network/top-ips` — most-attacked
  endpoints and top attacker IPs from history.
- `/api/ip/<ip>` — full intel on one IP: activity, category mix, recent
  blocks, ban status.
- `/api/ip-auto-mitigate` (POST) — ban every IP whose block count in the
  last hour exceeds a threshold. Body: `{"threshold":10,"duration_sec":3600}`.
- `/api/ddos/stats` — volumetric / conn-rate / slow-read / botnet
  counters + `under_attack` flag + adaptive baseline + spike streak.
- `/api/shaper/stats` — pre-WAF admission controller: admitted, rejected,
  current effective RPS, whether it's tightened under pressure.
- `/api/breaker/stats` — circuit-breaker state, failure count,
  short-circuited request total.
- `/api/zerotrust/policies` (GET/PUT) — inspect or replace the policy list.
- `/api/connection/history` / `/api/connection/events` — ping ring
  buffer and state-transition log so you can render a backend-health
  sparkline without synthesising it.
- `/api/egress/recent` — ring buffer of outbound decisions with target
  URL and block reason.
- `/api/history/events?from=&to=&limit=` — time-ranged block query
  across every rotated SQLite file.
- `/api/sessions?limit=N` / `/api/sessions/<id>` — live list of tracked
  sessions with risk scores, or one session's full view.
- `/api/browser-challenge.js` / `/api/browser-beacon.js` — served
  public; the SPA or your own origin can load them to opt in to the
  integrity probe and activity beacon.
- `/api/browser-challenge/verify` (POST) — the JS probe posts
  collected signals here; on pass you receive the `__wewaf_bc` cookie
  and a rotated session ID.
- `/api/session/beacon` (POST) — mouse/keyboard/time-on-page deltas.
- `/api/pow.js` — proof-of-work solver served on the protected origin.
- `/api/pow/verify` (POST) — accepts `(token, nonce)`, sets the
  `__wewaf_pow` pass cookie on success.
- `/api/graphql/stats` / `/api/graphql/recent` — per-operation
  counters, subscription totals, and a ring buffer of recent
  validated operations with depth/alias/field counts.

All routes honour CORS and the optional API key.

### Observability endpoints at a glance

| Endpoint                    | Format       | What you get                                       |
|-----------------------------|--------------|----------------------------------------------------|
| `/metrics`                  | Prometheus   | Counters, gauges, per-rule match totals.           |
| `/api/rules/counters`       | JSON         | `{counters: {RULE_ID: n, ...}}` — same data as `/metrics` but keyed for the UI. |
| `/api/events/stream`        | SSE          | Live blocks / egress decisions / bot detections.   |
| `/api/ddos/stats`           | JSON         | Adaptive baseline, spike streak, `under_attack`.   |
| `/api/breaker/stats`        | JSON         | Circuit-breaker state + failure count.             |
| `/api/shaper/stats`         | JSON         | Admitted / rejected / tightened flag.              |
| `/api/history/events`       | JSON         | Time-ranged query across rotated SQLite files.     |

### Key Prometheus metrics

| Metric                        | Type    | Labels     | Meaning                                 |
|-------------------------------|---------|------------|-----------------------------------------|
| `wewaf_requests_total`        | counter | —          | All requests seen by the proxy.         |
| `wewaf_blocked_total`         | counter | —          | Requests the WAF blocked.               |
| `wewaf_passed_total`          | counter | —          | Requests forwarded to the backend.      |
| `wewaf_errors_total`          | counter | —          | Proxy errors (backend failures).        |
| `wewaf_egress_blocked_total`  | counter | —          | Egress requests blocked.                |
| `wewaf_bots_detected_total`   | counter | —          | Requests matched a bot/scanner sig.     |
| `wewaf_rule_matches_total`    | counter | `rule_id`  | Per-rule match counts for noise tuning. |
| `wewaf_response_status`       | counter | `bucket`   | 2xx / 3xx / 4xx / 5xx distribution.     |
| `wewaf_bytes_in_per_second`   | gauge   | —          | Ingress rate sampled every 10 s.        |
| `wewaf_bytes_out_per_second`  | gauge   | —          | Egress rate sampled every 10 s.         |
| `wewaf_unique_ips`            | gauge   | —          | Distinct source IPs since rotation.     |

## Testing

```bash
go test -race ./...
```

Tests live alongside the package they exercise — Go's compiler requires
`_test.go` files in the same directory as the package under test. Black-
box integration tests that boot a real `httptest.Server` behind the proxy
live under `tests/integration/`.

| Package                         | What it covers                                            |
|---------------------------------|-----------------------------------------------------------|
| `internal/rules`                | False-positive regression suite + malicious-traffic match suite (41 cases). |
| `internal/limits`               | Rate-limiter math + eviction; breaker state machine inc. half-open probe gating. |
| `internal/bruteforce`           | Window expiry, reset, race safety.                        |
| `internal/core`                 | BanList expiry, cleanup, exponential-backoff math.        |
| `internal/engine`               | Canonicalise, path traversal, homoglyph fold, obfuscated Transfer-Encoding. |
| `internal/session`              | Cookie HMAC round-trip, tamper rejection, challenge cookie, score-rises-with-blocks. |
| `internal/graphql`              | Depth / alias / field limits, observe vs block, schema-aware `@requires(role)` enforcement, full-batch inspection, subscription guard. |
| `internal/proxy` (exfil + hsts) | Luhn-verified card match, AWS / GitHub / Stripe / Slack / JWT patterns, secret masking before logging, HSTS emission on HTTPS only. |
| `internal/ddos`                 | Botnet threshold trips at configured unique-IP count; fresh-count optimisation actually prunes stale entries. |
| `internal/dpi`                  | gRPC frame parser (bomb / count / truncation), WebSocket upgrade allowlist, RFC 6455 frame reader (masking, 64-bit length cap, reserved-opcode rejection). |
| `internal/audit`                | HMAC chain roundtrip + detect edit / delete / reorder / wrong-secret / truncated-tail cases. |
| `tests/integration`             | End-to-end: allow + block + per-rule counters + Prometheus exposition. |

## Hot-reload

Start the daemon with `-config config.json` and edit the file in place —
the watcher re-reads on mtime change, recompiles rules, and pushes the
result to the running engine. Fields that can't safely hot-swap (listen
addresses, admin API key, SQLite paths) are silently ignored and still
need a restart. A `[config hot-reload]` log line confirms each reload.

## Project layout

```
cmd/waf/              — entry point + telemetry→history persister adapter
internal/config/      — JSON config load + hot-swappable mode
internal/core/        — shared types (transactions, matches, ban list)
internal/engine/      — rule evaluation + canonicalization + phase orchestration
internal/rules/       — built-in signatures + regex compilation
internal/proxy/       — reverse proxy + egress proxy with DNS cache and per-dest RL
internal/ddos/        — volumetric + conn-rate + slow-read detector
internal/zerotrust/   — per-path access policies (auth, mTLS, CIDR, country)
internal/session/     — signed-cookie session tracker, risk scoring, JS challenge assets
internal/graphql/     — schema-aware GraphQL validator (depth / alias / field / auth)
internal/dpi/         — deep packet inspection for gRPC frames + WebSocket (RFC 6455)
internal/audit/       — tamper-evident HMAC-chained append-only audit log
internal/limits/      — semaphore + token bucket + circuit breaker + buffer pool
internal/telemetry/   — in-memory counters, ring buffers, persister hook
internal/history/     — rotating SQLite store + batched writer
internal/host/        — CPU/mem/disk/net sampler (gopsutil)
internal/connection/  — backend probe + ping/event history
internal/ssl/         — cert storage + TLS policy
internal/bruteforce/  — sliding-window login attempt tracker
internal/web/         — admin HTTP server + embedded SPA + SSE stream + /metrics
tests/integration/    — black-box end-to-end tests (boot real proxy + backend)
ui/                   — React + Vite source (builds to internal/web/dist)
history/              — created at runtime; rotating SQLite files live here
certs/                — created at runtime; uploaded PEM cert pairs
```

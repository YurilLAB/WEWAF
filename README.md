# WEWAF

<img src="internal/web/dist/eagle-logo-icon.png" alt="WEWAF" width="96">

A self-hosted web application firewall written in Go, paired with a React
admin dashboard. WEWAF sits in front of your backend as a reverse proxy,
inspects every request and response against a compiled rule set, defends the
origin from floods and abuse, and keeps a searchable history of what it saw —
all from a single binary.

It is managed from **ypanel**, Yuril Security's operator control panel. See
[`docs/ypanel.md`](docs/ypanel.md) for how WEWAF connects and the current
status of that integration.

## Why WEWAF exists

Self-hosted web application firewalls today tend to come in two shapes, and
neither is much fun to run.

The first is the heavyweight rule engine bolted onto a web server —
ModSecurity or Coraza in front of nginx or Apache. These work, but they are
several moving parts pretending to be one: the proxy, the rule engine, the
log pipeline, and whatever you wire up to read those logs and turn them into
dashboards, bans, and alerts. The firewall can only react to what it can
scrape back out of a log file after the fact, and standing the whole thing up
is a project in itself.

The second is the rented cloud WAF. You point your DNS at someone else's
edge, your traffic flows through infrastructure you don't control, the rules
are a black box you can't fully read, your request data lives on their disks,
and you pay every month for the privilege.

WEWAF is the third option: one static Go binary that is the proxy, the rule
engine, the DDoS detector, the egress filter, the zero-trust policy layer, the
rotating history store, and the dashboard, all in the same process. One
`go build`, one file to deploy, no sidecars, no external database, no traffic
leaving your machine. You own it, you can read every decision it makes, and
your data stays where you put it.

That compactness is also what makes it capable. Because every subsystem shares
memory with every other one, they can cooperate without RPC hops or
log-scraping glue: a session's risk score can trigger a proof-of-work
challenge, the DDoS detector can tighten the front-door admission shaper the
instant it sees a flood, and the rule engine can hand a verdict straight to the
live event stream. Those are the kinds of things a pile of separate processes
either charges extra for or simply can't do.

## What makes it different

A few design choices are worth calling out, because they are where WEWAF earns
its keep.

### Canonicalization before matching

Most encoding-based bypasses work because the firewall and the application
disagree about what a request actually says. WEWAF closes that gap before any
signature runs. URIs, paths, query arguments, and request bodies pass through a
dedicated canonicalizer: recursive URL decoding (up to three passes, so
`%2525..%2f` resolves to `../`), backslash-to-slash folding, null-byte
stripping, NFKC Unicode normalization so fullwidth and ligature tricks collapse
to ASCII, slash coalescing, dot-segment resolution, and homoglyph folding that
maps Cyrillic, Greek, and fullwidth lookalikes back to ASCII. Rules only have
to match one clean representation; the common evasions are peeled off first.

Crucially, the full signature set inspects the query string, not just request
bodies. A reflected payload in `?q=...` is checked by exactly the same rules
that check a form body, so the most common reflected-XSS and injection vectors
can't slip past on a `GET`.

### A DDoS detector tuned not to cry wolf

The naive rule — "flag anything above baseline times four" — false-positives on
every Black Friday and every viral link. WEWAF refuses to declare "under
attack" unless three things line up at once: the smoothed 10-second request
rate exceeds an adaptive baseline (weighted over a 5-minute warmup and never
polluted by attack traffic itself), it also crosses an absolute floor so a
quiet site isn't over-sensitive, and the condition holds across several
consecutive spike windows. Once tripped it stays tripped through a cool-down so
a brief dip doesn't reopen the gates. The result is a near-zero false-positive
rate on legitimate bursts while still catching sustained floods early.

It also watches three signals that individual rule matches miss: per-IP
connection rate, Slowloris-style slow reads (terminated before they tie up a
worker), and the botnet shape — many distinct IPs each staying individually
under the per-IP limit while converging on one sensitive path such as login or
admin.

### A front door that survives the flood

When the detector flips to "under attack", the firewall's own CPU becomes the
scarce resource. A global token-bucket admission shaper sits at the very front
of the request path, before any body buffering or rule work. Normally it is set
well above peak traffic and does nothing; under attack it auto-tightens so
excess requests get a fast `429` with no inspection cost, leaving enough
headroom to keep serving the requests it does admit.

A circuit breaker protects the origin from the other direction. After enough
consecutive backend failures it opens, short-circuiting requests to `503` with
a `Retry-After` for a cool-down, then lets a single probe through to test
recovery before closing again — so a struggling origin isn't finished off by a
retry storm.

### Honest defaults

Every WAF eventually panics on some malformed input. WEWAF's failsafe behaviour
is an explicit choice, not a silent default: `closed` (the default) returns a
`503` so the request can retry against a healthy instance, while `open` forwards
it unfiltered and marks the response so you know it happened. Most of the
heavier features — session scoring, the browser challenge, GraphQL validation,
DPI, egress inspection — ship observe-only, so you can watch what they would do
before you let them block anything.

### Bounded memory

Nothing grows without limit under attack. Every ring buffer has a declared cap
and every map has an eviction policy: recent blocks, egress decisions, bot
detections, traffic samples, unique IPs, and brute-force counters are all
bounded. History writes happen on a dedicated goroutine off a buffered channel;
if a burst fills the channel, events are dropped with a counter increment
rather than back-pressuring live traffic.

## How a request flows

Inbound traffic passes through the proxy in order. Each stage can stop the
request before it reaches the next:

1. Pre-WAF admission shaper (token bucket, tightens under attack)
2. Global concurrency semaphore
3. DDoS detector (volumetric, connection-rate, botnet, slow-read)
4. Per-IP rate limit
5. Zero-trust path policy (who are you, before anything else)
6. Circuit-breaker gate
7. Canonicalization, then rule evaluation across phases
8. Forward to the backend
9. Response inspection and secret/leak redaction

The admin dashboard and JSON API run on a separate port, and an optional egress
proxy guards outbound traffic from the backend. Every subsystem exposes a
`Stop()` or `Close()`; `SIGINT`/`SIGTERM` triggers an orderly shutdown that
flushes pending history before exiting.

## The rule engine

WEWAF compiles **377 signatures** from two layered packs: the native WEWAF pack
(274 rules focused on high-value exploit classes and recent CVEs) and a curated
port of the **OWASP Core Rule Set** v4 (103 rules across protocol enforcement,
LFI, RFI, RCE, PHP injection, XSS, SQLi, Java, and data-leakage categories).
CRS can be turned off entirely with `crs_enabled=false` if you want only the
native signatures.

Every rule carries a paranoia level (1–4) matching the CRS convention. PL1 is
the low-false-positive base set; higher levels add more aggressive matches. The
engine filters by the configured `paranoia_level` at evaluation time, so you can
start at PL1 in detection mode, watch, and ratchet up.

Rule changes are regression-locked. The false-positive suite in
`internal/rules/falsepositive_test.go` runs the full pack at the widest paranoia
level against realistic traffic that has historically tripped other WAFs —
search queries containing shell-command words, prose mentioning `javascript:`,
form posts with ampersands, hex colours and template placeholders in JSON,
URLs with dotfile lookalikes — and asserts that nothing fires. A parallel set of
malicious cases confirms detection still works. A change that breaks either
side doesn't land.

The native pack covers the classics — XSS, SQL injection, RCE, SSRF, XXE, path
traversal, CRLF, NoSQL, LDAP, JNDI, prototype pollution, file upload, open
redirect, HTTP request smuggling, and scanner/bot fingerprints — plus a number
of higher-value and more modern classes:

- Recent CVEs across 2023–2026, including Next.js middleware bypass, PHP-CGI
  argv injection, several VPN/gateway pre-auth bugs (PAN-OS, Ivanti, FortiOS,
  Check Point), TeamCity and GitLab auth bypasses, CitrixBleed, Confluence and
  XWiki template RCE, GeoServer, CUPS, React Server Components prototype-
  pollution RCE, Langflow and Marimo RCE, and the Cleo Harmony RCE chain.
- Log4Shell with obfuscation-aware patterns that unfold `${lower:j}${::-ndi}`
  style tricks, plus Spring4Shell, Confluence OGNL, Struts, ProxyShell, MOVEit,
  and Shellshock.
- Server-side template injection for Jinja2, Twig, ERB, Velocity, Freemarker,
  and Smarty, in both bodies and query strings.
- Insecure deserialization for Java, PHP, Node, Python pickle, Ruby Marshal,
  and YAML tag injection.
- GraphQL abuse, server-side and edge-side includes, React SSR / Next.js
  injection, prompt-injection and LangChain tool-abuse markers, mass-assignment
  fields, advanced scanner fingerprints, request-shape anomalies, and
  credential-stuffing tool signatures.
- Charset and header evasions: UTF-7 and UTF-16 smuggling, and injection
  carried in client-controlled headers such as `User-Agent`, `Referer`, and the
  forwarding/real-IP family that often land in logs and admin views.

## Operating modes

- `active` blocks any request whose cumulative score reaches `block_threshold`.
- `detection` evaluates rules and logs matches but forwards traffic unchanged —
  useful for a soft rollout.
- `learning` logs every match with its score so you can tune rules and
  allowlists before switching to active.

Mode is hot-swappable at runtime:

```bash
curl -X POST -d '{"mode":"detection"}' http://localhost:8443/api/config
```

## Quick start

Build the dashboard (needs Node 18+), then build and run the daemon:

```bash
cd ui
npm install
npm run build            # emits ../internal/web/dist/

cd ..
go build -o waf ./cmd/waf
./waf -config config.json
```

By default the proxy listens on `:8080` and the admin dashboard on `:8443`.
Point your application traffic at `http://<host>:8080` and open
`http://<host>:8443` in a browser.

## Configuration

`config.json` is sparse: defaults are applied for every field you leave out, so
you only list what you want to change. The tables below cover the fields most
operators touch. Every field also has a JSON-tag comment in
`internal/config/config.go`.

Set `WAF_API_KEY` in the environment to require an API key on every `/api/*`
request, presented via the `X-API-Key` header or an `api_key` query parameter.
Leave it unset only for development.

### Core proxy and limits

| Field                 | Default     | Purpose                                          |
|-----------------------|-------------|--------------------------------------------------|
| `listen_addr`         | `":8080"`   | Where inbound traffic hits the WAF.              |
| `admin_addr`          | `":8443"`   | Dashboard + API port. Put behind auth in prod.   |
| `backend_url`         | required    | Origin the proxy forwards to.                    |
| `trust_xff`           | `false`     | Trust `X-Forwarded-For` (only behind a CDN).     |
| `trusted_proxies`     | `[]`        | CIDR allowlist of upstream proxies whose `X-Forwarded-For` is honoured. Empty falls back to legacy left-most behaviour with a startup warning; populate it in production so a client reaching the WAF directly can't spoof its source IP. |
| `max_concurrent_req`  | `10000`     | Global semaphore on in-flight requests.          |
| `max_body_bytes`      | `10 MiB`    | Cap on request/response body inspection.         |
| `block_threshold`     | `100`       | Aggregate score at which a request is blocked.   |
| `rate_limit_rps`      | `100`       | Per-IP token bucket rate.                        |
| `rate_limit_burst`    | `150`       | Per-IP token bucket burst size.                  |
| `paranoia_level`      | `1`         | OWASP CRS paranoia 1–4. Raise after tuning.      |

### Resilience

| Field                                  | Default  | Purpose                                                        |
|----------------------------------------|----------|----------------------------------------------------------------|
| `backend_dial_timeout_ms`              | `5000`   | TCP dial timeout on the origin transport.                      |
| `backend_response_header_timeout_ms`   | `30000`  | Max time the origin can take to send response headers.         |
| `backend_max_idle_conns`               | `200`    | Connection-pool cap across all origins.                        |
| `backend_max_conns_per_host`           | `64`     | Per-host connection cap.                                        |
| `decompress_inspect`                   | `true`   | Decompress gzip/brotli bodies into a ratio-capped buffer before evaluation (zip-bomb defence). |
| `decompress_ratio_cap`                 | `100`    | Max allowed decompressed-to-compressed ratio.                  |
| `max_decompress_bytes`                 | `64 MiB` | Absolute decompressed-size cap.                                |
| `failsafe_mode`                        | `closed` | `closed` = 503 on engine panic, `open` = forward unfiltered.   |
| `breaker_consecutive_failures`         | `10`     | Origin failures in a row before the breaker opens.             |
| `breaker_open_timeout_sec`             | `30`     | Cool-down before a half-open probe is allowed.                 |

### Bans, DDoS, and admission control

| Field                              | Default       | Purpose                                                     |
|------------------------------------|---------------|-------------------------------------------------------------|
| `ddos_spike_windows_required`      | `3`           | Consecutive 10-second spike windows before declaring attack.|
| `ddos_cooldown_seconds`            | `60`          | Quiet period before releasing attack state.                 |
| `ddos_conn_rate_threshold`         | `300`         | Per-IP connections in a 10s window (CDN-friendly default).  |
| `ddos_botnet_unique_ip_threshold`  | `200`         | Unique IPs converging on a sensitive path in 60s.           |
| `shaper_enabled`                   | `false`       | Pre-WAF token-bucket admission. Tightens under attack.      |
| `shaper_max_rps` / `shaper_burst`  | `2000 / 4000` | Base budget and burst for the shaper.                       |
| `ban_backoff_enabled`              | `true`        | Repeat bans on the same IP inside the window get longer.    |
| `ban_backoff_multiplier`           | `2`           | Duration multiplier per repeat offence.                     |
| `max_ban_duration_sec`             | `604800`      | Upper cap so backoff doesn't grow without bound.            |

### Session tracking, browser challenge, GraphQL

| Field                          | Default        | Purpose                                                          |
|--------------------------------|----------------|------------------------------------------------------------------|
| `session_tracking_enabled`     | `false`        | Issue a signed session cookie and accumulate per-session signals.|
| `session_idle_ttl_sec`         | `1800`         | Evict sessions idle longer than this.                            |
| `session_block_threshold`      | `0` (off)      | Score at which a session's requests are blocked. `0` = observe.  |
| `browser_challenge_enabled`    | `false`        | Serve the JS integrity probe and accept verify POSTs.            |
| `browser_challenge_block`      | `false`        | If on, a failed challenge blocks the request outright.           |
| `graphql_enabled`              | `false`        | Parse GraphQL requests and enforce structural limits.            |
| `graphql_max_depth`            | `7`            | Max AST depth. Typical SPAs sit at 4–5.                          |
| `graphql_max_aliases`          | `10`           | Max aliased fields per operation (amplification defence).        |
| `graphql_max_fields`           | `200`          | Max total fields per operation.                                  |
| `graphql_schema_file`          | `""`           | Path to an SDL file. Enables `@requires(role:"…")` enforcement.  |

### Deep packet inspection, audit, egress, headers

The gRPC and WebSocket inspectors (`grpc_inspect`, `websocket_inspect`), the
HMAC-chained audit log (`audit_enabled`), outbound exfil scanning
(`egress_exfil_inspect`), and response security headers
(`security_headers_enabled`, `hsts_enabled`) each have their own config block —
all observe-only or off by default. JA3 TLS fingerprinting (`ja3_enabled`) and
proof-of-work for high-risk sessions (`pow_enabled`) round out the optional
defences. See `internal/config/config.go` for the complete field list with
inline comments.

## Endpoints and observability

Beyond `/api/health`, `/api/metrics`, and `/api/config`, the endpoints worth
knowing:

- `/api/events/stream` — Server-Sent Events: `hello`, `block`, `egress`,
  `bot`, `ping`.
- `/api/network/summary`, `/api/network/top-paths`, `/api/network/top-ips` —
  live bandwidth, status-code mix, most-attacked endpoints and top attackers.
- `/api/ip/<ip>` — full intel on one IP, with `/api/ip-auto-mitigate` (POST) to
  ban every IP over a block threshold in the last hour.
- `/api/ddos/stats`, `/api/shaper/stats`, `/api/breaker/stats` — live state of
  the three resilience subsystems.
- `/api/zerotrust/policies` (GET/PUT) — inspect or replace path policies.
- `/api/history/events?from=&to=&limit=` — time-ranged block query across every
  rotated SQLite file.
- `/api/sessions`, `/api/graphql/stats`, `/api/dpi/stats`, `/api/audit/verify` —
  per-subsystem state and counters.

Prometheus exposition lives at `/metrics`. The key series:

| Metric                       | Type    | Labels    | Meaning                              |
|------------------------------|---------|-----------|--------------------------------------|
| `wewaf_requests_total`       | counter | —         | All requests seen by the proxy.      |
| `wewaf_blocked_total`        | counter | —         | Requests the WAF blocked.            |
| `wewaf_passed_total`         | counter | —         | Requests forwarded to the backend.   |
| `wewaf_rule_matches_total`   | counter | `rule_id` | Per-rule match counts for tuning.    |
| `wewaf_response_status`      | counter | `bucket`  | 2xx / 3xx / 4xx / 5xx distribution.  |
| `wewaf_unique_ips`           | gauge   | —         | Distinct source IPs since rotation.  |

## History

Every block, IP activity update, and traffic sample is written to a SQLite
database under `history/`. The hot path never touches disk directly: the proxy
enqueues events to a buffered channel, and a single background writer drains it
every couple of seconds (or in batches of 256) inside one transaction. If a
burst fills the channel, events are dropped and counted rather than slowing the
request path.

At the rotation boundary (default one week) the writer closes the current
database and opens a fresh `history/waf-<timestamp>.sqlite`. Schema changes ship
as additive `ALTER TABLE ... ADD COLUMN` migrations applied on reopen, so
upgrades never require a data migration. History queries open only the database
files whose time range intersects the requested window.

## Testing

```bash
go test -race ./...
```

Tests live alongside the package they exercise. Black-box integration tests that
boot a real backend behind the proxy live under `tests/integration/`.

| Package                  | What it covers                                                          |
|--------------------------|-------------------------------------------------------------------------|
| `internal/rules`         | False-positive regression suite plus malicious-traffic match suite.     |
| `internal/engine`        | Canonicalization, traversal, homoglyph folding, charset evasion, query-string signature parity. |
| `internal/limits`        | Rate-limiter math and eviction; breaker state machine and half-open probe gating. |
| `internal/session`       | Cookie HMAC round-trip, tamper rejection, score-rises-with-blocks.      |
| `internal/graphql`       | Depth/alias/field limits, observe vs block, `@requires(role)` enforcement. |
| `internal/proxy`         | Luhn-verified card and secret-pattern exfil detection, HSTS emission, smuggling defences. |
| `internal/ddos`          | Botnet threshold and stale-entry pruning.                               |
| `internal/dpi`           | gRPC frame parser and the RFC 6455 WebSocket reader.                    |
| `internal/audit`         | HMAC chain round-trip and tamper detection (edit/delete/reorder/truncate). |
| `tests/integration`      | End-to-end allow + block + per-rule counters + Prometheus exposition.   |

## Hot reload

Run with `-config config.json` and edit the file in place — the watcher re-reads
on mtime change, recompiles rules, and pushes the result to the running engine.
Fields that can't safely hot-swap (listen addresses, admin API key, SQLite
paths) are ignored until a restart. A `[config hot-reload]` log line confirms
each reload.

## Project layout

```
cmd/waf/              entry point + telemetry-to-history persister
internal/config/      JSON config load + hot-swappable mode
internal/core/        shared types (transactions, matches, ban list)
internal/engine/      rule evaluation + canonicalization + phase orchestration
internal/rules/       built-in signatures + OWASP CRS port + regex compilation
internal/proxy/       reverse proxy + egress proxy with DNS cache and per-dest limits
internal/ddos/        volumetric + conn-rate + slow-read + botnet detector
internal/zerotrust/   per-path access policies (auth, mTLS, CIDR, country)
internal/session/     signed-cookie session tracker, risk scoring, JS challenge
internal/graphql/     schema-aware GraphQL validator
internal/dpi/         deep packet inspection for gRPC frames + WebSocket
internal/audit/       tamper-evident HMAC-chained audit log
internal/limits/      semaphore + token bucket + circuit breaker + buffer pool
internal/telemetry/   in-memory counters, ring buffers, persister hook
internal/history/     rotating SQLite store + batched writer
internal/ssl/         cert storage + TLS policy
internal/bruteforce/  sliding-window login attempt tracker
internal/web/         admin HTTP server + embedded SPA + SSE stream + /metrics
tests/integration/    black-box end-to-end tests
ui/                   React + Vite source (builds to internal/web/dist)
```

## Authorship

WEWAF is authored and maintained by YurilLAB.


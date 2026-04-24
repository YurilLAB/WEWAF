# WEWAF

<p align="center">
  <img src="internal/web/dist/eagle-logo-icon.png" alt="WEWAF Eagle Logo" width="120">
</p>

A self-hosted Web Application Firewall written in Go, paired with a React
admin dashboard. WEWAF sits in front of your backend as a reverse proxy,
inspects every transaction against a compiled rule set, and persists
telemetry to a rotating set of SQLite databases so historical data survives
restarts and stays searchable by time range.

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

WEWAF ships with **325 compiled signatures** across two layered rule packs:
the native WEWAF pack (~220 rules focused on high-value exploit classes and
recent CVEs), and a curated port of the **OWASP Core Rule Set** v4
(~106 rules across protocol enforcement, LFI, RFI, RCE, PHP injection, XSS,
SQLi, Java, and data-leakage categories).

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

- **2024 / 2025 CVEs**: Next.js middleware bypass (CVE-2025-29927), PHP-CGI
  argv injection (CVE-2024-4577), PAN-OS GlobalProtect (CVE-2024-3400),
  Ivanti Connect Secure (CVE-2024-21887), FortiOS SSL-VPN (CVE-2024-21762),
  TeamCity auth bypass (CVE-2024-27198), GitLab password-reset takeover
  (CVE-2023-7028), CitrixBleed (CVE-2023-4966), Confluence template RCE
  (CVE-2023-22527), XWiki SolrSearch (CVE-2025-24893), ScreenConnect
  (CVE-2024-1709), Veeam Backup (CVE-2024-40711), GeoServer OGC
  (CVE-2024-36401), CUPS IPP (CVE-2024-47176).
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
the ones you want to override need to be listed. The sections that
typically matter:

- **Proxy**: `listen_addr`, `admin_addr`, `backend_url`, `trust_xff`,
  `read_timeout_sec`, `write_timeout_sec`.
- **Resource limits**: `max_cpu_cores`, `max_memory_mb`,
  `max_concurrent_req`, `max_body_bytes`.
- **Security thresholds**: `block_threshold`, `rate_limit_rps`,
  `rate_limit_burst`, `brute_force_window_sec`, `brute_force_threshold`,
  `reputation_*`.
- **DDoS**: `ddos_volumetric_baseline` (initial RPS guess, replaced by the
  adaptive EMA after `ddos_warmup_seconds`), `ddos_volumetric_spike`
  (multiplier over baseline), `ddos_min_absolute_rps` (absolute floor —
  never flag below this even if the multiplier says so),
  `ddos_spike_windows_required` (consecutive spike windows before tripping,
  default 3), `ddos_cooldown_seconds` (quiet period before releasing
  attack state), `ddos_conn_rate_threshold` (per-IP conns/10s),
  `ddos_botnet_unique_ip_threshold` (unique IPs on sensitive paths/60s to
  flag), `ddos_slow_read_bps` (Slowloris floor).
- **Shaper** (pre-WAF admission control): `shaper_enabled`, `shaper_max_rps`,
  `shaper_burst`. Off by default — opt in once you've observed your
  traffic profile.
- **Rule engine**: `paranoia_level` (1–4, default 1), `crs_enabled`
  (default true, load the OWASP CRS pack on top of the native signatures).
- **Circuit breaker**: `breaker_consecutive_failures` (trip threshold,
  default 10), `breaker_open_timeout_sec` (cool-down, default 30).
- **Failsafe**: `failsafe_mode` — `"closed"` (default, 503 on engine
  panic) or `"open"` (forward unfiltered on panic).
- **Egress**: `egress_enabled`, `egress_addr`, `egress_allowlist`
  (exact hosts or `*.wildcard.com`), `egress_block_private_ips`,
  `egress_max_body_bytes`.
- **History**: `history_dir`, `history_rotate_hours`,
  `history_buffer_size`, `history_flush_seconds`.
- **Engine**: `mode`, `log_level`, `audit_log_path`, `rule_files`.

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

All routes honour CORS and the optional API key.

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
internal/limits/      — semaphore + token bucket + circuit breaker + buffer pool
internal/telemetry/   — in-memory counters, ring buffers, persister hook
internal/history/     — rotating SQLite store + batched writer
internal/host/        — CPU/mem/disk/net sampler (gopsutil)
internal/connection/  — backend probe + ping/event history
internal/ssl/         — cert storage + TLS policy
internal/bruteforce/  — sliding-window login attempt tracker
internal/web/         — admin HTTP server + embedded SPA + SSE stream
ui/                   — React + Vite source (builds to internal/web/dist)
history/              — created at runtime; rotating SQLite files live here
certs/                — created at runtime; uploaded PEM cert pairs
```

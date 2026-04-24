# WEWAF

<p align="center">
  <img src="internal/web/dist/eagle-logo-icon.png" alt="WEWAF Eagle Logo" width="120">
</p>

A self-hosted Web Application Firewall written in Go, paired with a React admin
dashboard. WEWAF sits in front of your backend as a reverse proxy, inspects
every transaction against a compiled rule set, and persists telemetry to a
rotating set of SQLite databases so historical data survives restarts and stays
searchable by time range.

## Highlights

- **In-process WAF engine** — 95+ compiled signatures across XSS, SQLi, RCE,
  SSRF, XXE, path traversal, CRLF, NoSQLi, LDAP, JNDI, prototype pollution,
  file upload, open redirect, HTTP smuggling, and scanner/bot fingerprints.
- **Three operating modes** — `active` (block), `detection` (log would-block),
  `learning` (log all matches to help tune rules). Hot-swappable at runtime.
- **Reverse proxy with WebSocket passthrough**, per-IP rate limiting, request
  body inspection with hard caps, and backend-response inspection with
  credential-leak redaction.
- **Hardened egress filter** — dot-bounded allowlist matching (no substring
  surprises), DNS resolution with classification of every resolved IP,
  explicit block of cloud metadata endpoints (169.254.169.254, Alibaba
  100.100.100.200, IPv6 IMDSv2), half-closing CONNECT tunnels that cannot
  leak goroutines.
- **Live Events stream (Server-Sent Events)** — every block, egress decision,
  and bot fingerprint is pushed to connected dashboard clients in real time.
- **IP Intelligence + auto-mitigation** — drill into any IP's activity,
  category mix, and ban status; one-click auto-ban for attackers exceeding a
  configurable block threshold.
- **Brute-force detector** with sliding-window per-IP tracking on login paths
  (trailing-slash normalised).
- **Reputation-based auto-ban** with expiry, swept by a background janitor.
- **Host telemetry daemon** — CPU, memory, disk, load average, and real
  network bandwidth (bytes/s in and out) via gopsutil, sampled every 5 s.
- **Connection manager** — probes the backend on an interval, maintains a
  100-sample ping-latency ring buffer and a 100-entry state-transition log,
  coalesces concurrent probes.
- **SSL / TLS manager** — upload, list, and delete PEM certificates;
  configurable minimum TLS version, HSTS, and cipher preference.
- **Rotating SQLite history** with time-range queries; every block, IP
  activity update, and traffic sample (including per-interval byte volumes)
  is persisted through a non-blocking queue and flushed in batched
  transactions. Rotation interval configurable; old databases are finalised
  with an `ended_at` timestamp and left in place for retroactive analysis.
- **Embedded admin dashboard** — React + Vite SPA served from the same Go
  binary, no external web server required.

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

After startup the proxy listens on `:8080` and the admin dashboard on `:8443`.
Point your application traffic at `http://<host>:8080` and open
`http://<host>:8443` in a browser.

## Endpoints

### Proxy
| Port | Purpose |
|------|---------|
| `:8080` | WAF-filtered reverse proxy — send site traffic here |
| `:8443` | Admin dashboard + JSON API |

### Core JSON API
| Path | Method | Description |
|------|--------|-------------|
| `/api/health` | GET | Liveness + current mode |
| `/api/metrics` | GET | Request counters, byte counters + rates, recent blocks, traffic history, status-code distribution |
| `/api/stats` | GET | Runtime + host stats (CPU %, memory %, disk %, latency) |
| `/api/config` | GET / POST | Fetch full config; POST `{"mode":"active"}` to hot-swap mode |
| `/api/blocks` | GET | Last 50 block records plus active bans |
| `/api/traffic` | GET | In-memory traffic-graph samples |
| `/api/rules` | GET | Compiled rule set metadata |
| `/api/bans` | GET / POST / DELETE | Inspect or manage the reputation ban list |
| `/api/ratelimit/config` | GET | Rate limit, brute-force, and block-threshold settings |

### Network monitoring
| Path | Description |
|------|-------------|
| `/api/network/summary` | Live byte totals, bandwidth rates, status-code buckets, recent egress, backend latency |
| `/api/network/top-paths?limit=` | Most-attacked endpoints in the last 24 h |
| `/api/network/top-ips?limit=` | Top IPs by request volume |

### IP Intelligence
| Path | Method | Description |
|------|--------|-------------|
| `/api/ip/<ip>` | GET | Everything known about one IP: request/block counts, attack categories, recent blocks, ban status |
| `/api/ip-auto-mitigate` | POST | Ban every IP whose block count in the last hour exceeds a threshold; body `{"threshold":10,"duration_sec":3600}` |

### Live events (SSE)
| Path | Description |
|------|-------------|
| `/api/events/stream` | Server-Sent Events. Types: `hello`, `block`, `egress`, `bot`, `ping` |

### Egress
| Path | Description |
|------|-------------|
| `/api/egress/status` | Enabled flag, allowlist, block counters, recent decisions |
| `/api/egress/recent?limit=` | Ring buffer of recent egress decisions with target URL + reason |

### Bots
| Path | Description |
|------|-------------|
| `/api/bots/detected?limit=` | Ring buffer of recent bot fingerprints with IP + user-agent + score |

### Host telemetry
| Path | Description |
|------|-------------|
| `/api/host/stats` | Hostname, platform, architecture, Go version, WAF version, uptime |
| `/api/host/resources` | CPU %, memory %, disk %, load avg, network IO, bandwidth (bps) |

### Connection management
| Path | Method | Description |
|------|--------|-------------|
| `/api/connection/status` | GET | Current backend connectivity + last ping + probe counters |
| `/api/connection/config` | GET / PUT | Backend URL, listener addresses, poll interval, timeouts |
| `/api/connection/test` | POST | Run a single probe now and return the result |
| `/api/connection/history` | GET | 100-sample ping-latency ring buffer |
| `/api/connection/events` | GET | State-transition events (online ↔ offline) |

### SSL / TLS
| Path | Method | Description |
|------|--------|-------------|
| `/api/ssl/certificates` | GET / POST | List or upload PEM-encoded certificates |
| `/api/ssl/certificates/{id}` | DELETE | Remove a certificate by ID |
| `/api/ssl/config` | GET / PUT | Minimum TLS version, HSTS, cipher preference |

### History (SQLite-backed time-range queries)
| Path | Description |
|------|-------------|
| `/api/history/databases` | List every DB file with its start/end timestamps, size, and row counts |
| `/api/history/events?from=&to=&limit=` | Blocks across DBs in the given RFC3339 (or Unix) time range |
| `/api/history/ips?from=&to=&limit=` | Aggregated IP activity across DBs in range |
| `/api/history/traffic?from=&to=&limit=` | Traffic-graph samples across DBs in range (includes per-bucket bytes in/out) |
| `/api/history/stats` | Writer queue depth, dropped/written event counters, rotations |
| `/api/requests?limit=` | Recent request events from the current DB (convenience) |
| `/api/ips?limit=` | Top IPs from the last 24 h (convenience) |

All `/api/*` routes honour CORS and optional bearer-style API key auth (see
*Authentication* below).

## Operating modes

- **`active`** — the engine blocks requests whose cumulative score reaches
  `block_threshold`. Blocked requests get HTTP 403 with an incident ID.
- **`detection`** — rules still evaluate; matches are logged and the UI sees
  them as events, but traffic is forwarded unchanged. Useful for soft rollout.
- **`learning`** — every match is logged with its score. Intended to help you
  author rule tweaks and whitelists before switching to `active`.

Mode is hot-swappable: `curl -X POST -d '{"mode":"detection"}' /api/config`.

## Egress protection

When `egress_enabled` is set, the WAF can double as an outbound proxy for
applications that make third-party calls. Before forwarding, the egress path
performs:

1. **Host allowlist** — matches exact hostnames or dot-bounded subdomains.
   `*.example.com` is a wildcard that includes every subdomain but excludes
   the apex. `google.com` in the allowlist does not match
   `googlecompromise.evil.com`.
2. **DNS classification** — hostnames are resolved and every returned IP is
   checked for loopback, private, link-local, multicast, and unspecified
   ranges. Cloud metadata endpoints (169.254.169.254, 100.100.100.200,
   IPv6 IMDSv2) are blocked explicitly even if reached through indirection.
3. **Rule engine evaluation** — outbound URLs and bodies are matched against
   egress-specific signatures.
4. **Body size limit** — enforced before the request is sent.

CONNECT tunnels use half-close: once either direction of the copy completes,
both sides are closed so idle peers cannot leak the other goroutine.

## Live events + IP Intelligence

The dashboard's landing page includes a **Live Events** panel that opens a
Server-Sent Events stream to `/api/events/stream`. Every block, egress
decision, and bot fingerprint is pushed immediately, with automatic reconnect
on transient errors. A keepalive ping every 25 s keeps the connection open
through proxies.

The **IP Intelligence** page (*Security → IP Intelligence*) lists the top
attackers from the last 24 h. Clicking an IP opens a drawer with its full
activity, attack-category mix, recent blocks, and ban status. The
Auto-Mitigation card runs a one-shot pass over the last hour of history and
bans every IP whose block count exceeds the threshold — useful for quickly
shutting down a burst.

## History subsystem

The history store writes every block, IP activity update, and traffic sample
to a SQLite database inside `history/`. A fresh database is created on
startup, and again each time the rotation window (default 168 h / 1 week)
elapses.

- **Non-blocking hot path.** The proxy enqueues events to a buffered channel.
  A single background writer drains the channel every two seconds (or when a
  batch of 256 accumulates) and applies them inside one transaction. If the
  buffer is ever full — e.g., during a burst that outpaces disk — the event
  is dropped and `history.dropped_events` is incremented. The request is
  unaffected.
- **Rotation boundary.** Every minute the writer checks whether the current
  DB is older than the rotation window. If so it sets `metadata.ended_at`,
  closes the file, and opens a new one named
  `history/waf-<rfc3339-timestamp>.sqlite`. Registered listeners (the
  telemetry layer) reset their in-memory aggregates so unique-IP counts etc.
  align with the fresh window.
- **Schema per DB.**
  - `metadata(id, started_at, ended_at, waf_version, rotation_seconds)`
  - `blocks(ts, ip, method, path, rule_id, rule_category, score, message)`
  - `ip_activity(ip, first_seen, last_seen, request_count, block_count)`
  - `traffic_points(ts, requests, blocked, bytes_in, bytes_out)`
- **Forward-compatible schema.** New columns are added to existing databases
  through `ALTER TABLE ... ADD COLUMN` on reopen, so upgrading does not
  require data migration.
- **Queries.** `/api/history/events`, `/api/history/ips`, and
  `/api/history/traffic` scan every DB whose `[started_at, ended_at]` range
  intersects the request window, aggregate results, and return them sorted.
  Databases outside the requested window are never opened.

## Memory safety

Long-running WAFs drift toward unbounded memory if every observation is kept
in process. WEWAF bounds the hot-path state explicitly:

- Recent blocks ring buffer: 500 entries (full history is in the DB).
- Recent egress decisions: 200 entries.
- Recent bot fingerprints: 200 entries.
- Traffic samples: 288 (24 h at 5-minute buckets).
- Unique IPs set: 100 000, reset on each history rotation.
- Connection ping history: 100 samples.
- Connection events: 100 transitions.
- Brute-force attempts per key: 10 000, trimmed to the sliding window every
  evict tick.
- Rate-limit buckets: evicted after 10 minutes of inactivity.
- SQLite connections use `journal_mode=WAL`, `synchronous=NORMAL`, and
  `busy_timeout=5000ms`.

## Configuration reference

Defaults are applied for every missing field; only the ones you want to
override need to live in `config.json`.

### Proxy
| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:8080` | Proxy listen address |
| `admin_addr` | `:8443` | Admin dashboard listen address |
| `backend_url` | `http://localhost:3000` | Origin server to protect |
| `trust_xff` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` |
| `read_timeout_sec` / `write_timeout_sec` | `30` | HTTP server timeouts |

### Resource limits
| Field | Default | Description |
|-------|---------|-------------|
| `max_cpu_cores` | all | `GOMAXPROCS` override |
| `max_memory_mb` | unlimited | Soft `runtime/debug` memory ceiling |
| `max_concurrent_req` | `10000` | Connection semaphore |
| `max_body_bytes` | `10485760` | Request body inspect+forward cap |

### Security thresholds
| Field | Default | Description |
|-------|---------|-------------|
| `block_threshold` | `100` | Score at which active-mode blocks a request |
| `rate_limit_rps` / `rate_limit_burst` | `100` / `150` | Per-IP token bucket |
| `brute_force_window_sec` | `300` | Sliding window for login attempt tracking |
| `brute_force_threshold` | `10` | Attempts inside the window that trigger a block |
| `reputation_window_sec` | `600` | Window for reputation scoring |
| `reputation_threshold` | `5` | Block count inside window that triggers auto-ban |
| `reputation_ban_duration_sec` | `3600` | Length of the auto-ban |

### Egress
| Field | Default | Description |
|-------|---------|-------------|
| `egress_enabled` | `false` | Enable the egress inspection proxy |
| `egress_addr` | `:8081` | Egress proxy listen address |
| `egress_allowlist` | `[]` | Exact host or `*.subdomain.com` wildcards |
| `egress_block_private_ips` | `true` | DNS-resolve and block private/metadata IPs |
| `egress_max_body_bytes` | `10485760` | Hard cap on outbound request bodies |

### Engine
| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `active` | `active`, `detection`, or `learning` |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` |
| `audit_log_path` | `""` | File path for audit logs (empty disables) |
| `rule_files` | `["rules.json"]` | Additional JSON rule files to load |

### History
| Field | Default | Description |
|-------|---------|-------------|
| `history_dir` | `history` | Directory the rotating SQLite files live in |
| `history_rotate_hours` | `168` | Lifetime of a single DB before rotation (default 1 week) |
| `history_buffer_size` | `4096` | Queue capacity for the write pipeline |
| `history_flush_seconds` | `2` | Maximum staleness before a batch is flushed |

## Authentication

Set `WAF_API_KEY` to require an API key on every `/api/*` request. Clients
must present the key via the `X-API-Key` header or the `api_key` query
parameter. Unset it to serve the API without authentication (development
only).

## Architecture

```
┌──────────────┐       ┌────────────────────────────────────────┐
│  Client      │──────▶│  :8080  WAF Proxy (inspect / forward)  │
└──────────────┘       └───────────────┬────────────────────────┘
                                       ▼
                       ┌────────────────────────┐     ┌───────────────┐
                       │  Rule Engine (phases)  │────▶│  Telemetry    │
                       │  request / response    │     │  counters +   │
                       └────────────────────────┘     │  ring buffers │
                                                      └──────┬────────┘
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
│  outbound    │       │  allowlist + DNS + metadata blocks     │
└──────────────┘       └────────────────────────────────────────┘
```

Every subsystem has a `Stop()` or `Close()` method; `SIGINT`/`SIGTERM`
triggers an orderly shutdown that flushes outstanding history events before
exiting.

## Project layout

```
cmd/waf/              — entry point + persister adapter
internal/config/      — JSON config load + hot-swappable mode
internal/core/        — shared types (transactions, matches, ban list)
internal/engine/      — rule evaluation + phase orchestration
internal/rules/       — built-in signatures + rule compilation
internal/proxy/       — reverse proxy + egress proxy with WAF-aware buffering
internal/telemetry/   — in-memory counters, ring buffers, persister hook
internal/history/     — rotating SQLite store + batched writer
internal/host/        — CPU/mem/disk/net sampler (gopsutil)
internal/connection/  — backend probe + ping/event history
internal/ssl/         — cert storage + TLS policy
internal/bruteforce/  — sliding-window login attempt tracker
internal/limits/      — semaphore + token-bucket rate limiter
internal/web/         — admin HTTP server + embedded SPA + SSE stream
ui/                   — React + Vite source (builds to internal/web/dist)
history/              — created at runtime; rotating SQLite files live here
certs/                — created at runtime; uploaded PEM cert pairs
```

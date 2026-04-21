# WEWaf — Foundation

A self-hosted Web Application Firewall (WAF) written in Go.

## Architecture

```
cmd/waf/           — entry point (proxy + admin servers)
internal/
  config/          — JSON config, validation, hot reload of mode
  core/            — shared types (Transaction, Rule, Match, Phase, Action)
  engine/          — 5-phase WAF evaluator (request/response headers + body + logging)
  rules/           — compiled regex rule set with built-in signatures
  proxy/           — reverse proxy with WAF inspection, WebSocket passthrough
  limits/          — GOMAXPROCS, memory limit, concurrency semaphore
  bruteforce/      — sliding-window login attempt detector
  telemetry/       — in-memory metrics, traffic history, recent blocks
  web/             — admin dashboard (HTML/template + JSON API)
```

## Quick Start

```bash
# Build
cd "WEWaf Web exploitation Web apllication firewall and open source website Firewall"
go build ./cmd/waf

# Run with defaults (backend = http://localhost:3000)
./waf

# Run with custom config
./waf -config config.json
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `http://:8080` | WAF proxy — send your site traffic here |
| `http://:8443` | Admin dashboard |
| `http://:8443/api/metrics` | JSON metrics |
| `http://:8443/api/stats` | System resource stats |
| `http://:8443/api/config` | GET/POST runtime config |
| `http://:8443/api/blocks` | Recent blocked requests |
| `http://:8443/api/traffic` | Traffic history for line graph |

## Built-in Signatures

- **XSS** — script tags, javascript protocol, event handlers, template injection
- **SQL Injection** — UNION SELECT, stacked queries, tautologies, time-based functions
- **Command Injection / RCE** — command substitution, reverse shells, dangerous chains
- **Path Traversal** — null bytes, dot-dot-slash, PHP wrappers, sensitive files
- **SSRF / Protocol Attacks** — cloud metadata endpoints, private IPs, HTTP smuggling
- **Scanner / Bot UA** — sqlmap, nikto, nmap, Burp, etc.
- **Brute-force** — per-IP sliding window on login endpoints

## Modes

- `active` — block threats immediately
- `detection` — log only, do not block
- `learning` — log and tag for whitelist generation

## Resource Limits

Set `max_cpu_cores` (GOMAXPROCS), `max_memory_mb` (soft Go heap limit), and `max_concurrent_req` (connection semaphore). Use `0` for unlimited / all available.

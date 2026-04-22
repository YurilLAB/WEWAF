# WEWAF

A self-hosted Web Application Firewall written in Go. It includes a built-in reverse proxy, a rule engine with signatures for common web attacks, and an embedded React admin dashboard for real-time monitoring.

## Quick Start

```bash
# Build
go build ./cmd/waf

# Run with defaults (backend = http://localhost:3000)
./waf

# Run with a custom configuration file
./waf -config config.json
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `:8080` | WAF proxy -- send site traffic here |
| `:8443` | Admin dashboard (embedded React SPA) |
| `/api/metrics` | Request counters, blocked/passed stats, errors |
| `/api/stats` | System resource stats, uptime, mode |
| `/api/config` | GET or POST runtime configuration |
| `/api/blocks` | Recent blocked requests |
| `/api/traffic` | Traffic history for the line graph |
| `/api/rules` | List of currently loaded compiled rules |
| `/api/health` | Health check and current WAF mode |

## Modes

- `active` -- block threats immediately and return HTTP errors
- `detection` -- log matches and anomalies without blocking traffic
- `learning` -- log traffic patterns to help tune rules and generate whitelists

## Built-in Signatures

- XSS -- script tags, javascript protocol, event handlers, template injection
- SQLi -- UNION SELECT, stacked queries, tautologies, time-based functions
- RCE -- command substitution, reverse shells, dangerous chains
- NoSQLi -- NoSQL injection patterns
- XXE -- XML external entity expansion
- Path Traversal -- null bytes, dot-dot-slash, PHP wrappers, sensitive files
- SSRF -- cloud metadata endpoints, private IPs, HTTP smuggling
- CRLF -- header injection and response splitting
- LDAP -- LDAP injection and wildcard abuse
- Prototype Pollution -- JavaScript prototype chain attacks
- JNDI -- JNDI lookup injection
- File Upload -- dangerous extensions and MIME type bypass
- Open Redirect -- unvalidated redirect targets
- Scanner UA -- sqlmap, nikto, nmap, Burp, and other automated scanners
- Brute-force -- per-IP sliding window detection on login endpoints

## Configuration Reference

Key fields in `config.json`:

| Field | Description |
|-------|-------------|
| `listen_addr` | Proxy listen address, e.g. `:8080` |
| `admin_addr` | Dashboard listen address, e.g. `:8443` |
| `backend_url` | Origin server to protect, e.g. `http://localhost:3000` |
| `trust_xff` | Whether to trust the X-Forwarded-For header |
| `mode` | `active`, `detection`, or `learning` |
| `block_threshold` | Score at which a request is blocked (default 100) |
| `rate_limit_rps` | Per-IP rate limit in requests per second |
| `rate_limit_burst` | Per-IP rate limit burst capacity |
| `max_body_bytes` | Maximum request body size to inspect |
| `read_timeout_sec` | HTTP read timeout |
| `write_timeout_sec` | HTTP write timeout |
| `audit_log_path` | File path for audit logs (empty disables logging) |
| `rule_files` | Additional JSON rule files to load |

## Resource Limits

- `max_cpu_cores` -- sets GOMAXPROCS (0 = all available)
- `max_memory_mb` -- sets a soft Go runtime memory limit (0 = unlimited)
- `max_concurrent_req` -- connection semaphore to prevent overload (0 = unlimited)
- Rate limiting is enforced per IP using a token bucket

## Authentication

Set the `WAF_API_KEY` environment variable to require an API key for all `/api/*` endpoints. Clients must provide the key via the `X-API-Key` header or the `api_key` query parameter.

# Connecting WEWAF to ypanel

**ypanel** is Yuril Security's unified operator control panel — a single web app
served at its own subdomain (`https://ypanel.yurillab.dev`) for running the
whole Yuril suite (QPot, DireC, WEWAF, Kmap, GPTL) from one place, scoped to the
licences an operator owns. In ypanel, **WEWAF** is the web-application-firewall
product: protected sites, the rule engine, the live block stream, bans, and
connectors.

This document defines how a WEWAF instance connects to ypanel. WEWAF ships no
bundled UI: each node serves only the JSON API, Prometheus `/metrics`, and the
SSE event stream on its admin port, and the admin root redirects a browser to
the ypanel subdomain (configurable via `ypanel_url`).

## The operator-plane model

ypanel never talks to a WEWAF instance directly. A WEWAF node phones home to the
DireC **activation worker** (the operator plane); ypanel reads those snapshots
and issues allow-listed control jobs the node applies.

```
  WEWAF node ──phone-home──▶ DireC activation worker ──reads──▶ ypanel (browser)
  (/metrics, SSE stream,      (Cloudflare Worker,             (operator session,
   per-rule counters,          the "operator plane")            licence-scoped)
   block/egress events)
```

WEWAF already exposes everything the operator plane needs:

- **Prometheus `/metrics`** + per-rule match counters (JSON + Prometheus)
- **Server-Sent Events** stream of blocks / egress / bots
- the rotating SQLite history store (time-sliced, WAL) for historical queries

The operator-plane integration is a thin reporter that pushes these snapshots to
the worker on an interval; ypanel reads them.

### What ypanel's WEWAF section drives

- **Sites** — the backends WEWAF fronts: mode (block/monitor/off), proxy health,
  traffic, block-rate, paranoia (1–4), TLS, DDoS posture, active bans.
- **Rules** — native signatures + OWASP CRS, paranoia-graded, per-rule action
  (block/log/off) and match counts.
- **Events** — the live block/inspection stream (rule, anomaly score, source).
- **Connectors** — Syslog/SIEM, webhook, Slack/Teams, Prometheus scrape,
  object-store log export, email digests.

### Security model (load-bearing)

- **Headers-only secrets** (operator session + client licence key); never in a
  URL/log/DOM. HTTPS enforced end-to-end.
- **No node secret in the browser.** A WEWAF node's local admin/API secret stays
  on the node; it is not part of the operator-plane contract.
- **Tenant isolation** (operators only see their own WEWAF fleets) and an
  **allow-listed** control vocabulary (mode/rule/ban changes are queued jobs the
  node applies on check-in). **Fail-closed** reads — no stale data when down.

## Status today (honest)

| Capability | Status |
|------------|--------|
| WEWAF engine: rules, DDoS detector, bans, `/metrics`, SSE, history store | **implemented** (this repo) |
| Bundled React admin dashboard (`ui/`, `internal/web/dist`) | **removed** — node ships no local UI; the admin root redirects to ypanel |
| ypanel WEWAF section (Sites/Rules/Events/Connectors/Settings) | **implemented** — honest demo today; fully operable in demo |
| Node → worker snapshot reporter | **implemented** — the ypanel-agent (`--product wewaf --product-api :8443 --wewaf-admin-key`) reads this node's admin API and pushes a worker-valid snapshot (sites/rules/packs/events/bans) |
| Operator job queue (ban controls applied to the node) | **implemented** — the agent applies `ban.add` / `ban.release` / `ban.purge` to `/api/bans`; rule/site-config verbs report an honest `ok:false` until the node exposes those endpoints |

The reporter is the [ypanel-agent](../../DireC/ypanel-agent) `--product wewaf`
mode: it reads this node's admin API locally (the admin key never leaves the
host) and pushes snapshots to the worker, which ypanel reads. Until an operator
runs the agent against a node, ypanel's WEWAF screens run on honest **Demo
data**; once a node checks in, ypanel switches to live reads with no panel
change.

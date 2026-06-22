# Protecting the server, not just the website

WEWAF is an L7 web application firewall: by default every decision it makes —
a ban, a DDoS verdict, a rate-limit — is enforced by returning an HTTP error
from the reverse proxy. That protects the **website**. It does nothing for the
**server the website runs on**: a "banned" attacker has still completed the TCP
handshake, TLS, and HTTP parse before being turned away, and is entirely free to
hammer SSH, a database port, or — if they discover the origin's IP — the
application itself, directly, bypassing the WAF completely.

Three opt-in features close that gap. They are independent; enable any subset.

| Feature | Protects | Default |
|---|---|---|
| Host-firewall ban sink | the host (all ports, pre-handshake) | off |
| Never-ban allowlist | the host (anti-self-DoS) | always-on guard + opt-in CIDRs |
| Origin proof-of-passage | the origin (direct-to-origin bypass) | off |

---

## 1. Host-firewall ban sink

When `firewall_sink_enabled` is on, a background reconcile loop syncs WEWAF's
active ban list into the host packet filter, so a banned source is dropped at
**L3/L4 across every port, before the handshake** — exactly the fail2ban /
CrowdSec model. SSH, databases, and the origin port are all protected, and the
WAF stops spending CPU refusing connections it has already decided to drop.

The in-process HTTP ban check is **not** removed: the sink is a pure add-on. If
a kernel call fails, the offender is still blocked at L7 (fail-open relative to
the existing enforcement, never relative to the attacker).

### Backends

| Platform | Backend | Mechanism |
|---|---|---|
| Linux | `nft` (nftables) | a `wewaf` table with timeout-flagged `blocklist4`/`blocklist6` sets and an input-hook chain (priority −150) that drops matching source addresses. Kernel-side timeouts mean a crashed daemon's drops self-expire. |
| Windows | `netsh`/PowerShell | per-IP inbound block rules in the `WEWAF` firewall group. No kernel timeout, so the group is flushed on startup and shutdown; the reconcile loop owns expiry. |

`firewall_backend` defaults to `auto` (nft on Linux, Windows Firewall on
Windows). Set it to `none` to disable, or pin it explicitly.

### Privileges

The sink shells out to the host firewall, which requires privilege:

- **Linux:** `CAP_NET_ADMIN` (run as root, or grant the capability:
  `setcap cap_net_admin+ep ./waf`). `nft` must be installed.
- **Windows:** run as Administrator (the service account needs rights to manage
  Windows Firewall).

If the tool is missing or the process lacks privilege, `EnsureSetup` fails, the
sink logs a warning and stays **off** — L7 ban enforcement continues unchanged.

### Trial it safely: dry-run

Set `firewall_dry_run: true` to log the exact commands the sink *would* run
without touching the host firewall. Recommended before going live:

```
firewall[dry-run]: nft <<<
add table inet wewaf
add chain inet wewaf input { type filter hook input priority -150 ; policy accept ; }
add set inet wewaf blocklist4 { type ipv4_addr ; flags timeout ; }
...
firewall[dry-run]: nft add element inet wewaf blocklist4 { 203.0.113.99 timeout 3899s }
```

### Inspecting the live ruleset (Linux)

```bash
sudo nft list table inet wewaf          # table, sets, chain, drop rules
sudo nft list set inet wewaf blocklist4 # current banned IPv4 + remaining timeout
```

### Configuration

| Field | Default | Purpose |
|---|---|---|
| `firewall_sink_enabled` | `false` | Master switch. |
| `firewall_backend` | `"auto"` | `auto` \| `nft` \| `netsh` \| `none`. |
| `firewall_dry_run` | `false` | Log commands instead of executing them. |
| `firewall_table` | `"wewaf"` | nftables table name (Linux). Sanitised to `[A-Za-z0-9_]`. |
| `firewall_reconcile_sec` | `5` | How often the ban set is synced to the kernel. |
| `firewall_max_rules` | `0` | Cap on kernel entries (0 = unlimited). Guards the per-rule Windows path under an IP-rotation flood. |

### Safety rails

- Every IP is canonicalised (`net.ParseIP`) before it can reach a command, so a
  ban string can carry no shell/argv/nft metacharacter. Commands run via
  `exec.Command` with a separate argv (no shell); the Windows path single-quotes
  the address. This surface is locked down by `FuzzCanonicalIP`,
  `FuzzNftArgsNoInjection`, and `FuzzPowerShellNoInjection`.
- **IPv6 is dropped at the /64 prefix**, matching the ban list's /64 keying, so a
  banned IPv6 attacker can't rotate the low 64 bits to evade the kernel drop the
  way they can't evade the L7 ban. IPv4 is dropped at the /32 host.
- The sink **never** pushes loopback, unspecified, link-local, multicast,
  broadcast, RFC1918/ULA **private**, or CGNAT (100.64.0.0/10) addresses to the
  kernel, regardless of configuration — so a spoofed `X-Forwarded-For` in legacy
  `trust_xff` mode can't turn an auto-ban into a kernel-wide block of your
  gateway or origin. (Populate `trusted_proxies` to remove the spoofing vector
  entirely; the daemon warns at startup if the sink is on without it.)
- The never-ban allowlist (below) is re-checked inside the sink, with /64-aware
  prefix semantics, as defence in depth.
- Long bans are refreshed before the kernel timeout lapses; a partial apply
  failure retries only the failed entries (no full-set exec storm); on a clean
  shutdown the ruleset is torn down.

---

## 2. Never-ban allowlist

Bans flow in from threat feeds, mesh peers, the admin API, and auto-mitigation —
all attacker-influenced to some degree. Banning your own CDN egress range (which
every visitor appears to come from when `trust_xff` is on) or the default
gateway is an instant self-inflicted outage, and once the firewall sink is on it
becomes a kernel-wide, all-ports outage.

`core.BanList` therefore refuses to ban:

- anything that is not a parseable IP address (also the injection guard),
- loopback and the unspecified address (always),
- any entry in `ban_allowlist`, **and** the configured `trusted_proxies` CIDRs
  (merged in automatically — never ban the CDN in front of you).

| Field | Default | Purpose |
|---|---|---|
| `ban_allowlist` | `[]` | CIDRs/IPs that must never be banned. Add your admin source, gateway, monitoring, and any office ranges. `trusted_proxies` are added automatically. |

---

## 3. Origin proof-of-passage (origin shield)

A WAF only protects an origin while traffic is forced through it. The moment an
attacker learns the origin's IP and connects directly, every WAF check is
skipped. `origin_shield_enabled` injects a shared-secret header on every request
forwarded to the backend; the origin is configured to require it, so a direct
hit fails. This is the Cloudflare *Authenticated Origin Pull* / AWS CloudFront
custom-header pattern.

The secret is **shared with the origin out of band** — it is never auto-
generated (the origin could not verify a random per-restart value) and is
redacted from every config/UI/log surface. Provide a second secret in
`origin_shield_secret_previous` during rotation so a key change never 403s live
traffic.

| Field | Default | Purpose |
|---|---|---|
| `origin_shield_enabled` | `false` | Master switch. Injects nothing unless a secret is set. |
| `origin_shield_header` | `X-WEWAF-Origin-Verify` | Header carried to the origin. |
| `origin_shield_secret` | `""` | Shared secret. Use ≥ 16 random bytes. Redacted. |
| `origin_shield_secret_previous` | `""` | Accepted during rotation. Redacted. |

WEWAF strips any client-supplied copy of the header on ingress and re-injects
the genuine secret with `Set` (overwrite), so a client can never forge it.

### Configuring the origin to require the header

**nginx**

```nginx
# Reject anything that did not come through WEWAF.
if ($http_x_wewaf_origin_verify != "your-shared-secret-here") {
    return 403;
}
```

**Caddy**

```caddy
@notfromwaf not header X-WEWAF-Origin-Verify "your-shared-secret-here"
respond @notfromwaf 403
```

**Go origin** — verify with the same primitive WEWAF signs with:

```go
import "wewaf/internal/proxy"

if !proxy.VerifyOriginSecret(r.Header.Get("X-WEWAF-Origin-Verify"), current, previous) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

> The header is only as private as the WAF→origin transport. On an untrusted
> network segment, run that hop over TLS so the secret is not observable.
> Combine with a firewall rule on the origin that only accepts the WAF's IP for
> defence in depth.

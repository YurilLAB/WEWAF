#!/usr/bin/env sh
# Put WEWAF in front of a website in one step.
#
# Generates a strong admin key, writes a config.json pointed at your origin,
# builds the daemon, and prints the exact command to run it plus the
# ypanel-agent command to wire the node into the operator console.
#
# Usage:
#   ./scripts/quickstart.sh [origin-url]
#   ./scripts/quickstart.sh http://localhost:3000
#
# Env overrides:
#   WEWAF_LISTEN  inbound traffic address      (default :8080)
#   WEWAF_ADMIN   admin/API address            (default 127.0.0.1:8443 — loopback)
#   WEWAF_CONFIG  config file to write          (default config.json)
#   WEWAF_GO      path to the go binary         (default: go on PATH)
#   WEWAF_SKIP_BUILD=1  write config + key only, skip the build
set -eu

BACKEND="${1:-}"
LISTEN="${WEWAF_LISTEN:-:8080}"
ADMIN="${WEWAF_ADMIN:-127.0.0.1:8443}"
OUT="${WEWAF_CONFIG:-config.json}"
GO="${WEWAF_GO:-go}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -z "$BACKEND" ]; then
	printf "Origin URL the WAF should protect (e.g. http://localhost:3000): "
	read -r BACKEND
fi
[ -z "$BACKEND" ] && { echo "quickstart: no origin URL provided" >&2; exit 1; }
case "$BACKEND" in
	http://*|https://*) : ;;
	*) echo "quickstart: origin must start with http:// or https:// (got '$BACKEND')" >&2; exit 1 ;;
esac

# 32-byte (64 hex char) admin key — meets the >=32 byte minimum the admin API
# enforces. Prefer openssl; fall back to /dev/urandom.
if command -v openssl >/dev/null 2>&1; then
	KEY="$(openssl rand -hex 32)"
else
	KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
fi

cat > "$OUT" <<JSON
{
  "listen_addr": "$LISTEN",
  "admin_addr": "$ADMIN",
  "backend_url": "$BACKEND",
  "mode": "active",
  "trust_xff": false,
  "ypanel_url": "https://ypanel.yurillab.dev"
}
JSON
echo "quickstart: wrote $OUT (origin=$BACKEND listen=$LISTEN admin=$ADMIN)"

if [ "${WEWAF_SKIP_BUILD:-}" != "1" ]; then
	echo "quickstart: building the daemon..."
	"$GO" -C "$ROOT" build -o waf ./cmd/waf
	echo "quickstart: built ./waf"
fi

cat <<TXT

────────────────────────────────────────────────────────────────────────────
WEWAF is configured. Two steps to go live:

1) Run the WAF (the admin key is required — keep it secret):

     WAF_API_KEY=$KEY ./waf -config $OUT

   Inbound traffic -> $LISTEN ; point your DNS / load balancer there.
   Admin API/metrics/SSE -> $ADMIN (loopback by default; keep it private).

2) Wire this node into ypanel (after enrolling a WEWAF instance in the panel):

     ypanel-agent \\
       --base https://ypanel.yurillab.dev \\
       --product wewaf \\
       --instance-id  wf_xxxxxxxxxxxxxxxxxxxxxxxx \\
       --enroll-token yw_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \\
       --jws-file /etc/direc/license.dat \\
       --product-api http://$ADMIN \\
       --wewaf-admin-key $KEY

The admin key stays on this host — it is never sent to ypanel.
────────────────────────────────────────────────────────────────────────────
TXT

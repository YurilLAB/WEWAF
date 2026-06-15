# Put WEWAF in front of a website in one step.
#
# Generates a strong admin key, writes a config.json pointed at your origin,
# builds the daemon, and prints the exact command to run it plus the
# ypanel-agent command to wire the node into the operator console.
#
# Usage:
#   ./scripts/quickstart.ps1 [-Origin http://localhost:3000]
#
# Env overrides: $env:WEWAF_GO (path to go.exe), $env:WEWAF_SKIP_BUILD=1
param(
    [string]$Origin = "",
    [string]$Listen = ":8080",
    [string]$Admin = "127.0.0.1:8443",
    [string]$Config = "config.json"
)
$ErrorActionPreference = "Stop"
$go = if ($env:WEWAF_GO) { $env:WEWAF_GO } else { "go" }
$root = Split-Path $PSScriptRoot -Parent

if (-not $Origin) { $Origin = Read-Host "Origin URL the WAF should protect (e.g. http://localhost:3000)" }
if (-not $Origin) { Write-Error "quickstart: no origin URL provided" }
if ($Origin -notmatch '^https?://') { Write-Error "quickstart: origin must start with http:// or https:// (got '$Origin')" }

# 32-byte (64 hex char) cryptographically-strong admin key — meets the >=32 byte
# minimum the admin API enforces.
$bytes = New-Object 'System.Byte[]' 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$key = -join ($bytes | ForEach-Object { '{0:x2}' -f $_ })

$json = @"
{
  "listen_addr": "$Listen",
  "admin_addr": "$Admin",
  "backend_url": "$Origin",
  "mode": "active",
  "trust_xff": false,
  "ypanel_url": "https://ypanel.yurillab.dev"
}
"@
Set-Content -Path $Config -Value $json -Encoding utf8
Write-Host "quickstart: wrote $Config (origin=$Origin listen=$Listen admin=$Admin)"

if ($env:WEWAF_SKIP_BUILD -ne "1") {
    Write-Host "quickstart: building the daemon..."
    & $go -C $root build -o waf.exe ./cmd/waf
    if ($LASTEXITCODE -ne 0) { Write-Error "quickstart: build failed" }
    Write-Host "quickstart: built waf.exe"
}

Write-Host @"

────────────────────────────────────────────────────────────────────────────
WEWAF is configured. Two steps to go live:

1) Run the WAF (the admin key is required — keep it secret):

     `$env:WAF_API_KEY = "$key"; ./waf.exe -config $Config

   Inbound traffic -> $Listen ; point your DNS / load balancer there.
   Admin API/metrics/SSE -> $Admin (loopback by default; keep it private).

2) Wire this node into ypanel (after enrolling a WEWAF instance in the panel):

     ypanel-agent --base https://ypanel.yurillab.dev --product wewaf ``
       --instance-id wf_xxxxxxxxxxxxxxxxxxxxxxxx ``
       --enroll-token yw_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ``
       --jws-file C:\ProgramData\DireC\license.dat ``
       --product-api http://$Admin --wewaf-admin-key $key

The admin key stays on this host — it is never sent to ypanel.
────────────────────────────────────────────────────────────────────────────
"@

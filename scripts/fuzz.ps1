# Runs every WEWAF fuzz target for a bounded time using Go's built-in fuzzing.
# No external dependencies, no CI minutes required — meant to be run locally
# (or in a nightly job once spare CI capacity exists).
#
# Usage:
#   ./scripts/fuzz.ps1 [seconds-per-target]
#   $env:WEWAF_GO = "D:\path\to\go.exe"; ./scripts/fuzz.ps1 30
#
# Exits non-zero if any target finds a crash (the reproducer is written under
# the package's testdata/fuzz/ directory and becomes a permanent regression
# corpus entry).
param([int]$Seconds = 60)

$ErrorActionPreference = "Stop"
$go = if ($env:WEWAF_GO) { $env:WEWAF_GO } else { "go" }
$root = Split-Path $PSScriptRoot -Parent

$targets = @(
    @{ pkg = "./internal/engine/";   fn = "FuzzCanonicalize" },
    @{ pkg = "./internal/engine/";   fn = "FuzzCanonicalizePath" },
    @{ pkg = "./internal/engine/";   fn = "FuzzDecodePercentU" },
    @{ pkg = "./internal/engine/";   fn = "FuzzFoldHomoglyphs" },
    @{ pkg = "./internal/engine/";   fn = "FuzzHasObfuscatedTransferEncoding" },
    @{ pkg = "./internal/dpi/";      fn = "FuzzInspectGRPCBody" },
    @{ pkg = "./internal/dpi/";      fn = "FuzzReadWSFrame" },
    @{ pkg = "./internal/proxy/";    fn = "FuzzMaybeDecompressBody" },
    @{ pkg = "./internal/audit/";    fn = "FuzzChainResume" },
    @{ pkg = "./internal/clientip/"; fn = "FuzzClientIP" }
)

$failed = @()
foreach ($t in $targets) {
    Write-Host "==== $($t.fn)  ($Seconds s) ===="
    & $go -C $root test -run='^$' -fuzz="^$($t.fn)$" -fuzztime="$($Seconds)s" $t.pkg
    if ($LASTEXITCODE -ne 0) { $failed += $t.fn }
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "FUZZ FAILURES: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "all fuzz targets passed" -ForegroundColor Green
